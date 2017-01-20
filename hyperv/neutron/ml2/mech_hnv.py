#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import json
import requests
from requests.status_codes import codes

from oslo_config import cfg
from oslo_log import log

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources

from neutron_lib import exceptions as n_exc
from neutron_lib import constants as const
from neutron_lib.plugins import directory

from neutron.plugins.ml2 import driver_api
from neutron.plugins.common import constants as plugin_const
from neutron.extensions import portbindings
from neutron.db import provisioning_blocks
from neutron.callbacks import resources
from neutron import context as n_context
from neutron import worker

from hyperv.common.i18n import _, _LE, _LI  # noqa
from hnv_client import client
from hyperv.common.utils import retry_on_http_error
from hyperv.neutron import exception as hyperv_exc
from hyperv.neutron import constants
from hyperv.neutron.ml2 import qos
from hyperv.neutron.ml2 import acl as hnv_acl

from hnv_client import config as hnv_config
from hnv_client.common import exception as hnv_exception

from neutron.common import config


LOG = log.getLogger(__name__)
CONF = cfg.CONF

class HNVWorker(worker.NeutronWorker):
    def __init__(self, driver):
        super(HNVWorker, self).__init__(worker_process_count=1)
        self._driver = driver

    def start(self):
        super(HNVWorker, self).start()
        self._driver._acl_driver.sync_acls()

    def stop(self):
        return

    def wait(self):
        return

    @staticmethod
    def reset():
        config.reset_service()


class HNVMechanismDriver(driver_api.MechanismDriver):
    """Hyper-V Network Virtualization driver.

    A mechanism driver is called on the creation, update, and deletion
    of networks and ports. For every event, there are two methods that
    get called - one within the database transaction (method suffix of
    _precommit), one right afterwards (method suffix of _postcommit).

    Exceptions raised by methods called inside the transaction can
    rollback, but should not make any blocking calls (for example,
    REST requests to an outside controller). Methods called after
    transaction commits can make blocking external calls, though these
    will block the entire process. Exceptions raised in calls after
    the transaction commits may cause the associated resource to be
    deleted.

    Because rollback outside of the transaction is not done in the
    update network/port case, all data validation must be done within
    methods that are part of the database transaction.
    """

    def initialize(self):
        """Perform driver initialization.

        Called after all drivers have been loaded and the database has
        been initialized. No abstract methods defined below will be
        called prior to this method being called.
        """
        LOG.info(_LI("Starting HNVMechanismDriver"))
        self._plugin_property = None
        # Initialize the logicalNetwork client
        self._ln_client = client.LogicalNetworks()
        # Initialize the ACL client
        self._acl_client = client.AccessControlLists()
        # Initialize virtualSubnet client
        self._vs_client = client.SubNetwork()
        #Initialize VirtualNetworks cloent
        self._vn_client = client.VirtualNetworks()
        # Get logical network for overlay network encapsulation
        self._logicalNetworkID = cfg.CONF.HNV.logical_network
        self._ln = self._get_logical_network(self._logicalNetworkID) 
        # addressSpace is a mandatory parameter when creating a virtual network
        # in the HNV network controller. We add a bogus address space when we
        # create the initial virtual network. This gets removed when we add our
        # first subnet.
        self._dummy_address_space = client.AddressSpace(address_prefixes=["1.0.0.0/32"])
        self.agent_type = constants.AGENT_TYPE_HNV
        self._setup_vif_port_bindings()
        self._qos_driver_property = None
        self._acl_driver_property = None
        self.subscribe()
        self._cached_ports_instance_ids = {}

    @property
    def _acl_driver(self):
        if self._acl_driver_property is None:
            self._acl_driver_property = hnv_acl.HNVAclDriver(self)
        return self._acl_driver_property

    @property
    def _qos_driver(self):
        if self._qos_driver_property is None:
            self._qos_driver_property = qos.HNVQosDriver(self)
        return self._qos_driver_property

    def subscribe(self):
        if cfg.CONF.SECURITYGROUP.enable_security_group:
            registry.subscribe(self.process_sg_notification,
                               resources.SECURITY_GROUP,
                               events.AFTER_CREATE)
            registry.subscribe(self.process_sg_notification,
                               resources.SECURITY_GROUP,
                               events.BEFORE_DELETE)
            registry.subscribe(self.process_sg_rule_notification,
                               resources.SECURITY_GROUP_RULE,
                               events.AFTER_CREATE)
            registry.subscribe(self.process_sg_rule_notification,
                               resources.SECURITY_GROUP_RULE,
                               events.BEFORE_DELETE)

    def process_sg_notification(self, resource, event, trigger, **kwargs):
        self._acl_driver.process_sg_notification(event, **kwargs)

    def process_sg_rule_notification(self, resource, event, trigger, **kwargs):
        self._acl_driver.process_sg_rule_notification(event, **kwargs)

    #TODO(gsamfira): IMPLEMENT_ME
    def _sync_ports(self):
        pass

    def get_workers(self):
        """Get any NeutronWorker instances that should have their own process

        Any driver that needs to run processes separate from the API or RPC
        workers, can return a sequence of NeutronWorker instances.
        """
        LOG.debug("returning HNV Worker")
        return (HNVWorker(self),)

    def _get_nc_ports(self):
        # TODO(gsamfira): maybe cache this value?
        ports = client.NetworkInterfaces.get()
        port_ids = {}
        for i in ports:
            port_ids[i.resource_id] = i
        return port_ids

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def _setup_vif_port_bindings(self):
        self.supported_vnic_types = [portbindings.VNIC_NORMAL]
        # NOTE(rtheis): Config for vif_type will ensure valid choices.
        self.vif_type = constants.VIF_TYPE_HYPERV
        # vif_details will be populated after we bind the port in the
        # network controller API. We will need to retrieve the instance_id
        self.vif_details = {}

    def _check_supported_network_type(self, net_type):
        return net_type in [plugin_const.TYPE_VXLAN,]

    def _insert_provisioning_block(self, context):
        # we insert a status barrier to prevent the port from transitioning
        # to active until the agent reports back that the wiring is done
        port = context.current
        if not context.host or port['status'] == const.PORT_STATUS_ACTIVE:
            # no point in putting in a block if the status is already ACTIVE
            return
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            # we check the VNIC type because there could be multiple agents
            # on a single host with different VNIC types
            return
        if context.host_agents(self.agent_type):
            provisioning_blocks.add_provisioning_component(
                context._plugin_context, port['id'], resources.PORT,
                provisioning_blocks.L2_AGENT_ENTITY)

    def _validate_segments(self, segment):
        network_type = segment['network_type']
        # TODO(gsamfira): So far I have found no way to get or set
        # this via API calls. The only way I managed to get the allocated
        # segmentation ID was by 
        segmentation_id = segment['segmentation_id']
        LOG.debug('Validating network segment with '
                      'type %(network_type)s, '
                      'segmentation ID %(segmentation_id)s.' %
                      {'network_type': network_type,
                       'segmentation_id': segmentation_id})
        if not self._check_supported_network_type(network_type):
            msg = _('Network type %s is not supported') % network_type
            raise n_exc.InvalidInput(error_message=msg)

    def create_network_precommit(self, context):
        """Allocate resources for a new network.

        :param context: NetworkContext instance describing the new
        network.

        Create a new network, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        segments = context.network_segments
        for segment in segments:
            self._validate_segments(segment)

    def _get_logical_network(self, network):
        ln = self._ln_client.get(resource_id=self._logicalNetworkID)
        if ln.network_virtualization_enabled != u'True':
            msg = _("The configured logical network "
                    "does not support virtualization") % self._logicalNetworkID
            raise n_exc.InvalidInput(error_message=msg)
        return ln

    def _create_network_on_nc(self, network):
        virtualNetworkID = network["id"]
        try:
            vn = self._vn_client.get(resource_id=virtualNetworkID)
            return vn
        except hnv_exception.NotFound:
            LOG.debug("Creating virtual network %(network_id)s on network controller" % {
                'network_id': virtualNetworkID,
                })
        ln_resource = client.Resource(resource_ref=self._ln.resource_ref)
        vn = client.VirtualNetworks(
                resource_id=virtualNetworkID,
                address_space=self._dummy_address_space,
                logical_network=ln_resource).commit(wait=True)
        return vn

    def create_network_postcommit(self, context):
        """Create a network.

        :param context: NetworkContext instance describing the new
        network.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        network = context.current
        self._create_network_on_nc(network)

    def update_network_precommit(self, context):
        """Update resources of a network.

        :param context: NetworkContext instance describing the new
        state of the network, as well as the original state prior
        to the update_network call.

        Update values of a network, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_network_precommit is called for all changes to the
        network state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        segments = context.network_segments
        for segment in segments:
            self._validate_segments(segment)

    def update_network_postcommit(self, context):
        """Update a network.

        :param context: NetworkContext instance describing the new
        state of the network, as well as the original state prior
        to the update_network call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_network_postcommit is called for all changes to the
        network state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        network = context.current
        original_network = context.original
        self._qos_driver.update_network(network, original_network)

    def delete_network_precommit(self, context):
        """Delete resources for a network.

        :param context: NetworkContext instance describing the current
        state of the network, prior to the call to delete it.

        Delete network resources previously allocated by this
        mechanism driver for a network. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        #Leaving here for later use
        pass

    def delete_network_postcommit(self, context):
        """Delete a network.

        :param context: NetworkContext instance describing the current
        state of the network, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        network = context.current
        self._vn_client.remove(resource_id=network['id'])

    def create_subnet_precommit(self, context):
        """Allocate resources for a new subnet.

        :param context: SubnetContext instance describing the new
        subnet.

        Create a new subnet, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        # Leaving here for later use
        pass

    # if etag changes between the GET call and the commit call
    # the API will throw a 412 error. We fetch the resource again and attempt
    # to modify it
    @retry_on_http_error(code=codes.precondition_failed)
    def _add_subnet_to_virtual_network(self, network_id, subnet_id, cidr):
        try:
            subnet_exists = self._vs_client.get(
                    parent_id=network_id,
                    resource_id=subnet_id)
            return
        except hnv_exception.NotFound:
            LOG.debug("Creating virtual subnet %(subnet_id)s on virtual "
                      "network %(network_id)s with cids %(cidr)s" % {
                'network_id': network_id,
                'subnet_id': subnet_id,
                'cidr': cidr,
                })
        virtualNetwork = client.VirtualNetworks.get(resource_id=network_id)
        subnet = client.SubNetwork(resource_id=subnet_id, address_prefix=cidr)
        dummy_prefix = self._dummy_address_space.address_prefixes[0]
        if cidr not in virtualNetwork.address_space["addressPrefixes"]:
            virtualNetwork.address_space["addressPrefixes"].append(cidr)
        if dummy_prefix in virtualNetwork.address_space["addressPrefixes"]:
            virtualNetwork.address_space["addressPrefixes"].remove(dummy_prefix)
        if virtualNetwork.subnetworks is None:
            virtualNetwork.subnetworks = [subnet,]
        else:
            virtualNetwork.subnetworks.append(subnet)
        virtualNetwork.commit(wait=True)
        return

    def create_subnet_postcommit(self, context):
        """Create a subnet.

        :param context: SubnetContext instance describing the new
        subnet.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.
        """
        subnet = context.current
        # HNV does not allow setting the gateway IP. It automatically allocates
        # the lowest IP address from a subnet as a router IP which gets configured
        # on the distributed router configured by HNV.
        gatewayIP = subnet["gateway_ip"]
        network_id = subnet["network_id"]
        subnet_id = subnet["id"]
        subnet_cidr = subnet["cidr"]
        self._add_subnet_to_virtual_network(network_id, subnet_id, subnet_cidr)

    def update_subnet_precommit(self, context):
        """Update resources of a subnet.

        :param context: SubnetContext instance describing the new
        state of the subnet, as well as the original state prior
        to the update_subnet call.

        Update values of a subnet, updating the associated resources
        in the database. Called inside transaction context on session.
        Raising an exception will result in rollback of the
        transaction.

        update_subnet_precommit is called for all changes to the
        subnet state. It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def update_subnet_postcommit(self, context):
        """Update a subnet.

        :param context: SubnetContext instance describing the new
        state of the subnet, as well as the original state prior
        to the update_subnet call.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Raising an exception will
        cause the deletion of the resource.

        update_subnet_postcommit is called for all changes to the
        subnet state.  It is up to the mechanism driver to ignore
        state or state changes that it does not know or care about.
        """
        pass

    def delete_subnet_precommit(self, context):
        """Delete resources for a subnet.

        :param context: SubnetContext instance describing the current
        state of the subnet, prior to the call to delete it.

        Delete subnet resources previously allocated by this
        mechanism driver for a subnet. Called inside transaction
        context on session. Runtime errors are not expected, but
        raising an exception will result in rollback of the
        transaction.
        """
        pass

    @retry_on_http_error(code=codes.precondition_failed)
    def _remove_address_prefix_from_virtual_network(self, network_id, cidr):
        try:
            virtualNetwork = self._vn_client.get(resource_id=network_id)
        except hnv_exception.NotFound:
            return
        dummy_prefix = self._dummy_address_space.address_prefixes[0]
        if cidr in virtualNetwork.address_space["addressPrefixes"]:
            virtualNetwork.address_space["addressPrefixes"].remove(cidr)
        # address space cannot be null or empty
        if len(virtualNetwork.address_space["addressPrefixes"]) == 0:
            virtualNetwork.address_space["addressPrefixes"].append(dummy_prefix)
        virtualNetwork.commit()
        
    def _remove_subnet_from_virtual_network(self, network_id, subnet_id):
        #import pdb; pdb.set_trace()
        try:
            exists = self._vs_client.get(resource_id=subnet_id, parent_id=network_id)
        except hnv_exception.NotFound:
            return
        self._vs_client.remove(resource_id=subnet_id, parent_id=network_id, wait=True)
        self._remove_address_prefix_from_virtual_network(network_id, exists.address_prefix)

    def delete_subnet_postcommit(self, context):
        """Delete a subnet.

        :param context: SubnetContext instance describing the current
        state of the subnet, prior to the call to delete it.

        Called after the transaction commits. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance. Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        subnet = context.current
        network_id = subnet["network_id"]
        subnet_id = subnet["id"]
        self._remove_subnet_from_virtual_network(network_id, subnet_id)

    def create_port_precommit(self, context):
        self._insert_provisioning_block(context)

    def create_port_postcommit(self, context):
        """Create a port.

        :param context: PortContext instance describing the port.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.
        """
        port = context.current
        network = context.network
        LOG.debug(
                "Creating port %(port)s bound to network %(network)s" % {
                    'port': port["id"],
                    'network': network.current["id"],
                    }
                )
        instance_id = self._bind_port_on_network_controller(port, network.current["id"])
        self._cached_ports_instance_ids[port["id"]] = instance_id


    def update_port_precommit(self, context):
        if context.host == context.original_host:
            return
        self._insert_provisioning_block(context)

    def update_port_postcommit(self, context):
        """Update a port.

        :param context: PortContext instance describing the new
        state of the port, as well as the original state prior
        to the update_port call.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.

        update_port_postcommit is called for all changes to the port
        state. It is up to the mechanism driver to ignore state or
        state changes that it does not know or care about.
        """
        port = context.current
        network = context.network
        self.update_port(port, network.current["id"])

    def delete_port_postcommit(self, context):
        """Delete a port.

        :param context: PortContext instance describing the current
        state of the port, prior to the call to delete it.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Runtime errors are not
        expected, and will not prevent the resource from being
        deleted.
        """
        port = context.current
        try:
            client.NetworkInterfaces.remove(resource_id=port["id"], wait=True)
        except hnv_exception.NotFound:
            pass
        return

    # TODO(gsamfira): IMPLEMENT_ME
    def _get_port_acl(self, port):
        return None

    def _get_ip_resource_id(self, ip, port_id):
        address = ip.get("ip_address")
        if address is None:
            raise ValueError("Invalid fixed_ips object")
        return "%s_%s" % (port_id, address)

    def _get_subnet_from_cache(self, subnet_id, network_id, cache):
        # you can have the same subnet ID on different virtual networks
        subnet_cache_key = "%s-%s" % (network_id, subnet_id)
        if type(cache) is not dict:
            cache = {}
        subnet_obj = cache.get(subnet_cache_key, False)
        if subnet_obj:
            return (cache, subnet_obj)
        try:
           subnet_obj = self._vs_client.get(resource_id=subnet_id, parent_id=network_id)
           cache[subnet_cache_key] = subnet_obj 
        except hnv_exception.NotFound:
            LOG.error("Failed to find subnet with ID %(subnet_id)s on network "
                    "%(network_id)s", 
                    {'subnet_id': subnet_id,
                     'network_id': network_id})
            raise err
        return (cache, subnet_obj)

    def update_port(self, port, network_id):
        create = False
        try:
            nc_port = client.NetworkInterfaces.get(resource_id=port["id"])
        except hnv_exception.NotFound:
            LOG.warning("Port %(port)s was not found in network controller. "
                "Creating new port object" % {
                'port': port["id"]
                })
            create = True
        if create:
            #TODO(gsamfira): Notify neutron L2 agent of the new instance ID
            #for this port, as that needs to be set on the VM switch port
            #for the network controller to be able to control it
            instance_id = self._bind_port_on_network_controller(port, network_id)
            port[portbindings.VIF_DETAILS].update(
                {constants.HNV_PORT_PROFILE_ID: instance_id})
            return instance_id
        port_details = self.get_port_details(port, network_id)
        nc_port.update(port_details)
        nc_port.commit(wait=True)
        return nc_port.instance_id

    # TODO(gsamfira): IMPLEMENT_ME
    def _confirm_ip_in_subnet(self, ip, subnet):
        return True

    def _get_subnet_from_neutron(self, subnet_id):
        admin_context = n_context.get_admin_context()
        subnet = self._plugin.get_subnet(admin_context, subnet_id)
        return subnet

    def _get_port_settins(self, port):
        qos_settings = self._qos_driver.get_qos_options(port)
        port_settings = client.PortSettings(
            qos_settings=qos_settings)
        return port_settings

    def _get_nc_ip_configuration(self, ip, network_id, port, cached_subnets):
        port_id = port["id"]
        acl = self._get_port_acl(port)
        subnet_id = ip.get("subnet_id")
        neutron_subnet = self._get_subnet_from_neutron(subnet_id)
        dns_nameservers = neutron_subnet.get("dns_nameservers", [])
        cached_subnets, subnet_obj = self._get_subnet_from_cache(
            subnet_id, network_id, cached_subnets)
        if not self._confirm_ip_in_subnet(ip["ip_address"], subnet_obj.address_prefix):
            # TODO(gsamfira): replace ValueError with module specific exception
            raise ValueError("fixed_ip %s is not part of subnet %s" % (
                ip["ip_address"], subnet_obj.address_prefix))
        resource_id = self._get_ip_resource_id(ip, port_id)
        subnet_resource = client.Resource(resource_ref=subnet_obj.resource_ref)
        ipConfiguration = client.IPConfiguration(
                    resource_id=resource_id,
                    private_ip_address=ip["ip_address"],
                    private_ip_allocation_method=constants.HNV_METHOD_STATIC,
                    subnet=subnet_resource,
                    access_controll_list=acl)
        return (ipConfiguration, dns_nameservers, cached_subnets)

    def get_port_details(self, port, network_id):
        mac_address = port["mac_address"].replace(":", "").replace("-", "").upper()
        port_settings = self._get_port_settins(port)
        cached_subnets = {}
        ipConfigurations = []
        dns_nameservers = set()
        for ip in port.get("fixed_ips", []):
            ipConfig, nameservers, cached_subnets = self._get_nc_ip_configuration(
                ip, network_id,
                port, cached_subnets)
            ipConfigurations.append(ipConfig)
            dns_nameservers.update(nameservers)
        if len(ipConfigurations) == 0:
            raise ValueError("Could not build valid IP address configurations")
        return {
            "resource_id": port["id"],
            "dns_settings": {"DnsServers": list(dns_nameservers)},
            "ip_configurations": ipConfigurations,
            "mac_address": mac_address,
            "port_settings": port_settings,
            "mac_allocation_method": constants.HNV_METHOD_STATIC,
        }

    def _bind_port_on_network_controller(self, port, network_id):
        port_options = self.get_port_details(port, network_id)
        networkInterface = client.NetworkInterfaces(**port_options)
        LOG.debug("Attempting to create network interface for %(port_id)s : %(payload)s" % {
            'port_id': port["id"],
            'payload': json.dumps(networkInterface),
            })
        networkInterface = networkInterface.commit(wait=True)
        return networkInterface.instance_id

    def get_agent_logical_network(self, agent):
        return agent['configurations'].get('logical_network', None)

    def bind_port(self, context):
        port = context.current
        network = context.network

        LOG.debug("Attempting to bind port %(port)s on "
                  "network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        vnic_type = context.current.get(portbindings.VNIC_TYPE,
                                        portbindings.VNIC_NORMAL)
        if vnic_type not in self.supported_vnic_types:
            LOG.debug("Refusing to bind due to unsupported vnic_type: %s",
                      vnic_type)
            return
        agents = context.host_agents(self.agent_type)
        if not agents:
            LOG.debug("Port %(pid)s on network %(network)s not bound, "
                      "no agent of type %(at)s registered on host %(host)s",
                      {'pid': context.current['id'],
                       'at': self.agent_type,
                       'network': context.network.current['id'],
                       'host': context.host})
        for agent in agents:
            LOG.debug("Checking agent: %s", agent)
            agent_ln = self.get_agent_logical_network(agent)
            # TODO(gsamfira): investigate allowing multiple logical networks. May need changes
            # to the VXLAN network type
            if agent_ln != self._logicalNetworkID:
                LOG.warning("Refusing to bind port %(pid)s to agent %(agent)s "
                        "Agent does not have access to logical network %(ln)s", {
                            'pid': context.current['id'],
                            'agent': agent,
                            'ln': self._logicalNetworkID})
                continue
            if agent['alive']:
                instance_id = self._cached_ports_instance_ids.get(port["id"])
                port[portbindings.VIF_DETAILS].update(
                    {constants.HNV_PORT_PROFILE_ID: instance_id})
                for segment in context.segments_to_bind:
                    if self._check_supported_network_type(segment["network_type"]):
                        context.set_binding(segment[driver_api.ID],
                                self.vif_type,
                                {constants.HNV_PORT_PROFILE_ID: instance_id})
                        LOG.debug("Bound using segment: %s", segment)
                        return
            else:
                LOG.warning(_LW("Refusing to bind port %(pid)s to dead agent: "
                                "%(agent)s"),
                            {'pid': context.current['id'], 'agent': agent})

