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

from neutron_lib import exceptions as n_exc

from neutron.plugins.ml2 import driver_api
from neutron.plugins.common import constants as plugin_const
from neutron.extensions import portbindings
from neutron.db import provisioning_blocks
from neutron.callbacks import resources
from neutron import import manager

from hyperv.common.i18n import _, _LE, _LI  # noqa
from hnv_client import client as sdn2_client
from hyperv.neutron import exception as hyperv_exc
from hyperv.neutron import constants

from hnv_client import config as hnv_config
from hnv_client.common import exception as hnv_exception

LOG = log.getLogger(__name__)
CONF = cfg.CONF

def retry_on_http_error(code, tries=5):
    def deco_retry(f):
        def f_retry(*args, **kwargs):
            mtries = tries
            if mtries <= 1:
                return f(*args, **kwargs)
            while mtries-1 > 0:
                try:
                    return f(*args, **kwargs)
                except requests.exceptions.HTTPError as err:
                    if err.response.status_code == code:
                        LOG.debug("Resource changed while we were updating")
                        mtries -= 1
                    else:
                        raise err
            return f(*args, **kwargs)
        return f_retry
    return deco_retry


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
        # Initialize the logicalNetwork client
        self._ln_client = sdn2_client.LogicalNetworks()
        # Initialize the ACL client
        self._acl_client = sdn2_client.AccessControlLists()
        # Initialize virtualSubnet client
        self._vs_client = sdn2_client.SubNetwork()
        #Initialize VirtualNetworks cloent
        self._vn_client = sdn2_client.VirtualNetworks()
        # Get logical network for overlay network encapsulation
        self._logicalNetworkID = cfg.CONF.HNV.logical_network
        self._ln = self._get_logical_network(self._logicalNetworkID) 
        # addressSpace is a mandatory parameter when creating a virtual network
        # in the HNV network controller. We add a bogus address space when we
        # create the initial virtual network. This gets removed when we add our
        # first subnet.
        self._dummy_address_space = sdn2_client.AddressSpace(address_prefixes=["1.0.0.0/32"])
        self.agent_type = constants.AGENT_TYPE_HYPERV
        self._setup_vif_port_bindings()

    @property
    def _plugin(self):
        if self._plugin_property is None:
            self._plugin_property = manager.NeutronManager.get_plugin()
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

    def _get_attribute(self, obj, attribute):
        res = obj.get(attribute)
        if res is const.ATTR_NOT_SPECIFIED:
            res = None
        return res

    def _ensure_default_acl(self):
        """
        There should be an ACL that mirrors the behavior of the default ACL in
        OpenStack. If one does not already exist, we create one. This function
        should not be called from inside any _precommit hook.
        """
        try:
            default_acl = self._acl_client(resource_id=constants.HNV_DEFAULT_NETWORK)
            return default_acl
        except hnv_exception.NotFound:
            LOG.debug("Creating default ACL on HNV network controller")

        allow_egress = sdn2_client.ACLRules(
                resource_id="Allow_Egress",
                action="Allow",
                destination_prefix="*",
                destination_port_range="*",
                source_prefix="*",
                source_port_range="*",
                description="Allow all egress traffic",
                priority="103", rule_type="Outbound")
        default_acl = sdn2_client.AccessControlLists(
                acl_rules=[allow_egress.dump(),],
                resource_id=constants.HNV_DEFAULT_NETWORK,
                inbound_action="Deny",
                outbound_action="Allow")
        default_acl.commit(wait=True)
        return default_acl

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
        ln_resource = sdn2_client.Resource(resource_ref=self._ln.resource_ref)
        vn = sdn2_client.VirtualNetworks(
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
        #Nothing to do fornetwork  update operations. Leaving this as a
        #placeholder for later use
        pass

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
        #Nothing to do for network update operations. Leaving this as a
        #placeholder for later use
        pass

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
        virtualNetwork = sdn2_client.VirtualNetworks.get(resource_id=network_id)
        subnet = sdn2_client.SubNetwork(resource_id=subnet_id, address_prefix=cidr)
        dummy_prefix = self._dummy_address_space.address_prefixes[0]
        if cidr not in virtualNetwork.address_space["addressPrefixes"]:
            virtualNetwork.address_space["addressPrefixes"].append(cidr)
        if dummy_prefix in virtualNetwork.address_space["addressPrefixes"]:
            virtualNetwork.address_space["addressPrefixes"].remove(dummy_prefix)
        if virtualNetwork.subnetworks is None:
            virtualNetwork.subnetworks = [subnet.dump(),]
        else:
            virtualNetwork.subnetworks.append(subnet.dump())
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

    def update_port_precommit(self, context):
        if context.host == context.original_host:
            return
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
        instance_id = self._bind_port_on_network_controller(port, network)
        self.vif_details[constants.HNV_PORT_PROFILE_ID] = instance_id
        pass

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
        pass

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
            sdn2_client.NetworkInterfaces.remove(resource_id=port["id"], wait=True)
        except hnv_exception.NotFound:
            pass
        return

    def get_workers(self):
        """Get any NeutronWorker instances that should have their own process

        Any driver that needs to run processes separate from the API or RPC
        workers, can return a sequence of NeutronWorker instances.
        """
        return ()

    # TODO(gsamfira): IMPLEMENT_ME
    def _get_port_acl(self, port):
        return []

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
            return subnet_obj
        try:
           subnet_obj = self._vs_client(resource_id=subnet_id, parent_id=network_id)
           cache[subnet_cache_key] = subnet_obj 
        except hnv_exception.NotFound as err:
            LOG.error("Failed to find subnet with ID %(subnet_id)s on network "
                    "%(network_id)s", 
                    {'subnet_id': subnet_id,
                     'network_id': network_id})
            raise err
        return (cache, subnet_obj)

    # TODO(gsamfira): IMPLEMENT_ME
    def _confirm_ip_in_subnet(self, ip, subnet):
        return True

    def _get_subnet_from_neutron(self, subnet_id):
        admin_context = n_context.get_admin_context()
        subnet = self._plugin.get_subnet(admin_context, subnet_id)
        return subnet

    def _bind_port_on_network_controller(self, port, network):
        port_id = port["id"]
        mac_address = port["mac_address"].replace(":", "").replace("-", "")
        nameservers = subnet['dns_nameservers']
        network_id = network['id']
        cached_subnets = {}
        acl = self._get_port_acl(port)
        ipConfigurations = []
        dns_servers = set()
        # TODO(gsamfira): validate IP version
        for ip in port.get("fixed_ips", []):
            subnet_id = ip.get("subnet_id")
            neutron_subnet = self._get_subnet_from_neutron()
            if neutron_subnet.get("dns_nameservers"):
                for i in neutron_subnet["dns_nameservers"]:
                    dns_nameservers.add(i)
            cached_subnets, subnet_obj = self._get_subnet_from_cache(subnet_id, network_id, cached_subnets)
            if self._confirm_ip_in_subnet(ip["ip_address"], subnet_obj.address_prefix) is False:
                # TODO(gsamfira): replace ValueError with module specific exception
                raise ValueError("fixed_ip %s is not part of subnet %s" % (
                    ip["ip_address"], subnet_obj.address_prefix))
            resource_id = self._get_ip_resource_id(ip, port_id)
            subnet_resource = sdn2_client.Resource(resource_id=subnet_obj.resource_ref)
            ipConfiguration = sdn2_client.IPConfiguration(
                    resource_id=resource_id,
                    private_ip_address=ip["ip_address"],
                    private_ip_allocation_method=constants.HNV_METHOD_STATIC,
                    subnet=subnet_resource,
                    access_controll_list=acl)
            ipConfigurations.append(ipConfiguration.dump())

        if len(ipConfigurations) == 0:
            raise ValueError("Could not build valid IP address configurations")

        networkInterface = sdn2_client.NetworkInterfaces(
                resource_id=port_id,
                dns_settings=list(dns_servers),
                ip_configurations=ipConfigurations,
                mac_address=mac_address,
                mac_allocation_method=constants.HNV_METHOD_STATIC).commit(wait=True)
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
                port[portbindings.VIF_DETAILS].update(self.vif_details)
                port[portbindings.PROFILE].update(self.vif_details)
                for segment in context.segments_to_bind:
                    context.set_binding(segment[driver_api.ID],
                            self.vif_type,
                            self.vif_details)
                    if self.try_to_bind_segment_for_agent(context, segment,
                                                          agent):
                        LOG.debug("Bound using segment: %s", segment)
                        return
            else:
                LOG.warning(_LW("Refusing to bind port %(pid)s to dead agent: "
                                "%(agent)s"),
                            {'pid': context.current['id'], 'agent': agent})
