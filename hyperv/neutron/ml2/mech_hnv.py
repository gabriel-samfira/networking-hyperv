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

from oslo_config import cfg
from oslo_log import log

from neutron_lib import exceptions as n_exc

from neutron.plugins.ml2 import driver_api
from neutron.plugins.common import constants as plugin_const

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources

from hyperv.common.i18n import _, _LE, _LI  # noqa
from hyperv.neutron import sdn2_client
from hyperv.neutron import constants
from hyperv.neutron import exception as hyperv_exc

LOG = log.getLogger(__name__)


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
        self._ln_client = sdn2_client.LogicalNetwork()
        # Initialize the ACL client
        self._acl_client = sdn2_client.AccessControlLists()
        # Initialize virtualSubnet client
        self._vs_client = sdn2_client.SubNetwork()
        # Get logical network for overlay network encapsulation
        self._logicalNetworkID = cfg.CONF.SDN2.logical_network
        self._ln = self._get_logical_network(self._logicalNetworkID) 
        # addressSpace is a mandatory parameter when creating a virtual network
        # in the HNV network controller. We add a bogus address space when we
        # create the initial virtual network. This gets removed when we add our
        # first subnet.
        self._dummy_address_space = sdn2_client.AddressSpace(address_prefixes=["1.0.0.0/32"])

    def _validate_segments(self, segment):
        network_type = segment['network_type']
        # TODO(gsamfira): So far I have found no way to get or set
        # this via API calls. The only way I managed to get the allocated
        # segmentation ID was by 
        segmentation_id = segment['segmentation_id']
        LOG.debug('Validating network segment with '
                      'type %(network_type)s, '
                      'segmentation ID %(segmentation_id)s, '
                      'physical network %(physical_network)s' %
                      {'network_type': network_type,
                       'segmentation_id': segmentation_id,
                       'physical_network': physical_network})
        if network_type != plugin_const.TYPE_VXLAN:
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
        except hyperv_exc.NotFound:
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
        ln = self._ln_client.get(resource_id=lnID)
        if ln.network_virtualization_enabled != u'True':
            msg = _('The configured logical network does not support virtualization') % lnID
            raise n_exc.InvalidInput(error_message=msg)
        return ln

    def _create_network_on_nc(self, network):
        virtualNetworkID = network["id"]
        try:
            vn = self._vs_client(resource_id=virtualNetworkID)
            return vn
        except hyperv_exc.NotFound:
            LOG.debug("Creating virtual network %(network_id)s on network controller" % {
                'network_id': virtualNetworkID,
                })
        vn = sdn2_client.VirtualNetworks(
                resource_id=virtualNetworkID,
                address_space=self._dummy_address_space,
                logical_network=self._ln).commit(wait=True)
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
        self._vs_client.remove(resource_id=network['id'])

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
        dummy_prefix = self._dummy_address_space.address_prefixes[0]
        try:
            subnet = sdn2_client.SubNetwork.get(resource_id=subnet_id, parent_id=network_id)
        except hyperv_exc.NotFound:
            LOG.debug("Creating subnet %(subnet_id)s on virtual network %(virtual_network)s" % {
                'subnet_id': subnet_id,
                'virtual_network': network_id})
        virtualNetwork = sdn2_client.VirtualNetworks.get(resource_id=network_id)
        if subnet_cidr not in virtualNetwork.address_space["addressPrefixes"]:
            virtualNetwork.address_space["addressPrefixes"].append(subnet_cidr)
        if dummy_prefix in virtualNetwork.address_space["addressPrefixes"]:
            virtualNetwork.address_space["addressPrefixes"].remove(subnet_cidr)

        subnet = sdn2_client.SubNetwork(resource_id=subnet_id, address_prefix=subnet_cidr)
                                                            

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
        pass

    def create_port_precommit(self, context):
        """Allocate resources for a new port.

        :param context: PortContext instance describing the port.

        Create a new port, allocating resources as necessary in the
        database. Called inside transaction context on session. Call
        cannot block.  Raising an exception will result in a rollback
        of the current transaction.
        """
        pass

    def create_port_postcommit(self, context):
        """Create a port.

        :param context: PortContext instance describing the port.

        Called after the transaction completes. Call can block, though
        will block the entire process so care should be taken to not
        drastically affect performance.  Raising an exception will
        result in the deletion of the resource.
        """
        pass

    def update_port_precommit(self, context):
        """Update resources of a port.

        :param context: PortContext instance describing the new
        state of the port, as well as the original state prior
        to the update_port call.

        Called inside transaction context on session to complete a
        port update as defined by this mechanism driver. Raising an
        exception will result in rollback of the transaction.

        update_port_precommit is called for all changes to the port
        state. It is up to the mechanism driver to ignore state or
        state changes that it does not know or care about.
        """
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

    def delete_port_precommit(self, context):
        """Delete resources of a port.

        :param context: PortContext instance describing the current
        state of the port, prior to the call to delete it.

        Called inside transaction context on session. Runtime errors
        are not expected, but raising an exception will result in
        rollback of the transaction.
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
        pass

    def bind_port(self, context):
        """Attempt to bind a port.

        :param context: PortContext instance describing the port

        This method is called outside any transaction to attempt to
        establish a port binding using this mechanism driver. Bindings
        may be created at each of multiple levels of a hierarchical
        network, and are established from the top level downward. At
        each level, the mechanism driver determines whether it can
        bind to any of the network segments in the
        context.segments_to_bind property, based on the value of the
        context.host property, any relevant port or network
        attributes, and its own knowledge of the network topology. At
        the top level, context.segments_to_bind contains the static
        segments of the port's network. At each lower level of
        binding, it contains static or dynamic segments supplied by
        the driver that bound at the level above. If the driver is
        able to complete the binding of the port to any segment in
        context.segments_to_bind, it must call context.set_binding
        with the binding details. If it can partially bind the port,
        it must call context.continue_binding with the network
        segments to be used to bind at the next lower level.

        If the binding results are committed after bind_port returns,
        they will be seen by all mechanism drivers as
        update_port_precommit and update_port_postcommit calls. But if
        some other thread or process concurrently binds or updates the
        port, these binding results will not be committed, and
        update_port_precommit and update_port_postcommit will not be
        called on the mechanism drivers with these results. Because
        binding results can be discarded rather than committed,
        drivers should avoid making persistent state changes in
        bind_port, or else must ensure that such state changes are
        eventually cleaned up.

        Implementing this method explicitly declares the mechanism
        driver as having the intention to bind ports. This is inspected
        by the QoS service to identify the available QoS rules you
        can use with ports.
        """
        pass

    @property
    def _supports_port_binding(self):
        return self.__class__.bind_port != MechanismDriver.bind_port

    def check_vlan_transparency(self, context):
        """Check if the network supports vlan transparency.

        :param context: NetworkContext instance describing the network.

        Check if the network supports vlan transparency or not.
        """
        pass

    def get_workers(self):
        """Get any NeutronWorker instances that should have their own process

        Any driver that needs to run processes separate from the API or RPC
        workers, can return a sequence of NeutronWorker instances.
        """
        return ()

    @classmethod
    def is_host_filtering_supported(cls):
        return (cls.filter_hosts_with_segment_access !=
                MechanismDriver.filter_hosts_with_segment_access)

    def filter_hosts_with_segment_access(
            self, context, segments, candidate_hosts, agent_getter):
        """Filter hosts with access to at least one segment.

        :returns: a set with a subset of candidate_hosts.

        A driver can overload this method to return a subset of candidate_hosts
        with the ones with access to at least one segment.

        Default implementation returns all hosts to disable filtering
        (backward compatibility).
        """
        return candidate_hosts
