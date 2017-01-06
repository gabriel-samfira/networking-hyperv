# Copyright 2017 Cloudbase Solutions Srl
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

import uuid
import json

from oslo_config import cfg
from oslo_log import log as logging
import requests
import requests_ntlm

from hyperv.common import objects
from hyperv.neutron import exception

CONF = cfg.CONF
CONF.import_group('SDN2', 'hyperv.neutron.config')
LOG = logging.getLogger(__name__)


class _BaseClient(object):

    def __init__(self, url=CONF.SDN2.url, username=CONF.SDN2.username,
                 password=CONF.SDN2.password):
        self._base_url = url
        if username and password:
            self._credentials = requests_ntlm.HttpNtlmAuth(username, password)
        else:
            self._credentials = None
        self._https_allow_insecure = CONF.SDN2.https_allow_insecure
        self._https_ca_bundle = CONF.SDN2.https_ca_bundle

    @staticmethod
    def _get_headers():
        """Prepare the HTTP headers for the current request."""

        # TODO(alexcoman): Add the x-ms-client-ip-address header in order
        # to improve the Network Controller requests logging.
        return {
            "Accept": "application/json",
            "Content-Type": "application/json; charset=UTF-8",
            "x-ms-client-request-id": uuid.uuid1().hex,
            "x-ms-return-client-request-id": "1",
        }

    def _verify_https_request(self):
        """Whether to disable the validation of HTTPS certificates.

        .. notes::
            When `https_allow_insecure` option is `True` the SSL certificate
            validation for the connection with the Network Controller API will
            be disabled (please don't use it if you don't know the
            implications of this behaviour).
        """
        if self._https_ca_bundle:
            return self._https_ca_bundle
        else:
            return not self._https_allow_insecure

    def _http_request(self, resource, method="GET", body=None):
        url = requests.compat.urljoin(self._base_url, resource)
        response = requests.request(method=method, url=url, data=body,
                                    headers=self._get_headers(),
                                    auth=self._credentials,
                                    verify=self._verify_https_request())

        if response.status_code == 404:
            raise exception.NotFound("Resource %r was not found." % resource)
        response.raise_for_status()

        if method == "DELETE":
            return

        try:
            return response.json()
        except ValueError:
            raise exception.ServiceException("Invalid service response.")

    def get_resource(self, path):
        """Getting the required information from the API."""
        try:
            response = self._http_request(path)
        except requests.exceptions.SSLError as exc:
            LOG.error(exc)
            raise exception.CertificateVerifyFailed(
                "HTTPS certificate validation failed.")

        return response

    def update_resource(self, path, data):
        """Update the required resource."""
        try:
            response = self._http_request(path, method="PUT",
                                          body=json.dumps(data))
        except requests.exceptions.SSLError as exc:
            LOG.error(exc)
            raise exception.CertificateVerifyFailed(
                "HTTPS certificate validation failed.")
        return response

    def remove_resource(self, path):
        """Delete the received resource."""
        try:
            self._http_request(path, method="DELETE")
        except requests.exceptions.SSLError as exc:
            LOG.error(exc)
            raise exception.CertificateVerifyFailed(
                "HTTPS certificate validation failed.")


class _BaseSDNModel(objects.Model):

    _endpoint = CONF.SDN2.url
    _client = _BaseClient()

    resource_ref = objects.Field(name="resource_ref", key="resourceRef",
                                 is_property=False)
    """A relative URI to an associated resource."""

    resource_id = objects.Field(name="resource_id", key="resourceId",
                                is_property=False)
    """The resource ID for the resource. The value MUST be unique in
    the context of the resource if it is a top-level resource, or in the
    context of the direct parent resource if it is a child resource."""

    instance_id = objects.Field(name="instance_id", key="instanceId",
                                is_property=False)
    """The globally unique Id generated and used internally by the Network
    Controller. The mapping resource that enables the client to map between
    the instanceId and the resourceId."""

    etag = objects.Field(name="etag", key="etag", is_property=False)
    """An opaque string representing the state of the resource at the
    time the response was generated."""

    def __init__(self, **fields):
        self._parent_id = fields.pop("parent_id", None)
        super(_BaseSDNModel, self).__init__(**fields)

    @property
    def parent_id(self):
        """The identifier for the specific ancestor resource."""
        return self._parent_id

    @classmethod
    def get(cls, resource_id=None, parent_id=None):
        """Retrieves the required resources.

        :param resource_id:      The identifier for the specific resource
                                 within the resource type.
        :param parent_id:        The identifier for the specific ancestor
                                 resource within the resource type.
        """

        endpoint = cls._endpoint.format(resource_id=resource_id or "",
                                        parent_id=parent_id or "")
        raw_data = cls._client.get_resource(endpoint)
        if resource_id is None:
            return [cls.from_raw_data(subnet) for subnet in raw_data["value"]]
        else:
            return cls.from_raw_data(raw_data)

    @classmethod
    def remove(cls, resource_id, parent_id=None):
        """Delete the required resource.

        :param resource_id:      The identifier for the specific resource
                                 within the resource type.
        :param parent_id:        The identifier for the specific ancestor
                                 resource within the resource type.
        """
        endpoint = cls._endpoint.format(resource_id=resource_id or "",
                                        parent_id=parent_id or "")
        cls._client.remove_resource(endpoint)

    def commit(self, wait=False):
        """Apply all the changes on the current model."""
        super(_BaseSDNModel, self).commit()
        endpoint = self._endpoint.format(resource_id=self.resource_id or "",
                                         parent_id=self.parent_id or "")
        request_body = self.dump(include_read_only=False)
        response = self._client.update_resource(endpoint, data=request_body)
        return self.from_raw_data(response)


class AccessControlLists(_BaseSDNModel):

    """Access Constrol List Model.

    An accessControlLists resource contains a list of ACL rules.
    Access control list resources can be assigned to virtual subnets
    or IP configurations.

    An ACL can be associated with:
        * Subnets of a virtual or logical network. This means that all
        network interfaces (NICs) with IP configurations created in the
        subnet inherit the ACL rules in the Access Control List. Often,
        subnets are used for a specific architectural tier (frontend,
        middle tier, backend) in more complex applications. Assigning
        an ACL to subnets can thus be used to control the network flow
        between the different tiers.
        *IP configuration of a NIC. This means that the ACL will be
        applied to the parent network interface of the specified IP
        configuration.
    """

    _endpoint = "/networking/v1/accessControlLists/{resource_id}"

    acl_rules = objects.Field(name="acl_rules", key="aclRules")
    """Indicates the rules in an access control list."""

    inbound_action = objects.Field(name="inbound_action",
                                   key="inboundDefaultAction",
                                   default="Permit")
    """Indicates the default action for Inbound Rules. Valid values are
    `Permit` and `Deny`. The default value is `Permit`."""

    outbound_action = objects.Field(name="outbound_action",
                                    key="outboundDefaultAction",
                                    default="Permit")
    """Indicates the default action for Outbound Rules. Valid values are
    `Permit` and `Deny`. The default value is `Permit`."""

    ip_configuration = objects.Field(name="ip_configuration",
                                     key="ipConfigurations")
    """Indicates references to IP addresses of network interfaces
    resources this access control list is associated with."""

    subnets = objects.Field(name="subnets", key="subnets")
    """Indicates an array of references to subnets resources this access
    control list is associated with."""


class ACLRules(_BaseSDNModel):

    """ACL Rules Model.

    The aclRules resource describes the network traffic that is allowed
    or denied for a network interface of a virtual machine. Currently,
    only inbound rules are expressed.
    """

    _endpoint = ("/networking/v1/accessControlLists/{parent_id}"
                 "/aclRules/{resource_id}")

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    action = objects.Field(name="action", key="action")
    """Indicates the action the ACL Rule will take. Valid values
    are: `Allow` and `Deny`."""

    destination_prefix = objects.Field(name="destination_prefix",
                                       key="destinationAddressPrefix")
    """Indicates the CIDR value of destination IP or a pre-defined tag
    to which traffic is destined. You can specify 0.0.0.0/0 for IPv4
    all and ::/0 for IPv6 all traffic."""

    destination_port_range = objects.Field(name="destination_port_range",
                                           key="destinationPortRange")
    """Indicates the destination port(s) that will trigger this ACL
    rule. Valid values include a single port, port range (separated by "-"),
    or "*" for all ports. All numbers are inclusive."""

    source_prefix = objects.Field(name="source_prefix",
                                  key="sourceAddressPrefix")
    """Indicates the CIDR value of source IP or a pre-defined TAG from
    which traffic is originating. You can specify 0.0.0.0/0 for IPv4 all
    and ::/0 forIPv6 all traffic."""

    source_port_range = objects.Field(name="source_port_range",
                                      key="sourcePortRange")
    """Indicates the source port(s) that will trigger this ACL rule.
    Valid values include a single port, port range (separated by "-"),
    or "*" for all ports. All numbers are inclusive."""

    description = objects.Field(name="description", key="description")
    """Indicates a description of the ACL rule."""

    logging = objects.Field(name="logging", key="logging",
                            default="Enabled")
    """Indicates whether logging will be turned on for when this
    rule gets triggered. Valid values are `Enabled` or `Disabled`."""

    priority = objects.Field(name="priority", key="priority")
    """Indicates the priority of the rule relative to the priority of
    other ACL rules. This is a unique numeric value in the context of
    an accessControlLists resource. Value from 101 - 65000 are user
    defined. Values 1 - 100 and 65001 - 65535 are reserved."""

    protocol = objects.Field(name="protocol", key="protocol")
    """Indicates the protocol to which the ACL rule will apply.
    Valid values are `TCP` or `UDP`."""

    rule_type = objects.Field(name="rule_type", key="type")
    """Indicates whether the rule is to be evaluated against ingress
    traffic (Inbound) or egress traffic (Outbound). Valid values are
    `Inbound` or `Outbound`."""


class IPConfiguration(_BaseSDNModel):

    """IP Configuration Model.

    This resource represents configuration information for IP addresses:
    allocation method, actual IP address, membership of a logical or virtual
    subnet, load balancing and access control information.
    """

    _endpoint = ("/networking/v1/networkInterfaces/{parent_id}"
                 "/ipConfigurations/{resource_id}")

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    access_controll_list = objects.Field(name="access_controll_list",
                                         key="accessControlList",
                                         is_required=False)
    """Indicates a reference to an accessControlList resource that defines
    the ACLs in and out of the IP Configuration."""

    backend_address_pools = objects.Field(
        name="backend_address_pools", key="loadBalancerBackendAddressPools",
        is_required=False, is_read_only=True)
    """Reference to backendAddressPools child resource of loadBalancers
    resource."""

    inbound_nat_rules = objects.Field(
        name="loadBalancerInboundNatRules", key="loadBalancerInboundNatRules",
        is_required=False)
    """Reference to inboundNatRules child resource of loadBalancers
    resource."""

    private_ip_address = objects.Field(
        name="private_ip_address", key="privateIPAddress",
        is_required=False)
    """Indicates the private IP address of the IP Configuration."""

    private_ip_allocation_method = objects.Field(
        name="private_ip_allocation_method", key="privateIPAllocationMethod",
        is_required=False)
    """Indicates the allocation method (Static or Dynamic)."""

    public_ip_address = objects.Field(
        name="public_ip_address", key="privateIpAddress",
        is_required=False)
    """Indicates the public IP address of the IP Configuration."""

    service_insertion = objects.Field(
        name="service_insertion", key="serviceInsertion",
        is_required=False)
    """Indicates a reference to a serviceInsertion resource that defines
    the service insertion in and out of the IP Configuration."""

    subnet = objects.Field(name="subnet", key="subnet", is_read_only=True)
    """Indicates a reference to the subnet resource that the IP Configuration
    is connected to."""


class LogicalNetworks(_BaseSDNModel):

    """Logical networks model.

    The logicalNetworks resource represents a logical partition of physical
    network that is dedicated for a specific purpose.
    A logical network comprises of a collection of logical subnets.
    """

    _endpoint = "/networking/v1/logicalNetworks/{resource_id}"

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    subnetworks = objects.Field(name="subnetworks", key="subnets",
                               is_required=False, default=[])
    """Indicates the subnets that are contained in the logical network."""

    network_virtualization_enabled = objects.Field(
        name="network_virtualization_enabled",
        key="networkVirtualizationEnabled", default=False, is_required=False)
    """Indicates if the network is enabled to be the Provider Address network
    for one or more virtual networks. Valid values are `True` or `False`.
    The default is `False`."""

    virtual_networks = objects.Field(name="virtual_networks",
                                     key="virtualNetworks",
                                     is_read_only=True)
    """Indicates an array of virtualNetwork resources that are using
    the network."""

    @classmethod
    def from_raw_data(cls, raw_data):
        """Create a new model using raw API response."""
        subnetworks = []
        for raw_subnet in raw_data["properties"].get("subnets", []):
            subnetworks.append(LogicalSubnetworks.from_raw_data(raw_subnet))
        raw_data["properties"]["subnets"] = subnetworks

        virtual_networks = []
        for raw_network in raw_data["properties"].get("virtualNetworks", []):
            virtual_networks.append(Resource.from_raw_data(raw_network))
        raw_data["properties"]["virtualNetworks"] = virtual_networks

        return super(LogicalNetworks, cls).from_raw_data(raw_data)


class LogicalSubnetworks(_BaseSDNModel):

    """Logical subnetworks model.

    The logicalSubnets resource consists of a subnet/VLAN pair.
    The vlan resource is required; however it MAY contain a value of zero
    if the subnet is not associated with a vlan.
    """

    _endpoint = ("/networking/v1/logicalNetworks/{parent_id}"
                 "/logicalSubnets/{resource_id}")

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    address_prefix = objects.Field(name="address_prefix", key="addressPrefix")
    """Identifies the subnet id in form of ipAddresss/prefixlength."""

    vlan_id = objects.Field(name="vlan_id", key="vlanId", is_required=True,
                            default=0)
    """Indicates the VLAN ID associated with the logical subnet."""

    routes = objects.Field(name="routes", key="routes", is_required=False)
    """Indicates the routes that are contained in the logical subnet."""

    ip_pools = objects.Field(name="ip_pools", key="ipPools",
                             is_required=False)
    """Indicates the IP Pools that are contained in the logical subnet."""

    dns_servers = objects.Field(name="dns_servers", key="dnsServers",
                                is_required=False)
    """Indicates one or more DNS servers that are used for resolving DNS
    queries by devices or host connected to this logical subnet."""

    network_interfaces = objects.Field(name="network_interfaces",
                                       key="networkInterfaces",
                                       is_read_only=True)
    """Indicates an array of references to networkInterfaces resources
    that are attached to the logical subnet."""

    is_public = objects.Field(name="is_public", key="isPublic")
    """Boolean flag specifying whether the logical subnet is a
    public subnet."""

    default_gateways = objects.Field(name="default_gateways",
                                     key="defaultGateways")
    """A collection of one or more gateways for the subnet."""


class SubNetwork(_BaseSDNModel):

    """SubNetwork Model.

    The subnets resource is used to create Virtual Subnets (VSIDs) under
    a tenant's virtual network (RDID). The user can specify the addressPrefix
    to use for the subnets, the accessControl Lists to protect the subnets,
    the routeTable to be applied to the subnet, and optionally the service
    insertion to use within the subnet.
    """

    _endpoint = ("/networking/v1/virtualNetworks/{parent_id}"
                 "/subnets/{resource_id}")

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    address_prefix = objects.Field(name="address_prefix", key="addressPrefix",
                                   is_required=True)
    """Indicates the address prefix that defines the subnet. The value is
    in the format of 0.0.0.0/0. This value must not overlap with other
    subnets in the virtual network and must fall in the addressPrefix defined
    in the virtual network."""

    access_controll_list = objects.Field(name="access_controll_list",
                                         key="accessControlList",
                                         is_required=False)
    """Indicates a reference to an accessControlLists resource that defines
    the ACLs in and out of the subnet."""

    service_insertion = objects.Field(name="service_insertion",
                                      key="serviceInsertion",
                                      is_required=False)
    """Indicates a reference to a serviceInsertions resource that defines the
    service insertion to be applied to the subnet."""

    route_table = objects.Field(name="route_table", key="routeTable",
                                is_required=False)
    """Indicates a reference to a routeTable resource that defines the tenant
    routes to be applied to the subnet."""

    ip_configuration = objects.Field(name="ip_configuration",
                                     key="ipConfigurations",
                                     is_read_only=False)
    """Indicates an array of references of networkInterfaces resources that
    are connected to the subnet."""


class VirtualNetworks(_BaseSDNModel):

    """Virtual Network Model.

    This resource is used to create a virtual network using HNV for tenant
    overlays. The default encapsulation for virtualNetworks is Virtual
    Extensible LAN but this can be changed by updating the virtual
    NetworkManager resource. Similarly, the HNV Distributed Router is enabled
    by default but this can be overridden using the virtualNetworkManager
    resource.
    """

    _endpoint = "/networking/v1/virtualNetworks/{resource_id}"

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    configuration_state = objects.Field(name="configuration_state",
                                        key="configurationState",
                                        is_read_only=True)
    """Indicates the last known running state of this resource."""

    address_space = objects.Field(name="address_space",
                                  key="addressSpace",
                                  is_required=True)
    """Indicates the address space of the virtual network."""

    dhcp_options = objects.Field(name="dhcp_options", key="dhcpOptions",
                                 is_required=False)
    """Indicates the DHCP options used by servers in the virtual
    network."""

    subnetworks = objects.Field(name="subnetworks", key="subnets",
                                is_required=False)
    """Indicates the subnets that are on the virtual network."""

    logical_network = objects.Field(name="logical_network",
                                    key="logicalNetwork",
                                    is_required=True)
    """Indicates a reference to the networks resource that is the
    underlay network which the virtual network runs on."""


class MacPools(_BaseSDNModel):

    """MacPools Model.

    The macPools resource specifies a range of MAC addresses which are used
    internally by the Network Controller service modules and are plumbed down
    to the hosts for items such as Host vNICs.
    """

    _endpoint = "/networking/v1/macPools/{resource_id}"

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    start_mac_address = objects.Field(name="start_mac_address",
                                      key="startMacAddress",
                                      is_required=True)
    """This is a string in the form of "AA-BB-CC-DD-EE-FF"."""

    end_mac_address = objects.Field(name="end_mac_address",
                                    key="endMacAddress",
                                    is_required=True)
    """This is a string in the form of "UU-VV-WW-XX-YY-ZZ"."""

    usage = objects.Field(name="usage", key="usage", is_read_only=True)
    """Usage statistics of the MAC address pool."""


class NetworkInterfaces(_BaseSDNModel):

    """Network Interface Model.

    The networkInterfaces resource specifies the configuration of either
    a host virtual interface (host vNIC) or a virtual server NIC (VMNIC).
    """

    _endpoint = "/networking/v1/networkInterfaces/{resource_id}"

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    dns_settings = objects.Field(name="dns_settings", key="dnsSettings",
                                 is_read_only=True)
    """Indicates the DNS settings of this network interface."""

    ip_configurations = objects.Field(name="ip_configurations",
                                      key="ipConfigurations")
    """Indicates an array of IP configurations that are contained
    in the network interface."""

    is_host = objects.Field(name="is_host",
                            key="isHostVirtualNetworkInterface")
    """True if this is a host virtual interface (host vNIC)
    False if this is a virtual server NIC (VMNIC)."""

    is_primary = objects.Field(name="is_primary", key="isPrimary",
                               default=True)
    """`True` if this is the primary interface and the default
    value if the property is not set or `False` if this is a
    secondary interface."""

    is_multitenant_stack = objects.Field(name="is_multitenant_stack",
                                         key="isMultitenantStack",
                                         default=False)
    """`True` if allows the NIC to be part of multiple virtual networks
    or `False` if the opposite."""

    internal_dns_name = objects.Field(name="internal_dns_name",
                                      key="internalDnsNameLabel")
    """Determines the name that will be registered in iDNS
    when the iDnsServer resource is configured."""

    server = objects.Field(name="server", key="server",
                           is_read_only=True)
    """Indicates a reference to the servers resource for the
    machine that is currently hosting the virtual machine to
    which this network interface belongs."""

    port_settings = objects.Field(name="port_settings", key="portSettings")
    """A PortSettings object."""

    mac_address = objects.Field(name="mac_address", key="privateMacAddress")
    """Indicates the private MAC address of this network interface."""

    mac_allocation_method = objects.Field(name="mac_allocation_method",
                                          key="privateMacAllocationMethod")
    """Indicates the allocation scheme of the MAC for this
    network interface."""

    service_insertion_elements = objects.Field(
        name="service_insertion_elements", key="serviceInsertionElements",
        is_read_only=True)
    """Indicates an array of serviceInsertions resources that
    this networkInterfaces resource is part of."""


class PortSettings(objects.Model):

    """Port Settings Model."""

    mac_spoofing = objects.Field(name="mac_spoofing", key="macSpoofing",
                                 is_required=False)
    """Specifies whether virtual machines can change the source MAC
    address in outgoing packets to one not assigned to them."""

    arp_guard = objects.Field(name="arp_guard", key="arpGuard",
                              is_required=False)
    """Specifies whether ARP guard is enabled or not. ARP guard
    will allow only addresses specified in ArpFilter to pass through
    the port."""

    dhcp_guard = objects.Field(name="dhcp_guard", key="dhcpGuard",
                               is_required=False)
    """Specifies the number of broadcast, multicast, and unknown
    unicast packets per second a virtual machine is allowed to
    send through the specified virtual network adapter."""

    storm_limit = objects.Field(name="storm_limit", key="stormLimit",
                                is_required=False)
    """Specifies the number of broadcast, multicast, and unknown
    unicast packets per second a virtual machine is allowed to
    send through the specified virtual network adapter."""

    port_flow_limit = objects.Field(name="port_flow_limit",
                                    key="portFlowLimit",
                                    is_required=False)
    """Specifies the maximum number of flows that can be executed
    for the port."""

    vmq_weight = objects.Field(name="vmq_weight", key="vmqWeight",
                               is_required=False)
    """Specifies whether virtual machine queue (VMQ) is to be
    enabled on the virtual network adapter."""

    iov_weight = objects.Field(name="iov_weight", key="iovWeight",
                               is_required=False)
    """Specifies whether single-root I/O virtualization (SR-IOV) is to
    be enabled on this virtual network adapter."""

    iov_interrupt_moderation = objects.Field(name="iov_interrupt_moderation",
                                             key="iovInterruptModeration",
                                             is_required=False)
    """Specifies the interrupt moderation value for a single-root I/O
    virtualization (SR-IOV) virtual function assigned to a virtual
    network adapter."""

    iov_queue_pairs = objects.Field(name="iov_queue_pairs",
                                    key="iovQueuePairsRequested",
                                    is_required=False)
    """Specifies the number of hardware queue pairs to be allocated
    to an SR-IOV virtual function."""

    outbound_reserved_value = objects.Field(name="outbound_reserved_value",
                                            key="outboundReservedValue",
                                            is_required=False)
    """If outboundReservedMode is "absolute" then the value indicates the
    bandwidth, in Mbps, guaranteed to the virtual port for transmission
    (egress)."""

    outbound_maximum_mbps = objects.Field(name="outbound_maximum_mbps",
                                          key="QosSettings",
                                          is_required=False)
    """Indicates the maximum permitted send-side bandwidth, in Mbps,
    for the virtual port (egress)."""

    inbound_maximum_mbps = objects.Field(name="inbound_maximum_mbps",
                                         key="QosSettings",
                                         is_required=False)
    """Indicates the maximum permitted receive-side bandwidth for the
    virtual port (ingress) in Mbps."""


class ServiceInsertions(_BaseSDNModel):

    """Service Insertion Model.

    The serviceInsertions resource specifies the relationship between
    the service insertion and the service insertion rule.
    """

    _endpoint = "/networking/v1/ServiceInsertions/{resource_id}"

    provisioning_state = objects.Field(name="provisioning_state",
                                       key="provisioningState",
                                       is_read_only=True)
    """Indicates the various states of the resource. Valid values are
    Deleting, Failed, Succeeded, and Updating."""

    ip_configuration = objects.Field(name="ip_configuration",
                                     key="ipConfigurations",
                                     is_read_only=True)
    """Indicates references to IP addresses of network interfaces
    resources this access control list is associated with."""

    priority = objects.Field(name="priority", key="priority",
                             is_required=True)
    """Indicates the relative order in which the policies are processed."""

    insertion_type = objects.Field(name="insertion_type", key="type",
                                   is_required=True)
    """Indicate the type of service insertion. Valid value is PortMirror."""

    rules = objects.Field(name="rules", key="rules", is_required=False)
    """Indicates an array of rules used to define what traffic will go
    through the service insertion."""

    insertion_elements = objects.Field(name="insertion_elements",
                                       key="serviceInsertionElements",
                                       is_required=False)
    """Indicates an array of elements in the list of network interfaces
    to send packets matching rules through."""

    subnets = objects.Field(name="subnets", key="subnets", is_read_only=True)
    """Indicates an array of references to subnets resources with which
    this serviceInsertions resource is associated."""


class ConfigurationState(objects.Model):

    """Model for configuration state."""

    uuid = objects.Field(name="uuid", key="id")
    status = objects.Field(name="status", key="status")
    last_update = objects.Field(name="last_update",
                                key="lastUpdatedTime")
    interface_errors = objects.Field(name="interface_errors",
                                     key="virtualNetworkInterfaceErrors")
    host_errors = objects.Field(name="host_erros", key="hostErrors")


class VirtualInterfaceError(objects.Model):

    """Model for Virtual interface errors."""

    uuid = objects.Field(name="uuid", key="id")
    status = objects.Field(name="status", key="status")
    details = objects.Field(name="details", key="detailedInfo")
    last_update = objects.Field(name="last_update", key="lastUpdatedTime")


class AddressSpace(objects.Model):

    """Indicates the address space of the virtual network."""

    address_prefixes = objects.Field(name="address_prefixes",
                                     key="addressPrefixes",
                                     is_property=False,
                                     is_required=True)
    """Indicates the valid list of address prefixes that
    can make up this virtual network. The value is an array
    of address prefixes in the format of 0.0.0.0/0.
    The space cannot be shrunk if addresses are in use in a
    subnet belonging to the virtual network.
    """


class Resource(objects.Model):

    """Model for the resource references."""

    resource_ref = objects.Field(name="resource_ref", key="resourceRef",
                                 is_property=False, is_required=True)
    """A relative URI to an associated resource."""
