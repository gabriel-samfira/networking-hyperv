import netaddr

from neutron_lib import constants as const

from hnv import client
from hnv.common import exception as hnv_exception
from hyperv.neutron import constants

from networking_ovn.common import extensions
from neutron.services import service_base
from neutron.db import common_db_mixin
from neutron.db import extraroute_db


LOG = log.getLogger(__name__)

def get_manager(port):
    owner = port.get("device_owner")
    if owner == const.DEVICE_OWNER_ROUTER_GW:
        return LoadBalancerManager()
    elif owner == const.DEVICE_OWNER_FLOATINGIP:
        return PublicIPAddressManager()
    return None


class HNVL3RouterPlugin(service_base.ServicePluginBase,
                        common_db_mixin.CommonDbMixin,
                        extraroute_db.ExtraRoute_dbonly_mixin,
                        HNVMixin):

    supported_extension_aliases = 'router'

    def __init__(self):
        LOG.info(_LI("Starting HNVL3RouterPlugin"))
        super(HNVL3RouterPlugin, self).__init__()

    def add_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(OVNL3RouterPlugin, self).add_router_interface(
                context, router_id, interface_info)

        LOG.debug("ARGS %r ---->>> %r ----->>> %r" % (context, router_id, interface_info))
        LOG.debug("INTERFACE info: %r" % router_interface_info)
        # port = self._plugin.get_port(context, router_interface_info['port_id'])
        # if (len(router_interface_info['subnet_ids']) == 1 and
        #         len(port['fixed_ips']) > 1):
        #     # NOTE(lizk) It's adding a subnet onto an already existing router
        #     # interface port, try to update lrouter port 'networks' column.
        #     self.update_lrouter_port_in_ovn(context, router_id, port)
        # else:
        #     self.create_lrouter_port_in_ovn(context, router_id, port)
        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(OVNL3RouterPlugin, self).remove_router_interface(
                context, router_id, interface_info)

        LOG.debug("ARGS %r ---->>> %r ----->>> %r" % (context, router_id, interface_info))
        LOG.debug("INTERFACE info: %r" % router_interface_info)
        # port_id = router_interface_info['port_id']
        # try:
        #     port = self._plugin.get_port(context, port_id)
        #     # The router interface port still exists, call ovn to update it.
        #     self.update_lrouter_port_in_ovn(context, router_id, port)
        # except n_exc.PortNotFound:
        #     # The router interface port doesn't exist any more, call ovn to
        #     # delete it.
        #     self._ovn.delete_lrouter_port(utils.ovn_lrouter_port_name(port_id),
        #                                   utils.ovn_name(router_id),
        #                                   if_exists=False
        #                                   ).execute(check_error=True)
        return router_interface_info


class HNVMixin(object):

    @property
    def _admin_context(self):
        admin_ctx = getattr(self, "_admin_context_property", None)
        if admin_ctx:
            return admin_ctx
        self._admin_context_property = n_context.get_admin_context()
        return self._admin_context_property

    @property
    def _plugin(self):
        plugin_property = getattr(self, "_plugin_property", None)
        if plugin_property:
            return plugin_property
        self._plugin_property = directory.get_plugin()
        return self._plugin_property

    def _get_lnsubnet_for_ip(self, ip):
        subnet_id = ip["subnet_id"]
        subnet = self._plugin.get_subnet(
                    self._admin_context,
                    subnet_id)
        subnet = client.LogicalSubnetworks.get(
            parent_id=subnet["network_id"],
            resource_id=logical_subnet)
        net = netaddr.IPNetwork(subnet.address_prefix)
        if ip["ip_address"] in net:
            return subnet
        return None
        

class LoadBalancerManager(HNVMixin):

    def __init__(self):
        self._ln_cache = {}

    def _get_logical_network(self, network_id):
        if self._ln_cache.get(network_id):
            return self._ln_cache[network_id]
        ln = client.LogicalNetworks.get(resource_id=network_id)
        self._ln_cache[network_id] = ln
        return self._ln_cache[network_id]

    def _get_resource_ids(self, port):
        port_id = port["id"]
        lb_id = "lb-%s" % port_id
        fe_id = "fe-%s" % port_id
        be_id = "fe-%s" % port_id
        onat_id = "onat-%s" % port_id
        return {
            "lb-id": lb_id,
            "fe-id": fe_id,
            "be-id": be_id,
            "onat-id": onat_id,
        }

    def _get_frontend_ip_configurations(self, ips, load_balancer):
        ret = []
        lb = load_balancer
        for ip in ips:
            frontend_id = "fe-%s" % ip["ip_address"]
            ip_subnet = self._get_lnsubnet_for_ip(ip)
            if not ip_subnet:
                raise Exception("Failed to find subnet for ip %(ip)s in "
                    "network controller" % {
                        "ip": ip["ip_address"]})
            #TODO: Consider using wait=False wherever possible.
            fe = client.FrontendIPConfigurations(
                tags={"provider": constants.HNV_PROVIDER_NAME},
                parent_id=lb.resource_id,
                resource_id=frontend_id,
                subnet=ip_subnet,
                private_ip_address=ip["ip_address"],
                private_ip_allocation_method="Static").commit(wait=True)
            ret.append(fe.resource_ref)
        return ret

    def _create_load_balancer(self, port):
        resource_ids = self._get_resource_ids(port)
        try:
            lb = client.LoadBalancers.get(resource_id["lb-id"])
            return lb
        except hnv_exception.NotFound:
            LOG.debug("Creating new load balancer %s" % resource_id["lb-id"])

        fixed_ips = port.get("fixed_ips")
        if not fixed_ips:
            LOG.debug("No fixed ips set on this port. Nothing to do")
            return
        lb = client.LoadBalancers(
            tags={"provider": constants.HNV_PROVIDER_NAME},
            resource_id=resource_ids["lb-id"]).commit(wait=True)
        fe_ips = cls._get_frontend_ip_configurations(fixed_ips, lb)
        if len(fe_ips) == 0:
            raise Exception("Failed to get frontend IP configurations")
        be = client.BackendAddressPools(
            tags={"provider": constants.HNV_PROVIDER_NAME},
            parent_id=lb.resource_id,
            resource_id=resource_ids["be-id"]).commit(wait=True)
        onat = client.OutboundNATRules(
            tags={"provider": constants.HNV_PROVIDER_NAME},
            resource_id=resource_ids["onat-id"],
            parent_id=lb.resource_id,
            frontend_ip_configurations=fe_ips,
            backend_address_pool=be.resource_ref,
            protocol="All").commit(wait=True)
        return client.LoadBalancers.get(resource_id=lb.resource_id)

    def _remove_load_balancer(self, port):
        resource_ids = self._get_resource_ids(port)
        client.LoadBalancers.remove(resource_id=resource_ids["lb-id"])

    @classmethod
    def create(cls, port):
        obj = cls()
        return obj._create_load_balancer(port)
        
    @classmethod
    def remove(cls, port):
        obj = cls()
        return obj._remove_load_balancer(port)

"""
{
  "allowed_address_pairs": [], 
  "extra_dhcp_opts": [], 
  "updated_at": "2017-02-09T23:01:30Z", 
  "device_owner": "network:floatingip", 
  "revision_number": 3, 
  "binding:profile": {}, 
  "fixed_ips": [
    {
      "subnet_id": "1c256e00-45d5-40ef-ba2c-b94aa2e137df", 
      "ip_address": "10.7.12.100"
    }
  ], 
  "id": "adece209-0a5a-445f-a91f-bbb7fd8e580f", 
  "security_groups": [], 
  "binding:vif_details": {}, 
  "binding:vif_type": "unbound", 
  "mac_address": "00:1d:d8:01:f0:6e", 
  "device_id": "PENDING", 
  "status": "N/A", 
  "binding:host_id": "", 
  "description": "", 
  "qos_policy_id": null, 
  "project_id": "", 
  "name": "", 
  "admin_state_up": true, 
  "network_id": "ca44b6f3-b5dc-4a70-942e-7434e14d8b1f", 
  "tenant_id": "", 
  "created_at": "2017-02-09T23:01:30Z", 
  "binding:vnic_type": "normal"
}

"""
class PublicIPAddressManager(HNVMixin):

    def _get_vip_id(self, port):
        owner = port.get("device_owner")
        if owner != const.DEVICE_OWNER_FLOATINGIP:
            raise ValueError("Invalid port owner for floating IP")
        vip_id = port.get("device_id")
        if not vip_id:
            raise ValueError("Port does not have device ID assigned")
        return vip_id

    def _create(self, port):
        vip_id = self._get_vip_id(port)
        ips = port.get("fixed_ips")
        if len(ips) == 0:
            LOG.debug("No fixed_ips to work with")
            return
        try:
            public_ip = client.PublicIPAddresses.get(resource_id=vip_id)
            return public_ip
        except hnv_exception.NotFound:
            LOG.debug("Creating public IP address %(public_ip)s" % {
                'public_ip': ips[0]["ip_address"]})
        # There should be only one floating IP on
        # a port
        subnet = self._get_lnsubnet_for_ip(ips[0])
        if not subnet:
            raise Exception("Failed to find subnet for ip %(ip)s in "
                "network controller" % {"ip": ip["ip_address"]})
        public_ip = client.PublicIPAddresses(
            tags={"provider": constants.HNV_PROVIDER_NAME},
            resource_id=vip_id,
            ip_address=ips[0]["ip_address"],
            allocation_method="Static",
            idle_timeout=4).commit(wait=True)
        return public_ip

    def _delete(self, port):
        vip_id = self._get_vip_id(port)
        ips = port.get("fixed_ips")
        try:
            vip = client.PublicIPAddresses.get(resource_id=vip_id)
        except hnv_exception.NotFound:
            return
        if vip.ip_configuration:
            # if we get here, it means that neutron has already
            # dissassociated this IP address from its ports and
            # has issued a delete. We may be out of sync. Disassociate
            # IP and delete
            self._disassociate_public_ip({
                'floating_ip_address': ips[0]["ip_address"],
                'floating_ip_id': vip_id
                })
        vip.remove(resource_id=vip.resource_id)

    def _get_and_validate_vip(self, vip, vip_id):
        ip = client.PublicIPAddresses.get(resource_id=vip_id)
        if ip.ip_address != vip:
            raise ValueError("floating_ip_address %(neutron_address)s has "
                "a different value from the IP associated with "
                "floating_ip_id in the network controller %(nc_address)s" % {
                'neutron_address': vip,
                'nc_address': ip.ip_address})
        return ip

    def _associate_public_ip(self, assoc_data):
        dip = assoc_data["fixed_ip_address"]
        net_adapter_id = assoc_data["fixed_port_id"]
        vip_address = assoc_data["floating_ip_address"]
        vip_id = assoc_data["floating_ip_id"]
        vip_obj = self._get_and_validate_vip(vip_address, vip_id)
        vip_resource_ref = client.Resource(resource_ref=vip_obj.resource_ref)
        net_adapter = client.NetworkInterfaces.get(resource_id=net_adapter_id)
        found = False
        for idx, val in enumerate(net_adapter.ip_configurations):
            if net_adapter.ip_configurations[idx].private_ip_address == dip:
                net_adapter.ip_configurations[idx].public_ip_address = vip_obj
                found = True
                break
        if not found:
            raise Exception("Failed to find DIP %(dip)s on network interface "
                "%(network_interface)s" % {
                'dip': dip,
                'network_interface': net_adapter_id})
        return net_adapter.commit(wait=true)

    def _disassociate_public_ip(self, assoc_data):
        dip = assoc_data["fixed_ip_address"]
        net_adapter_id = assoc_data["fixed_port_id"]
        vip_address = assoc_data["floating_ip_address"]
        vip_id = assoc_data["floating_ip_id"]
        vip_obj = self._get_and_validate_vip(vip_address, vip_id)
        if not vip_obj.ip_configuration:
            return
        ip_config = vip_obj.ip_configuration.get_resource()
        ip_config.public_ip = None
        ip_config.commit(wait=True)

    @classmethod
    def update_vip_association(cls, assoc_data):
        obj = cls()
        dip = assoc_data["fixed_ip_address"]
        net_adapter_id = assoc_data["fixed_port_id"]
        if dip and net_adapter_id:
            return obj._associate_public_ip(assoc_data)
        return obj._disassociate_public_ip(assoc_data)

    @classmethod
    def create(cls, port):
        obj = cls()
        return obj._create(port)

    @classmethod
    def remove(cls, port):
        obj = cls()
        return obj._delete(port)

"""
{
    'fixed_ip_address': internal_ip_address,
    'fixed_port_id': port_id,
    'router_id': router_id,
    'last_known_router_id': previous_router_id,
    'floating_ip_address': floatingip_db.floating_ip_address,
    'floating_network_id': floatingip_db.floating_network_id,
    'floating_ip_id': floatingip_db.id,
    'next_hop': next_hop,
    'context': context}
"""

