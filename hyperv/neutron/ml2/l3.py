import netaddr

from oslo_log import log

from neutron_lib import constants as const

from hnv import client
from hnv.common import exception as hnv_exception
from hyperv.neutron import constants
from hyperv.common.i18n import _, _LE, _LI

from neutron_lib.plugins import directory

from neutron.plugins.common import constants as n_const
from neutron import context as n_context
from neutron.callbacks import registry
from neutron.callbacks import resources
from neutron.callbacks import events

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


class HNVMixin(common_db_mixin.CommonDbMixin,
        extraroute_db.ExtraRoute_dbonly_mixin):

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
            resource_id=subnet_id)
        net = netaddr.IPNetwork(subnet.address_prefix)
        if ip["ip_address"] in net:
            return subnet
        return None

    def _get_lb_for_router(self, router):
        ext_port_id = router.get("gw_port_id")
        if not ext_port_id:
            LOG.debug("Router %s has no external network set. Nothing to do here" % router_id)
            return

        ext_port = self._plugin.get_port(self._admin_context, ext_port_id)
        lb = LoadBalancerManager.get(ext_port)
        if not lb.backend_address_pools:
            LOG.debug("There are no backend address pools defined on %s" % lb.resource_id)
            return
        return lb

    def _get_lb_for_router_by_id(self, router_id):
        router = self.get_router(self._admin_context, router_id)
        return self._get_lb_for_router(router)

    def _get_attached_router_interfaces(self, context, router_id):
        filters = dict(
                device_id=[router_id],
                device_owner=[const.DEVICE_OWNER_ROUTER_INTF])
        ports = self._plugin.get_ports(context, filters=filters)
        return ports

    def _get_virtual_networks(self, ids):
        vn = client.VirtualNetworks.get()
        return [i for i in vn if i.resource_id in ids]

    def _get_network_interfaces(self, ids):
        net = client.NetworkInterfaces.get()
        return {i.resource_id: i for i in net if i.resource_id in ids}

    def _get_subnet_info_from_interface(self, interface):
        net_id = interface["network_id"]
        ret = []
        fixed_ips = interface.get("fixed_ips", [])
        for i in fixed_ips:
            tmp = {
                'network_id': net_id,
                'subnet_id': i["subnet_id"]
            } 
            if tmp in ret:
                continue
            ret.append(tmp)
        return ret

    def _get_connected_interfaces(self, subnets):
        ip_configurations = []
        net_ids = [i["network_id"] for i in subnets]
        virt_nets = self._get_virtual_networks(net_ids)
        for net in virt_nets:
            for sub in net.subnetworks:
                details = {
                    "network_id": sub.parent_id,
                    "subnet_id": sub.resource_id
                }
                if details in subnets:
                    for ip in sub.ip_configuration:
                        ip_configurations.append(ip.get_resource())
        # Unfortunately, calling PUT on an IP resource is not allowed (for some reason). To update the
        # NAT load balancer, we need to update the IP configuration as part of the network interface
        # and call PUT on the network interface itself
        net_iface_ids = [i.parent_id for i in ip_configurations]
        net_ifaces = self._get_network_interfaces(net_iface_ids)
        ret = {}
        for i in ip_configurations:
            if not ret.get(i.parent_id):
                ret[i.parent_id] = {
                    "iface": net_ifaces[i.parent_id],
                    "ip_configs": []}
            ret[i.parent_id]["ip_configs"].append(i.resource_id)
        return ret


class LoadBalancerManager(HNVMixin):

    def __init__(self):
        self._ln_cache = {}
        self._subnet_lb_cache = {}

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

    def _get_frontend_ip_configurations(self, ips, resource_ids):
        ret = []
        for ip in ips:
            frontend_id = "%s-%s" % (resource_ids["fe-id"], ip["ip_address"])
            ip_subnet = self._get_lnsubnet_for_ip(ip)
            if not ip_subnet:
                raise Exception("Failed to find subnet for ip %(ip)s in "
                    "network controller" % {
                        "ip": ip["ip_address"]})
            #TODO: Consider using wait=False wherever possible.
            fe = client.FrontendIPConfigurations(
                tags={"provider": constants.HNV_PROVIDER_NAME},
                parent_id=resource_ids["lb-id"],
                resource_id=frontend_id,
                subnet=ip_subnet,
                private_ip_address=ip["ip_address"],
                private_ip_allocation_method="Static")
            LOG.debug("Creating FRONTEND IP config: %r" % fe.dump())
            ret.append(fe)
        return ret

    def _create_load_balancer(self, port):
        resource_ids = self._get_resource_ids(port)
        try:
            lb = client.LoadBalancers.get(resource_ids["lb-id"])
            return lb
        except hnv_exception.NotFound:
            LOG.debug("Creating new load balancer %s" % resource_ids["lb-id"])

        fixed_ips = port.get("fixed_ips")
        if not fixed_ips:
            LOG.debug("No fixed ips set on this port. Nothing to do")
            return
        fe_ips = self._get_frontend_ip_configurations(
            fixed_ips, resource_ids)
        if len(fe_ips) == 0:
            raise Exception("Failed to get frontend IP configurations")
        be = client.BackendAddressPools(
            tags={"provider": constants.HNV_PROVIDER_NAME},
            parent_id=resource_ids["lb-id"],
            resource_id=resource_ids["be-id"])
        onat = client.OutboundNATRules(
            tags={"provider": constants.HNV_PROVIDER_NAME},
            resource_id=resource_ids["onat-id"],
            parent_id=resource_ids["lb-id"],
            frontend_ip_configurations=fe_ips,
            backend_address_pool=be,
            protocol="All")
        lb = client.LoadBalancers(
            tags={"provider": constants.HNV_PROVIDER_NAME},
            resource_id=resource_ids["lb-id"],
            outbound_nat_rules=[onat,],
            backend_address_pools=[be,],
            frontend_ip_configurations=fe_ips)
        lb.commit(wait=True)
        return client.LoadBalancers.get(resource_id=lb.resource_id)

    def _remove_load_balancer_by_id(self, lb_id):
        client.LoadBalancers.remove(resource_id=lb_id)

    def _remove_load_balancer(self, port):
        resource_ids = self._get_resource_ids(port)
        self._remove_load_balancer_by_id(resource_ids["lb-id"])

    def _get_router_interfaces_for_subnet(self, subnet):
        filters = {
            'network_id': [subnet["network_id"]],
            'device_owner': [const.DEVICE_OWNER_ROUTER_INTF], 
            'fixed_ips': {'subnet_id': [subnet["subnet_id"]]}
        }
        ports = self._plugin.get_ports(self._admin_context, filters=filters)
        return ports

    def _subnet_cache_key(self, subnet):
        return "%s-%s" % (subnet["subnet_id"], subnet["network_id"])

    def _get_lb_for_port(self, port):
        # TODO: check if there is an easier way to get the
        # gw_port_id starting from the port of a VM
        subnet_info = self._get_subnet_info_from_interface(port)
        ret = []
        for subnet in subnet_info:
            k = self._subnet_cache_key(subnet)
            if k in self._subnet_lb_cache:
                ret.append(self._subnet_lb_cache[k])
                continue
            router_int = self._get_router_interfaces_for_subnet(subnet)
            for r_int in router_int:
                router_id = r_int["device_id"]
                lb = self._get_lb_for_router_by_id(router_id)
                self._subnet_lb_cache[k] = lb
                ret.append(lb)
        return ret

    def _get_load_balancer(self, port):
        resource_ids = self._get_resource_ids(port)
        return client.LoadBalancers.get(resource_id=resource_ids["lb-id"])

    @classmethod
    def get_all(cls):
        vips = client.LoadBalancers.get()
        ret = {}
        # TODO: abstract this logic. It's used in various places
        for i in vips:
            if not i.tags or i.tags.get("provider") != constants.HNV_PROVIDER_NAME:
                continue
            ret[i.resource_id[3:]] = i
        return ret

    def get_port_backend_pool(self, port):
        lbs = self._get_lb_for_port(port)
        ret = []
        for i in lbs:
            ret.append(i.backend_address_pools[0])
        return ret

    @classmethod
    def bulk_create(cls, ports):
        obj = cls()
        for port in ports:
            obj._create_load_balancer(port)

    @classmethod
    def create(cls, port):
        obj = cls()
        return obj._create_load_balancer(port)
        
    @classmethod
    def remove(cls, port):
        obj = cls()
        return obj._remove_load_balancer(port)

    @classmethod
    def bulk_remove_by_id(cls, ports):
        obj = cls()
        for i in ports:
            obj._remove_load_balancer_by_id(i)

    @classmethod
    def get(cls, port):
        obj = cls()
        return obj._get_load_balancer(port)

class PublicIPAddressManager(HNVMixin):

    def _get_vip_id(self, port):
        owner = port.get("device_owner")
        if owner != const.DEVICE_OWNER_FLOATINGIP:
            raise ValueError("Invalid port owner for floating IP: %r" % owner)
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

    def _delete_by_id(self, vip_id, fixed_ips=None):
        ips = fixed_ips
        try:
            vip = client.PublicIPAddresses.get(resource_id=vip_id)
        except hnv_exception.NotFound:
            return
        if vip.ip_configuration:
            # if we get here, it means that neutron has already
            # dissassociated this IP address from its ports and
            # has issued a delete. We may be out of sync. Disassociate
            # IP and delete
            args = {
                'floating_ip_id': vip_id,
            }
            if ips:
                args["floating_ip_address"] = ips[0]["ip_address"]
            self._disassociate_public_ip(args)
        vip.remove(resource_id=vip.resource_id)

    def _delete(self, port):
        vip_id = self._get_vip_id(port)
        self._delete_by_id(vip_id)

    def _get_vip(self, vip_id, vip=None):
        ip = client.PublicIPAddresses.get(resource_id=vip_id)
        if vip and ip.ip_address != vip:
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
        vip_obj = self._get_vip(vip_id, vip_address)
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
        return net_adapter.commit(wait=True)

    def _disassociate_public_ip(self, assoc_data):
        vip_address = assoc_data.get("floating_ip_address")
        vip_id = assoc_data["floating_ip_id"]
        vip_obj = self._get_vip(vip_id, vip_address)
        if not vip_obj.ip_configuration:
            return

        ip = vip_obj.ip_configuration.get_resource()
        net_iface = client.NetworkInterfaces.get(resource_id=ip.parent_id)
        for idx, i in enumerate(net_iface.ip_configurations):
            if net_iface.ip_configurations[idx].resource_id == ip.resource_id:
                resource = vip_obj.ip_configuration
                pub_ip = net_iface.ip_configurations[idx].public_ip_address
                if pub_ip:
                    net_iface.ip_configurations[idx].public_ip_address = None
                break
        net_iface.commit(wait=True)

    def get_vip_for_internal_port(self, port, ip):
        port_id = port["id"]
        filters = {
            'fixed_port_id': [port_id],
            'fixed_ip_address': [ip]
        }
        floating_ip = self.get_floatingips(self._admin_context, filters=filters)
        if len(floating_ip) == 0:
            return None
        vip = client.PublicIPAddresses.get(resource_id=floating_ip[0]["id"])
        resource = client.Resource(resource_ref=vip.resource_ref)
        return resource

    @classmethod
    def get_all(self):
        vips = client.PublicIPAddresses.get()
        ret = {}
        for i in vips:
            if not i.tags or i.tags.get("provider") != constants.HNV_PROVIDER_NAME:
                continue
            ret[i.resource_id] = i
        return ret

    @classmethod
    def update_vip_association(cls, assoc_data):
        obj = cls()
        dip = assoc_data["fixed_ip_address"]
        net_adapter_id = assoc_data["fixed_port_id"]
        if dip and net_adapter_id:
            return obj._associate_public_ip(assoc_data)
        return obj._disassociate_public_ip(assoc_data)

    @classmethod
    def bulk_create(cls, ports):
        obj = cls()
        for port in ports:
            obj._create(port)

    @classmethod
    def create(cls, port):
        obj = cls()
        return obj._create(port)

    @classmethod
    def remove(cls, port):
        obj = cls()
        return obj._delete(port)

    @classmethod
    def bulk_remove_by_id(cls, ports):
        obj = cls()
        for i in ports:
            obj._delete_by_id(i)


class HNVL3RouterPlugin(service_base.ServicePluginBase,
                        HNVMixin):

    supported_extension_aliases = [
            'router',
            'extraroute']

    def __init__(self):
        LOG.info(_LI("Starting HNVL3RouterPlugin"))
        super(HNVL3RouterPlugin, self).__init__()
        self._public_ip = PublicIPAddressManager()
        self._lb = LoadBalancerManager()
        self.subscribe()

    def subscribe(self):
        # Removing a router gateway will delete the coresponding load balancer
        # which in turn will cascade and remove the load balancer from all interfaces
        # that had it configured
        registry.subscribe(self.process_floating_ip_update,
                           resources.FLOATING_IP,
                           events.AFTER_UPDATE)

    def process_floating_ip_update(self, resource, event, trigger, **kwargs):
        LOG.debug("FLOATING DATA: %r >>>> %r >>>> %r >>>> %r" % (resource, event, trigger, kwargs))
        self._public_ip.update_vip_association(kwargs)

    def get_plugin_type(self):
        return n_const.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("L3 Router Service Plugin for basic L3 forwarding"
                " using HNV") 

    def _get_ip_configurations_for_subnet(self, interface_info):
        ret = []
        net_id = interface_info["network_id"]
        subnet_ids = interface_info.get("subnet_ids", [])
        for i in subnet_ids:
            nc_subnet = client.SubNetworks.get(parent_id=net_id, resource_id=i)
            if nc_subnet.ip_configuration:
                for ip_conf in nc_subnet.ip_configuration:
                    ret.append(ip_conf)
        return ret

    def _apply_lb_on_connected_networks(self, router_interfaces, lb):
        subnets = []
        for i in router_interfaces:
            info = self._get_subnet_info_from_interface(i)
            for j in info:
                if j in subnets:
                    continue
                subnets.append(j)
        net_ifaces = self._get_connected_interfaces(subnets)
        be_resource = client.Resource(
                resource_ref=lb.backend_address_pools[0].resource_ref)
        for i in net_ifaces:
            iface = net_ifaces[i]["iface"]
            for idx, ip in enumerate(iface.ip_configurations):
                if ip.resource_id in net_ifaces[i]["ip_configs"]:
                    iface.ip_configurations[idx].backend_address_pools.append(be_resource)
            iface.commit(wait=True)

    #def _clear_lb_from_connected_networks(self, router_interfaces, lb):
    #    subnets = []
    #    for i in router_interfaces:
    #        info = self._get_subnet_info_from_interface(i)
    #        for j in info:
    #            if j in subnets:
    #                continue
    #            subnets.append(j)
    #    net_ifaces = self._get_connected_interfaces(subnets)
    #    be_resource = lb.backend_address_pools[0].resource_ref
    #    for i in net_ifaces:
    #        iface = net_ifaces[i]["iface"]
    #        for idx, ip in enumerate(iface.ip_configurations):
    #            if ip.resource_id in net_ifaces[i]["ip_configs"]:
    #                new_be = []
    #                for backend in iface.ip_configurations[idx].backend_address_pools:
    #                    if backend.resource_ref == be_resource:
    #                        continue
    #                    new_be.append(backend)
    #                iface.ip_configurations[idx].backend_address_pools = new_be
    #        iface.commit(wait=True)

    def update_router(self, context, id, router):
        original_router = self.get_router(context, id)
        lb = None
        original_gw = original_router.get("gw_port_id")
        if original_gw:
            lb = self._get_lb_for_router(original_router)

        updated = super(HNVL3RouterPlugin, self).update_router(context, id, router)
        external_port = updated.get("gw_port_id")
        if external_port == original_gw:
            return updated
        router_id = updated["id"]
        if external_port:
            router_interfaces = self._get_attached_router_interfaces(context, router_id)
            lb = self._get_lb_for_router(updated)
            self._apply_lb_on_connected_networks(router_interfaces, lb)
        return updated

    def add_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(HNVL3RouterPlugin, self).add_router_interface(
                context, router_id, interface_info)

        ip_configs = self._get_ip_configurations_for_subnet(router_interface_info)
        if len(ip_configs) == 0:
            LOG.debug("No IP configurations found for any "
                "of the subnets configured on %s" % router_interface_info["network_id"])

        lb = self._get_lb_for_router_by_id(router_id)
        if not lb:
            return
        for cfg in ip_configs:
            # for some reason, the IPConfiguration resource does not allow
            # PUT operations. We have to get the NetworkInterface object
            # and update that.
            ip = cfg.get_resource()
            net_iface = client.NetworkInterfaces.get(resource_id=ip.parent_id)
            for idx, i in enumerate(net_iface.ip_configurations):
                if net_iface.ip_configurations[idx].resource_id == ip.resource_id:
                    resource = client.Resource(
                        resource_ref=lb.backend_address_pools[0].resource_ref)
                    net_iface.ip_configurations[idx].backend_address_pools.append(resource)
                    break
            net_iface.commit(wait=False)
        return router_interface_info

    def remove_router_interface(self, context, router_id, interface_info):
        router_interface_info = \
            super(HNVL3RouterPlugin, self).remove_router_interface(
                context, router_id, interface_info)

        ip_configs = self._get_ip_configurations_for_subnet(router_interface_info)
        if len(ip_configs) == 0:
            LOG.debug("No IP configurations found for any "
                "of the subnets configured on %s" % router_interface_info["network_id"])

        lb = self._get_lb_for_router_by_id(router_id)
        if not lb:
            return
        for cfg in ip_configs:
            # for some reason, the IPConfiguration resource does not allow
            # PUT operations. We have to get the NetworkInterface object
            # and update that.
            ip = cfg.get_resource()
            net_iface = client.NetworkInterfaces.get(resource_id=ip.parent_id)
            for idx, i in enumerate(net_iface.ip_configurations):
                if net_iface.ip_configurations[idx].resource_id == ip.resource_id:
                    resource = client.Resource(
                        resource_ref=lb.backend_address_pools[0].resource_ref)
                    backend_pool = net_iface.ip_configurations[idx].backend_address_pools
                    ids = [i.resource_ref for i in backend_pool] 
                    new = []
                    for backend in backend_pool:
                        if resource.resource_ref in ids:
                            continue
                        new.append(backend)
                    net_iface.ip_configurations[idx].backend_address_pools = new
                    break
            LOG.debug("NET_IFACE: %r" % net_iface.dump())
            net_iface.commit(wait=False)
        return router_interface_info

