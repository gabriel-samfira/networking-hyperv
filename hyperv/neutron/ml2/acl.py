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
import netaddr
import hashlib

# from oslo_config import cfg
from neutron import context as n_context
from neutron.callbacks import events
from hnv import client
from requests.status_codes import codes
from hyperv.common.utils import retry_on_http_error
from oslo_log import log
from hyperv.neutron import constants
from neutron_lib import constants as const

from hnv.common import exception as hnv_exception

ACL_PROP_MAP = {
    'direction': {'ingress': "Inbound",
                  'egress': "Outbound"},
    'protocol': {'tcp': "TCP",
                 'udp': "UDP",
                 'all': "All"},
    'action': {'allow': "Allow",
               'deny': "Deny"},
    'default': "*",
    'ethertype': {4: "IPv4", 6: "IPv6"},
    'address_default': {'IPv4': '0.0.0.0/0', 'IPv6': '::/0'}
}

LOG = log.getLogger(__name__)

DEFAULT_RULE_PRIORITY=100

class HNVAclDriver(object):

    def __init__(self, driver):
        self._plugin = driver._plugin
        self._driver = driver
        self.admin_context = n_context.get_admin_context()
        self._nc_ports = {}
        # this will enable resynchronization in case of
        # resources that exist in neutron but don't exist
        # in the network controller
        #TODO(gsamfira): take from config
        self._heal = True
        # self._neutron_rules = neutron_rules
        # self._nc_rules = nc_rules
        # self._security_groups = {}

    def _remove_acl(self, acl_id):
        try:
            acl = client.AccessControlLists.get(resource_id=acl_id)
        except hnv_exception.NotFound:
            return
        for i in acl.ip_configuration:
            ip_conf = i.get_resource()
            net_iface = client.NetworkInterfaces.get(resource_id=ip_conf.parent_id)
            for idx, ip_conf in enumerate(net_iface.ip_configurations):
                if acl.resource_ref == ip_conf.access_controll_list.resource_ref:
                    net_iface.ip_configurations[idx].access_controll_list = None
            net_iface.commit(wait=True)
        client.AccessControlLists.remove(resource_id=acl_id)

    def _remove_acls(self, acl_list):
        if type(acl_list) is not list:
            acl_list = [acl_list,]
        for i in acl_list:
            self._remove_acl(i)

    def _get_drop_all_rules(self):
        rules = []
        drop_incomming = client.ACLRules(
            resource_id="DropAllIncomming",
            protocol="All",
            rule_type="Inbound",
            source_port_range="*",
            source_prefix="*",
            destination_port_range="*",
            destination_prefix="*",
            action=ACL_PROP_MAP["action"]["deny"],
            description="Drop all incoming traffic by default",
            priority=65000)
        drop_outgoing = client.ACLRules(
            resource_id="DropAllOutgoing",
            protocol="All",
            rule_type="Outbound",
            source_port_range="*",
            source_prefix="*",
            destination_port_range="*",
            destination_prefix="*",
            action=ACL_PROP_MAP["action"]["deny"],
            description="Drop all outgoing traffic by default",
            priority=64999)
        return [drop_incomming, drop_outgoing]

    def _create_acls_and_rules(self, sgs):
        # NOTE(gsamfira): Fri Jan 20 16:15:20 EET 2017
        # At the time of this writing the network controller
        # that installs with the stable version of Windows Server 2016
        # does not expose the inboundDefaultAction and outboundDefaultAction
        # for ACLs. Adding default rules to drop all traffic, with the highest
        # priority value that is user definable, to mimic DROP ALL policy.
        for i in sgs:
            default_rules = self._get_drop_all_rules()
            processed_rules = self._process_rules(sgs[i])
            default_rules.extend(processed_rules[i]["rules"])
            acl = client.AccessControlLists(
                resource_id=i,
                inbound_action="Deny",
                outbound_action="Deny",
                tags={"provider": constants.HNV_PROVIDER_NAME},
                acl_rules=default_rules,
                )
            LOG.debug("Creating new ACL %(security_group)s on NC "
                    "with payload %(payload)s" % {
                'security_group': i,
                'payload': acl.dump()})
            acl.commit(wait=True)

    def _apply_nc_acl_rules(self, acl, rules):
        # we are syncing and we want to overwrite any existing rule.
        if isinstance(acl, client.AccessControlLists) is False:
            return
        default_rules = self._get_drop_all_rules()
        rules.extend(default_rules)
        try:
            acl.refresh()
        except hnv_exception.NotFound:
            # resource dissapeared while updating
            return
        acl.acl_rules = rules
        acl.commit(wait=True, if_match=False)

    def _sync_existing_sgs(self, db_sgs, nc_acls):
        for sg in db_sgs:
            LOG.debug("Syncing security group %(security_group)s" % {
                'security_group': sg})
            rules = self._process_rules(db_sgs[sg])
            self._apply_nc_acl_rules(nc_acls[sg], rules[sg]["rules"])

    def _get_nc_acls(self, ids=None):
        # TODO(gsamfira): Cache this value
        nc_acls = []
        # TODO: arbitrary number. Should turn into constant
        if ids and len(ids) < 3:
            for i in ids:
                nc_acls.append(client.AccessControlLists.get(resource_id=i))
        else:
            nc_acls = client.AccessControlLists.get()
        nc_acl_list = {}
        for i in nc_acls:
            if not i.tags or i.tags.get("provider") != constants.HNV_PROVIDER_NAME:
                # ignore ACL not added by us
                continue
            if ids and i.resource_id not in ids:
                continue
            if nc_acl_list.get(i.resource_id) is None:
                nc_acl_list[i.resource_id] = i
        return nc_acl_list

    def _get_aggregate_id(self, sg_ids):
        if type(sg_ids) is not list:
            sg_ids = [sg_ids,]
        sg_ids.sort()
        joined = "".join(sg_ids)
        return hashlib.md5(joined).hexdigest()

    def _get_port_acl(self, port):
        sg_ids = port.get("security_groups", [])
        if len(sg_ids) == 0:
            return None
        elif len(sg_ids) == 1:
            acl = client.AccessControlLists(resource_id=sg_ids[0])
            return client.Resource(resource_ref=acl.resource_ref)
        aggregate_id = self._get_aggregate_id(sg_ids)
        acls = client.AccessControlLists(resource_id=aggregate_id)
        return client.Resource(resource_ref=acls.resource_ref)

    def _get_sg_ids_from_ports(self, ports):
        if type(ports) is not dict:
            raise ValueError("Expected dict")
        all_sgs = set()
        for i in ports:
            sgs = set(ports[i].get("security_groups", []))
            all_sgs.update(sgs)
        as_list = list(all_sgs)
        if len(as_list) == 0:
            return None
        return as_list

    def _get_db_acls(self, ids=None):
        db_sg_list = {}
        filters = {}
        if ids:
            filters["id"] = ids
        db_security_groups = self._plugin.get_security_groups(
            self.admin_context,
            filters=filters)
        for i in db_security_groups:
            if db_sg_list.get(i["id"]) is None:
                db_sg_list[i["id"]] = i["security_group_rules"]
        return db_sg_list

    def _get_aggregate_db_acls(self, db_acls, ports=None, ignore_sgs=None):
        ignore_sgs = ignore_sgs or []
        ignore = set(ignore_sgs)
        if not ports:
            tmp = self._driver._get_db_ports()
            ports = tmp["compute"]
        ret = {}
        for i in ports:
            sgs = set(ports[i].get("security_groups", []))
            sgs = list(sgs - ignore)
            if len(sgs) < 2:
                continue
            aggregate_id = self._get_aggregate_id(sgs)
            if ret.get(aggregate_id):
                continue
            all_rules = []
            for sg in sgs:
                all_rules.extend(db_acls.get(sg, []))
            tmp = []
            for i in all_rules:
                cp = i.copy()
                cp["security_group_id"] = aggregate_id
                tmp.append(cp)
            ret[aggregate_id] = tmp
        return ret

    def sync_acls(self, ports=None, departing_sgs=None):
    #    ids = None
    #    if ports is not None:
    #        ids = self._get_sg_ids_from_ports(ports)
    #        if ids is None:
    #            # Nothing to sync (hopefully)
    #            return
        nc_acls = self._get_nc_acls() #(ids=ids)
        db_acls = self._get_db_acls() #(ids=ids)
        # ACLs that need to be created in the network controller comprised
        # of the rules from multiple security groups set on a port. It's an
        # unfortunate limitation of HNV, that you are not allowed to add a
        # list of ACLs on a given port. 
        ag_db_acls = self._get_aggregate_db_acls(
                db_acls, ports=ports, ignore_sgs=departing_sgs)
        db_acls.update(ag_db_acls)
        nc_rule_set = set(nc_acls.keys())
        db_rule_set = set(db_acls.keys())
        #db_rule_set.update(set(ag_db_acls.keys()))

        must_remove = list(nc_rule_set - db_rule_set)
        must_add = list(db_rule_set - nc_rule_set)
        sync = list(db_rule_set & nc_rule_set)
        
        new_secgroups = {k: db_acls[k] for k in must_add}
        sync_db_rules = {k: db_acls[k] for k in sync}
        sync_nc_rules = {k: nc_acls[k] for k in sync}
        # sync existing security groups first. This will allow rules
        # with remote_group_ids to pick up all members of that security group
        self._sync_existing_sgs(sync_db_rules, sync_nc_rules)
        # add new acls
        self._create_acls_and_rules(new_secgroups)
        return must_remove
        #self._remove_acls(must_remove)

    def process_sg_notification(self, event, **kwargs):
        LOG.debug("Processing security group notification for %(sec_group)s" % {
            'sec_group': kwargs.get('security_group'),
            })
        sg = kwargs.get('security_group')
        if event == events.AFTER_CREATE:
            acl = client.AccessControlLists(
                resource_id=sg['id'],
                inbound_action="Deny",
                outbound_action="Deny",
                tags={"provider": constants.HNV_PROVIDER_NAME}).commit(wait=True)
        elif event == events.BEFORE_DELETE:
            ports = self._get_ports_with_secgroups([sg['id'],])
            try:
                acl = client.AccessControlLists.get(
                    resource_id=sg['id'])
            except hnv_exception.NotFound:
                return
            acl.remove(resource_id=acl.resource_id, wait=True)
            # only really relevant on delete. When adding a new SG,
            # it's not yet assigned to any VM
            #if len(ports):
            LOG.debug("Sync-ing ACLS for SGS belonging to %r" % ports)
            self.sync_acls(ports=ports, departing_sgs=[sg["id"],])
        return

    def _get_ports_with_secgroups(self, sg_ids):
        if type(sg_ids) is not list:
            sg_ids = [sg_ids,]
        p_binding = self._plugin._get_port_security_group_bindings(
                self.admin_context, filters = {
                    'security_group_id': sg_ids},
                fields=["port_id"])
        if len(p_binding) == 0:
            return {}
        port_ids = [i["port_id"] for i in p_binding]
        ports = []
        for i in port_ids:
            p = self._plugin.get_port(self.admin_context, i)
            if p.get("device_owner", "").startswith(const.DEVICE_OWNER_COMPUTE_PREFIX):
                ports.append(p)
        #ports = self._plugin.get_ports(self.admin_context, filters={
        #    "id": [port_ids,]})
        return {i["id"]:i for i in ports}

    def process_sg_rule_notification(self, event, **kwargs):
        LOG.debug("Processing security group rule notification for %(sec_group)s" % {
            'sec_group': kwargs.get('security_group_rule_id'),
            })
        options = {}
        sg_id = None
        if event == events.AFTER_CREATE:
            options["sg_rule"] = kwargs.get('security_group_rule')
            options["sg_id"] = options["sg_rule"]['security_group_id']
            sg_id = options["sg_id"]
        elif event == events.AFTER_DELETE:
            sg_id = kwargs["security_group_id"]
        ports = self._get_ports_with_secgroups([sg_id,]) 
        to_remove = self.sync_acls(ports=ports)
        self._remove_acls(to_remove)

    def _create_acl_rule(self, sg_rule, sg_id):
        try:
            existing_rules = client.AccessControlLists.get(
                resource_id=sg_id)
        except hnv_exception.NotFound:
            LOG.warning("Failed to find ACL with ID %(sgid)s"
            "network controller may be out of sync" % {
            'sgid': sg_id})
            if self._heal:
                LOG.warning("Attempting resync of ACLs")
                self.sync_acls()
        acl_list = self._process_rules(sg_rule)
        rules = acl_list.get(sg_id, {"rules": []})
        should_commit = False
        for acl in rules["rules"]:
            if acl in existing_rules.acl_rules:
                continue
            existing_rules.acl_rules.append(acl)
            should_commit = True
        if should_commit:
            existing_rules.commit(wait=True)

    def _delete_acl_rule(self, sg_rule, sg_id):
        remote_group = sg_rule.get("remote_group_id", None)
        if remote_group:
            member_ips = self._get_member_ips()
            rules = self._get_member_rules(sg_rule, member_ips.get(remote_group, []))
            self._remove_acl_rules(rules)
        else:
            rules = self._process_rules(sg_rule)
            self._remove_acl_rules(rules[sg_id]["rules"])

    # def _get_ip_configs(self):
    #     ip_configs = {}
    #     ports = client.NetworkInterfaces.get()
    #     for port in ports:
    #         for ip in port.ip_configurations:
    #             ref = ip.get("resourceRef")
    #             ip_configs[ref] = ip
    #     return ip_configs

    # def _get_ip_from_cache(self, ref, ip_config_cache):
    #     ip = ip_config_cache.get(ref, False)
    #     if not ip:
    #         # refresh cache
    #         ip_config_cache = self._get_ip_configs()
    #     return (ip_config_cache.get(ref), ip_config_cache)

    def _get_member_ips(self):
        db_ports = self._driver._get_db_ports()
        members = self._driver._get_port_member_ips(db_ports["compute"].values())
        return members

    # def _get_sg_members(self, sg_id, ip_config_cache):
    #     ips = []
    #     try:
    #         sg = client.AccessControlLists.get(resource_id=sg_id)
    #     except hnv_exception.NotFound:
    #         return (ips, ip_config_cache)

    #     if sg.ip_configuration:
    #         for i in sg.ip_configuration:
    #             ref = i.get("resourceRef")
    #             ip_config, ip_config_cache = self._get_ip_from_cache(
    #                 ref, ip_config_cache)
    #             if not ip_config:
    #                 continue
    #             ips.append(ip_config.private_ip_address)
    #     return (ips, ip_config_cache)

    def _sanitize_protocol(self, protocol):
        if protocol in ("icmp", "ipv6-icmp", "icmpv6"):
            return None
        if protocol is None:
            return ACL_PROP_MAP["protocol"]["all"]
        return ACL_PROP_MAP["protocol"][protocol]

    def _sanitize_port(self, rule):
        port = None
        port_range_max = rule.get("port_range_max")
        port_range_min = rule.get("port_range_min")
        if port_range_max is None or port_range_min is None:
            return "*"
        if port_range_min == port_range_max:
            port = port_range_max
        else:
            port = "%s-%s" % (
                int(port_range_min),
                int(port_range_max))
        return port

    def _sanitize_remote_ip_prefix(self, remote_ip, ethertype):
        if remote_ip is None:
            remote_ip = ACL_PROP_MAP["address_default"][ethertype]
        return remote_ip

    def _get_acl_rule(self, rule, priority=DEFAULT_RULE_PRIORITY):
        direction = ACL_PROP_MAP["direction"][rule["direction"]]
        protocol = self._sanitize_protocol(rule["protocol"])
        if protocol is None:
            LOG.debug("Protocol %(protocol)s is not supported" % {
                'protocol': rule["protocol"]})
            return None
        description = rule["description"]

        if direction == ACL_PROP_MAP["direction"]["egress"]:
            destination_prefix = self._sanitize_remote_ip_prefix(
                    rule["remote_ip_prefix"], rule["ethertype"])
            source_prefix = ACL_PROP_MAP["default"]
            destination_port_range = self._sanitize_port(rule)
            source_port_range = ACL_PROP_MAP["default"]
        else:
            destination_prefix = ACL_PROP_MAP["default"]
            source_prefix = self._sanitize_remote_ip_prefix(
                    rule["remote_ip_prefix"], rule["ethertype"])
            destination_port_range = self._sanitize_port(rule) #ACL_PROP_MAP["default"]
            source_port_range = ACL_PROP_MAP["default"] #self._sanitize_port(rule)

        security_group_id = rule["security_group_id"]
        rule_id = rule["id"]
        rule = client.ACLRules(
            parent_id=security_group_id,
            resource_id=rule_id,
            protocol=protocol,
            rule_type=direction,
            source_port_range=source_port_range,
            source_prefix=source_prefix,
            destination_port_range=destination_port_range,
            destination_prefix=destination_prefix,
            action=ACL_PROP_MAP["action"]["allow"],
            description=description,
            priority=priority)
        return rule

    def _get_member_rule_id(self, sg_rule_id, ip):
        return "%s_%s" % (sg_rule_id, ip)

    def _get_sgs_member_rules_for_port(self, port):
        sgs = port.get("security_groups", [])
        if len(sgs) == 0:
            return []
        ret = []
        rules = self._plugin.get_security_group_rules(
            self.admin_context,
            filters={"remote_group_id": sgs})
        member_ips = self._driver._get_port_member_ips(port)
        for i in rules:
            remote_sg = i.get("remote_group_id")
            member_rules, priority = self._get_member_rules(i, member_ips.get(remote_sg, []))
            ret.extend(member_rules)
        return ret

    def add_member_to_sgs(self, port):
        updated_sgs = set()
        rules = self._get_sgs_member_rules_for_port(port)
        for i in rules:
            updated_sgs.add(i.parent_id)
            #i.commit(wait=True)
        ports = self._get_ports_with_secgroups(list(updated_sgs))
        self.sync_acls(ports=ports)

    def _remove_acl_rules(self, rules):
        acls = {}
        updated_sgs = set()
        # You can't call remove() on a rule directly, because the HNV API,
        # for whatever reason complains about the ACL being used. You can however,
        # overwrite all the rules in an ACL by calling commit()...
        # Also, the following two for loops look wrong to me, but I ran out of coffee
        for i in rules:
            updated_sgs.add(i.parent_id)
            if i.parent_id not in acls:
                acls[i.parent_id] = {
                        "acl": client.AccessControlLists.get(resource_id=i.parent_id),
                        "rules": [i.resource_ref,]
                        }
            else:
                acls[i.parent_id]["rules"].append(i.resource_ref)
        for acl in acls:
            new = []
            for rule in acls[acl]["acl"].acl_rules:
                if rule.resource_ref in acls[acl]["rules"]:
                    continue
                new.append(rule)
            acl = client.AccessControlLists.get(resource_id=acls[acl]["acl"].resource_id)
            acl.acl_rules = new
            acl.commit(wait=True)
        ports = self._get_ports_with_secgroups(list(updated_sgs))
        self.sync_acls(ports=ports)
        return

    # this should be called when a port is removed in neutron
    def remove_member_from_sg(self, port):
        rules = self._get_sgs_member_rules_for_port(port)
        self._remove_acl_rules(rules)

    def _get_member_rules(self, rule, members, priority=DEFAULT_RULE_PRIORITY):
        rules = []
        for member in members:
            r = None
            ip = netaddr.IPAddress(member)
            tmp_rule = rule.copy()
            if tmp_rule["ethertype"] != ACL_PROP_MAP['ethertype'][ip.version]:
                continue
            tmp_rule["id"] = self._get_member_rule_id(tmp_rule["id"], member)
            tmp_rule["remote_ip_prefix"] = "%s/%s" % (member, ip.netmask_bits())
            LOG.debug("Getting ACL rule for %(remote_ip)s with protocol %(protocol)s" % {
                'remote_ip': tmp_rule["remote_ip_prefix"],
                'protocol': tmp_rule["protocol"]})
            r = self._get_acl_rule(tmp_rule, priority=priority)
            if r is None:
                continue
            priority += 1
            rules.append(r)
        return (rules, priority)

    def _process_rules(self, rules):
        sec_groups = {}
        member_ips = self._get_member_ips()
        if type(rules) is not list:
            rules = [rules,]
        for i in rules:
            sg_members = []
            sg_id = i["security_group_id"]
            tmp_rules = []
            if sec_groups.get(sg_id) is None:
                sec_groups[sg_id] = {
                        "priority": DEFAULT_RULE_PRIORITY,
                        "rules": []}
            remote_group = i.get("remote_group_id", None)
            if remote_group:
                sg_members = member_ips.get(remote_group, set())
            if remote_group and len(sg_members) > 0:
                tmp_rules, sec_groups[sg_id]["priority"] = self._get_member_rules(
                        i, list(sg_members), sec_groups[sg_id]["priority"])
            else:
                rule = self._get_acl_rule(i, sec_groups[sg_id]["priority"])
                if rule:
                    tmp_rules.append(rule)
                    sec_groups[sg_id]["priority"] += 1
            for j in tmp_rules:
                sec_groups[sg_id]["rules"].append(j)
        return sec_groups

