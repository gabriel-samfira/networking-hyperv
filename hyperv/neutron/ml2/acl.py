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

import netaddr

# from oslo_config import cfg
from neutron import context as n_context
from neutron.callbacks import events
from hnv_client import client
from requests.status_codes import codes
from hyperv.common.utils import retry_on_http_error

from hyperv.neutron import exception as hyperv_exc

# CONF = cfg.CONF

ACL_PROP_MAP = {
    'direction': {'ingress': "Inbound",
                  'egress': "Outbound"},
    'protocol': {'tcp': "TCP",
                 'udp': "UDP",
                 'all': "All"},
    'action': {'allow': "Allow",
               'deny': "Deny"},
    'default': "*",
    'address_default': {'IPv4': '0.0.0.0/0', 'IPv6': '::/0'}
}

DEFAULT_RULE_PRIORITY=100
_PROVIDER_NAME = "openstack"

class HNVAclDriver(object):

    def __init__(self, driver):
        self._plugin = driver._plugin
        self._driver = driver
        self.admin_context = n_context.get_admin_context()
        self._nc_ports = {}
        # self._neutron_rules = neutron_rules
        # self._nc_rules = nc_rules
        # self._security_groups = {}

    def _remove_acl(self, acl_id):
        client.AccessControlLists.remove(resource_id=acl_id)

    def _remove_acls(self, acl_list):
        if type(acl_list) is not list:
            acl_list = [acl_list,]
        for i in acl_list:
            self._remove_acl(i)

    def _create_acls_and_rules(self, sgs):
        for i in sgs:
            LOG.debug("Creating new ACL %(security_group)s on NC" % {
                'security_group': i})
            rules = self._process_rules(sgs[i])
            acl = client.AccessControlLists(
                resource_id=i,
                inbound_action="Deny",
                outbound_action="Deny",
                tags={"provider": _PROVIDER_NAME},
                acl_rules=rules,
                ).commit(wait=True)

    @retry_on_http_error(code=codes.precondition_failed)
    def _apply_nc_acl_rules(self, acl, rules):
        # refresh ACL. Allows us to handle situations where the resource
        # has changed between the time we fetched it and the commit
        acl = client.AccessControlLists.get(resource_id=acl.resource_id)
        acl.acl_rules = rules
        acl.commit()

    def _sync_existing_sgs(self, db_sgs, nc_acls):
        for sg in db_sgs:
            LOG.debug("Syncing security group %(security_group)s" % {
                'security_group': sg})
            rules = self._process_rules(db_sgs[sg])
            self._apply_nc_acl_rules(nc_acls[sg], rules)

    def sync_acls(self):
        nc_acls = client.AccessControlLists.get()
        nc_acl_list = {}
        db_sg_list = {}
        for i in nc_acls:
            if i.tags and i.tags.get("provider") != _PROVIDER_NAME:
                # ignore ACL not added by us
                continue
            if nc_acl_list.get(i.resource_id) is None:
                nc_acl_list[i.resource_id] = i

        db_security_groups = self._plugin.get_security_groups(
            self.admin_context)
        for i in db_security_groups:
            if db_sg_list.get(i["id"]) is None:
                db_sg_list[i["id"]] = i["rules"]

        nc_rule_set = set(nc_acl_list.keys())
        db_rule_set = set(db_sg_list.keys())

        must_remove = list(nc_rule_set - db_rule_set)
        must_add = list(db_rule_set - nc_rule_set)
        sync = list(db_rule_set & nc_rule_set)

        new_secgroups = {k: db_sg_list[k] for k in must_add}
        sync_db_rules = {k: db_sg_list[k] for k in sync}
        sync_nc_rules = {k: nc_acl_list[k] for k in sync}
        self._remove_acls(must_remove)
        # sync existing security groups first. This will allow rules
        # with remote_group_ids to pick up all members of that security group
        self._sync_existing_sgs(sync_db_rules, sync_nc_rules)
        # add new acls
        self._create_acls_and_rules(new_secgroups)

    def process_sg_notification(self, event, **kwargs):
        sg = kwargs.get('security_group')
        if event == events.AFTER_CREATE:
            acl = client.AccessControlLists(
                resource_id=sg['id'],
                inbound_action="Deny",
                outbound_action="Deny",
                tags={"provider": _PROVIDER_NAME}).commit(wait=True)
        elif event == events.BEFORE_DELETE:
            try:
                acl = client.AccessControlLists.get(
                    resource_id=sg['id'])
            except hyperv_exc.NotFound:
                return
            acl.remove(resource_id=acl.resource_id, wait=True)
        return

    def process_sg_rule_notification(self, event, **kwargs):
        options = {}
        if event == events.AFTER_CREATE:
            options["sg_rule"] = kwargs.get('security_group_rule')
            options["sg_id"] = options["sg_rule"]['security_group_id']
            return self._create_acl_rule(**options)
        elif event == events.BEFORE_DELETE:
            options["sg_rule"] = self._plugin.get_security_group_rule(
                self.admin_context, kwargs.get('security_group_rule_id'))
            options["sg_id"] = options["sg_rule"]['security_group_id']
            return self._delete_acl_rule(**options)

    def _create_acl_rule(self, sg_rule, sg_id):
        acl_list = self._process_rules(sg_rule)
        rules = acl_list.get(sg_id, [])
        for acl in rules:
            acl.commit(wait=True)

    def _delete_acl_rule(self, sg_rule, sg_id):
        try:
            acl = client.ACLRules.get(
                parent_id=sg_id, resource_id=sg_rule["id"])
        except hyperv_exc.NotFound:
            return
        client.ACLRules.remove(
            resource_id=sg_rule["id"], parent_id=sg_id, wait=True)

    def _get_ip_configs(self):
        ip_configs = {}
        ports = client.NetworkInterfaces.get()
        for port in ports:
            for ip in port.ip_configurations:
                ref = ip.get("resourceRef")
                ip_configs[ref] = ip
        return ip_configs

    def _get_ip_from_cache(self, ref, ip_config_cache):
        ip = ip_config_cache.get(ref, False)
        if not ip:
            # refresh cache
            ip_config_cache = self._get_ip_configs()
        return (ip_config_cache.get(ref), ip_config_cache)

    def _get_sg_members(self, sg_id, ip_config_cache):
        ips = []
        try:
            sg = client.AccessControlLists.get(resource_id=sg_id)
        except hyperv_exc.NotFound:
            return ips

        if sg.ip_configuration:
            for i in sg.ip_configuration:
                ref = i.get("resourceRef")
                ip_config, ip_config_cache = self._get_ip_from_cache(
                    ref, ip_config_cache)
                if not ip_config:
                    continue
                ips.append(ip_config.private_ip_address)
        return ips

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

    def _get_acl_rule(self, rule, priority=DEFAULT_RULE_PRIORITY):
        direction = ACL_PROP_MAP["direction"][rule["direction"]]
        protocol = self._sanitize_protocol(rule["protocol"])
        if protocol is None:
            LOG.debug("Protocol %(protocol)s is not supported" % {
                'protocol': rule["protocol"]})
            return None
        description = rule["description"]

        if direction == ACL_PROP_MAP["direction"]["egress"]:
            destination_prefix = rule["remote_ip_prefix"]
            source_prefix = ACL_PROP_MAP["default"]
            destination_port_range = self._sanitize_port(rule)
            source_port_range = ACL_PROP_MAP["default"]
        else:
            destination_prefix = ACL_PROP_MAP["default"]
            source_prefix = rule["remote_ip_prefix"]
            destination_port_range = ACL_PROP_MAP["default"]
            source_port_range = self._sanitize_port(rule)

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

    def _get_member_rules(self, rule, members):
        rules = []
        for i in members:
            version = netaddr.IPAddress(i).version
            tmp_rule = rule.copy()
            tmp_rule["id"] = "%s_%s" % (tmp_rule["id"], i)
            tmp_rule["remote_ip_prefix"] = "%s/%s" % (i, i.netmask_bits())
            rule = self._get_acl_rule(tmp_rule)
            if rule is None:
                continue
            rules.append(rule)

    def _process_rules(self, rules):
        sec_groups = {}
        if type(rules) is not list:
            rules = [rules,]
        for i in rules:
            sg_id = i["security_group_id"]
            tmp_rules = []
            if sec_groups.get(sg_id) is None:
                sec_groups[sg_id] = []
            remote_group = i.get("remote_group_id", None)
            if remote_group:
                member_ips, self._nc_ports = self._get_sg_members(
                    remote_group, self._nc_ports)
            if len(member_ips):
                tmp_rules = self._get_member_rules(i, member_ips)
            else:
                rule = self._get_acl_rule(i)
                if rule:
                    tmp_rules.append(rule)
            for j in tmp_rules:
                sec_groups[sg_id].append(j)
        return sec_groups

