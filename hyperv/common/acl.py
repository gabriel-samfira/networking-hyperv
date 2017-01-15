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

from neutron import context as n_context

from hnv_client import client

CONF = cfg.CONF

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

class AclRuleConverter(object):

	def __init__(self, neutron_rules, nc_rules=None):
		self._neutron_rules = neutron_rules
		self._nc_rules = nc_rules
		self._security_groups = {}

	def _get_sg_members(self, grpid):
		pass

	def _sanitize_protocol(self, protocol):
		if protocol in ("icmp", "ipv6-icmp", "icmpv6"):
			return None
		if protocol is None:
			return ACL_PROP_MAP["protocol"]["all"]
		return ACL_PROP_MAP["protocol"][protocol]

	def _sanitize_port(self, rule):
		port = None
		port_range_max = rule["port_range_max"]
		port_range_min = rule["port_range_min"]
		if port_range_min == port_range_max:
			port = port_range_max
		else:
			port = "%s-%s" % (
				int(port_range_min),
				int(port_range_max))
		return (port if port else "*")


	def _get_acl_rule(self, rule, priority):
		direction = ACL_PROP_MAP["direction"][rule["direction"]]
		protocol = self._get_protocol(rule["protocol"])
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
		#security_group_id = rule["security_group_id"]
		rule_id = rule["id"]
		rule = client.ACLRules(
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

	def _process_rules(self, rules):
		sec_groups = {}

		for i in rules:
			sg_id = i["security_group_id"]
			if sec_groups.get(sg_id) is None:
				sec_groups[sg_id] = i

		for acl in sec_groups.keys():
			if not self._security_groups[acl]:
				self._security_groups[acl] = {}
			existing = self._get_access_control_list(acl)
			for rule in existing.acl_rules:
				self._security_groups[acl].append(client.ACLRules.from_raw_data(rule))



class Acl(object):

	# Tenant ACL rule priority starts at 100
	_SG_PRIORITY_START=100

	def __init__(self, plugin, port_details=None):
		self._port = port_details
		self._acl_client = client.AccessControlLists()
		self._plugin = plugin
		self._admin_context = n_context.get_admin_context()

	def fetch_security_group_from_neutron(self, sec_group_id):
		return self._plugin.get_security_group(self._admin_context, sec_group_id)

	def fetch_security_groups(self):
		pass

