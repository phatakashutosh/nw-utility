# Copyright 2018 Ashutosh S. Phatak
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author - Ashutosh Phatak
# Status - Development

import logging
import json

# python wsgi (web socket) for REST API
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import WSGIApplication

# import ryu controller base
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls

# for raising exception/errors
from ryu.exception import OFPUnknownVersion

# import library for OpenFlow packet decoding
from ryu.lib import mac
from ryu.lib import dpid as dpid_lib
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.ofproto import inet

#supporting OpenFlow protocols and its parsers
from ryu.lib import ofctl_v1_3
from ryu.lib import ofctl_v1_4
from ryu.lib import ofctl_v1_5
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ofproto_v1_5
from ryu.ofproto import ofproto_v1_3_parser
from ryu.ofproto import ofproto_v1_4_parser
from ryu.ofproto import ofproto_v1_5_parser

# -- you can add this part if required -- #
#from ryu.lib import ofctl_v1_0
#from ryu.lib import ofctl_v1_2
#from ryu.ofproto import ofproto_v1_0
#from ryu.ofproto import ofproto_v1_2
#from ryu.ofproto import ofproto_v1_2_parser
# ---x---x--x--- #

# =============================
#          REST API
# =============================
#
#  Note: specify switch, as follows.
#   {switch-id} : 'all' or switchID
#

# x-- About Firewall status --x
#
# get status of all switches
# GET /network/status

# x-- Registering switches as firewall --x
#
# to register switch as firewall
# PUT /network/firewall/reg/{switchid}
#
# to remove switch from firewall functionalities
# PUT /network/firewall/unreg/{switchid}

# x-- About Firewall rules --x
#
# get rules
# GET /network/firewall/rules/{switchid}
#
# set firewall rules
# POST /network/firewall/rules/{switchid}
#
# delete firewall rules
# DELETE /firewall/rules/{switchid}
#
#
# x-- request body format for rules--x
#   {"<field1>":"<value1>", "<field2>":"<value2>",...}
#
#     <field>  : <value>
#    "priority": "0 to 65533"
#    "in_port" : "<int>"
#    "dl_src"  : "<xx:xx:xx:xx:xx:xx>"
#    "dl_dst"  : "<xx:xx:xx:xx:xx:xx>"
#    "dl_type" : "<ARP or IPv4 or IPv6>"
#    "nw_src"  : "<A.B.C.D/M>"
#    "nw_dst"  : "<A.B.C.D/M>"
#    "ipv6_src": "<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/M>"
#    "ipv6_dst": "<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/M>"
#    "nw_proto": "<TCP or UDP or ICMP or ICMPv6>"
#    "tp_src"  : "<int>"
#    "tp_dst"  : "<int>"
#    "actions" : "<ALLOW or DENY>"
#
#   Note: specifying nw_src/nw_dst
#         without specifying dl-type as "ARP" or "IPv4"
#         will automatically set dl-type as "IPv4".
#
#   Note: specifying ipv6_src/ipv6_dst
#         without specifying dl-type as "IPv6"
#         will automatically set dl-type as "IPv6".
#
#   Note: When "priority" has not been set up,
#         "0" is set to "priority".
#
#   Note: When "actions" has not been set up,
#         "ALLOW" is set to "actions".
#
#
# x-- request body format for rule_id --x
#   {"<field>":"<value>","<field>":"<value>"}
#
#     <field>  : <value>
#    "rule_id" : "<int>" or "all"
#

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'

ALL = 'all'
SWITCHID = 'switch_id'
RULE_ID = 'rule_id'
STATUS = 'status'
LOG_STATUS = 'log_status'
STATUS_ENABLE = 'enable'
STATUS_DISABLE = 'disable'
COMMAND_RESULT = 'command_result'
ACL = 'access_control_list'
RULES = 'rules'
COOKIE = 'cookie'
PRIORITY = 'priority'
MATCH = 'match'
IN_PORT = 'in_port'
SRC_MAC = 'dl_src'
DST_MAC = 'dl_dst'
DL_TYPE = 'dl_type'
DL_TYPE_ARP = 'ARP'
DL_TYPE_IPV4 = 'IPv4'
DL_TYPE_IPV6 = 'IPv6'
DL_VLAN = 'dl_vlan'
SRC_IP = 'nw_src'
DST_IP = 'nw_dst'
SRC_IPV6 = 'ipv6_src'
DST_IPV6 = 'ipv6_dst'
NW_PROTO = 'nw_proto'
NW_PROTO_TCP = 'TCP'
NW_PROTO_UDP = 'UDP'
NW_PROTO_ICMP = 'ICMP'
NW_PROTO_ICMPV6 = 'ICMPv6'
TP_SRC = 'tp_src'
TP_DST = 'tp_dst'
ACTION = 'actions'
ACTION_ALLOW = 'ALLOW'
ACTION_DENY = 'DENY'
ACTION_PACKETIN = 'PACKETIN'


STATUS_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX
ARP_FLOW_PRIORITY = ofproto_v1_3_parser.UINT16_MAX - 1
LOG_FLOW_PRIORITY = 0
ACL_FLOW_PRIORITY_MIN = LOG_FLOW_PRIORITY + 1
ACL_FLOW_PRIORITY_MAX = ofproto_v1_3_parser.UINT16_MAX - 2

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094
COOKIE_SHIFT_VLANID = 32

# x-- network utility application with REST --x

class RestAPI(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION, ofproto_v1_4.OFP_VERSION, ofproto_v1_5.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
	super(RestAPI, self).__init__(*args, **kwargs)

	# logger configure
	MainController.set_logger(self.logger)

	# data initiation
	self.dpset = kwargs['dpset']
	wsgi = kwargs['wsgi']
	self.waiters = {}
	self.data = {}
	self.data['dpset'] = self.dpset
	self.data['waiters'] = self.waiters
	wsgi.registory['MainController'] = self.data

	#REST API URI links
	mapper = wsgi.mapper
	path = '/network'
	requirements = {'switchid': SWITCHID_PATTERN}

	# Get network status
	uri = path + '/status'
	mapper.connect('network', uri, controller=MainController, action='get_status', conditions=dict(method=['GET']))

	# Register node as firewall
	uri = path + '/firewall/reg/{switchid}'
	mapper.connect('network', uri, controller=MainController, action='regist_ovs_fw', conditions=dict(method=['PUT']), requirements=requirements)

	# Unregister node as firewall
	uri = path + '/firewall/unreg/{switchid}'
	mapper.connect('network', uri, controller=MainController, action='unregist_ovs_fw', conditions=dict(method=['PUT']), requirements=requirements)

	# Firewall switch configuration
	uri = path + '/firewall/rules/{switchid}'

	# -- Get rules
	mapper.connect('network', uri, controller=MainController, action='get_rules', conditions=dict(method=['GET']), requirements=requirements)

	# -- Set rules
	mapper.connect('network', uri, controller=MainController, action='set_rule', conditions=dict(method=['POST']), requirements=requirements)

	# -- Delete rules
	mapper.connect('network', uri, controller=MainController, action='delete_rule', conditions=dict(method=['DELETE']), requirements=requirements)

	# Updating list of connected switches
    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def handler_datapath(self, ev):
	if ev.enter:
	    MainController.update_list(ev.dp, True)
	else:
	    MainController.update_list(ev.dp, False)

    # Handle OpenFlow Protocol SwitchFeatures events & assign nodes as learning switches
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
	datapath = ev.msg.datapath
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	match = parser.OFPMatch()
	actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
	mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        MainController._LOGGER.info('switch is ready for learning: %s',datapath.id)

#        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, priority=0,
#                                match=match, out_port=ofproto.OFPP_ANY,
#                                cookie=0, cookie_mask=0, buffer_id=0xffffffff)
        datapath.send_msg(mod)

    # for OpenFlow version1.3 or later
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_3(self, ev):

        msg = ev.msg
        dp = msg.datapath
	    MainController._LOGGER.info('waiters before if call %s', self.waiters)
        if dp.id not in self.waiters:
            return
        if msg.xid not in self.waiters[dp.id]:
            return
	    MainController._LOGGER.info('waiters after if call %s', self.waiters)
        lock, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        flags = 0
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION or \
                dp.ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION:
            flags = dp.ofproto.OFPSF_REPLY_MORE
        elif dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flags = dp.ofproto.OFPMPF_REPLY_MORE

        if msg.flags & flags:
            return
        del self.waiters[dp.id][msg.xid]
        lock.set()


    # handle packet_in and divert to switch/firewall module
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
	msg = ev.msg
	#datapath = msg.datapath
	dpid = msg.datapath.id
	if dpid in MainController.LIST_FW:
	    Firewall_module(msg.datapath)._pckt_in_(msg)
	else:
	    Switch_module(msg.datapath)._pckt_in_(msg)

# maintaining list of nodes connected to firewall
class ListOFnodes(dict):

    def __init__(self):
        super(ListOFnodes, self).__init__()

    def get_ofs(self, dp_id):
        if len(self) == 0:
            raise ValueError('No node assigned as Firewall.')

        dps = {}
        if dp_id == ALL:
            dps = self
        else:
            try:
                dpid = dpid_lib.str_to_dpid(dp_id)
            except:
                raise ValueError('Invalid switchID.')

            if dpid in self:
                dps = {dpid: self[dpid]}
            else:
                msg = 'firewall node is not connected. : switchID=%s' % dp_id
                raise ValueError(msg)

        return dps

# Controller module handling network utility application request
class MainController(ControllerBase):

    LIST_Nodes = {}
    LIST_FW = ListOFnodes()
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(MainController, self).__init__(req, link, data, **config)
        self.dpset = data['dpset']
        self.waiters = data['waiters']
	self.rule_num = 0

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[NW][%(levelname)s] %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    # Actions on REST requests

    # get status of connected nodes
    # GET /network/status
    def get_status(self, req, **kwargs):
	return self._get_status(ALL)

    def _get_status(self, datapath):
	msgs = []
	for dpid in self.LIST_Nodes:
	    msg = {hex(dpid).lstrip('0x') : 'switch'}
	    # hex(num).lstrip('0x') is to remove Ox of hex num from final printing
	    if dpid in self.LIST_FW:
		msg = {hex(dpid).lstrip('0x'): 'firewall'}
	    msgs.append(msg)

	body = json.dumps(msgs)
	return Response(content_type='application/json', body=body)

    # to register switch as firewall
    # PUT /network/firewall/reg/{switchid}
    def regist_ovs_fw(self, req, switchid, **_kwargs):
        return self._regist_ovs_fw(switchid)


    @staticmethod
    def _regist_ovs_fw(dp):
	try:
	    dpid = dpid_lib.str_to_dpid(dp)
	except:
	    raise ValueError('Invalid switchID')
	datapath = MainController.LIST_Nodes[dpid]
	try:
	    ovs_fw = Firewall_module(datapath)
	except OFPUnknownVersion as message:
	    MainController._LOGGER.info('dpid=%s: %s', dpid_str, message)
	    return

	MainController.LIST_FW.setdefault(dpid, ovs_fw)

	ovs_fw.flush_all(datapath)
	ovs_fw.set_arp_flow()
#	ovs_fw.set_log_enable()
	MainController._LOGGER.info('Node dpid=%s: Joined as firewall.',dp)

	msg = {'result': 'success', 'details': 'firewall running.'}
	body = json.dumps(msg)
	return Response(content_type='application/json', body=body)

	#to remove sw from firewall functionalities
	# PUT /network/firewall/unreg/{switchid}
    def unregist_ovs_fw(self, req, switchid, **_kwargs):
        return self._unregist_ovs_fw(switchid)

    @staticmethod
    def _unregist_ovs_fw(dp):
	try:
	    dpid = dpid_lib.str_to_dpid(dp)
	except:
	    raise ValueError('Invalid switchID.')
	datapath = MainController.LIST_Nodes[dpid]
        if dpid in MainController.LIST_FW:
            del MainController.LIST_FW[dpid]
	    try:
		ovs_fw = Firewall_module(datapath)
	    except OFPUnknownVersion as message:
		MainController._LOGGER.info('dpid=%s: %s', dpid_str, message)
		return
	    ovs_fw.flush_all(datapath)
	    Switch_module(datapath).add_table_miss(datapath)
	    MainController._LOGGER.info('Node dpid=%s: Removed as firewall.',dp)

	    msg = {'result': 'success', 'details': 'firewall stopped.'}

	else:
	    msg = {'result': 'failed', 'details': 'switch is not firewall.'}
	body = json.dumps(msg)
	return Response(content_type='application/json', body=body)

    # get rules
    # GET /network/firewall/rules/{switchid}

    def get_rules(self, req, switchid):
        try:
            dps = self.LIST_FW.get_ofs(switchid)
        except ValueError as message:
            return Response(status=400, body=str(message))

        msgs = []
 #       for ovs_fw in dps.values():
	datapath = self.LIST_Nodes[dpid_lib.str_to_dpid(switchid)]
        msgs = Firewall_module(datapath).get_rules(self.waiters)
	MainController._LOGGER.info('waiters at GET %s', self.waiters)
        #msgs.append(rules)

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # set firewall rules
    # POST /network/firewall/rules/{switchid}
    def set_rule(self, req, switchid, **_kwargs):

        try:
            rule = req.json if req.body else {}
        except ValueError:
            MainController._LOGGER.debug('invalid syntax %s', req.body)
            return Response(status=400)

        try:
            dps = self.LIST_FW.get_ofs(switchid)
        except ValueError as message:
            return Response(status=400, body=str(message))
	self.rule_num += 1
	rule_id = self.rule_num & ofproto_v1_3_parser.UINT32_MAX
        msgs = []
        for ovs_fw in dps.values():
            try:
                msg = ovs_fw.add_rule(rule, rule_id)
                #msgs.append(msg)
            except ValueError as message:
                return Response(status=400, body=str(message))
	msgs.append(msg)
        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)

    # delete firewall rules
    # DELETE /firewall/rules/{switchid}
    def delete_rule(self, req, switchid, **_kwargs):
	try:
	    ruleid = req.json if req.body else {}
	except ValueError:
	    MainController._LOGGER.debug('invalid syntax %s', req.body)
	    return Response(status=400)

	try:
	    dps = self.LIST_FW.get_ofs(switchid)

	except ValueError as message:
	    return Response(status=400, body=str(message))

	msgs = []
	for ovs_fw in dps.values():
	    try:
		msg = ovs_fw.remove_rule(ruleid, self.waiters)
		msgs.append(msg)
	    except ValueError as message:
		return Response(status=400, body=str(message))

        body = json.dumps(msgs)
        return Response(content_type='application/json', body=body)


    # make list of connected nodes
    @staticmethod
    def update_list(dp, add):
	dpid_str = dpid_lib.dpid_to_str(dp.id)
        if add:
	    MainController.LIST_Nodes[dp.id] = dp
	    MainController._LOGGER.info('Node dpid=%s has joined',dpid_str)
 #      MainController.regist_ofs(ev.dp)
        else:
	    del MainController.LIST_Nodes[dp.id]
	    if ev.dp.id in self.LIST_FW:
		del self.LIST_FW[dp.id]
	    MainController._LOGGER.info('Node dpid=%s has left.',dpid_str)
 #      MainController.unregist_ofs(ev.dp)

# firewall module for implementing security policies
 class Firewall_module(object):

    _OFCTL = {ofproto_v1_3.OFP_VERSION: ofctl_v1_3,
              ofproto_v1_4.OFP_VERSION: ofctl_v1_4,
              ofproto_v1_5.OFP_VERSION: ofctl_v1_5}

    def __init__(self, dp):
        super(Firewall_module, self).__init__()

        self.dp = dp
        version = dp.ofproto.OFP_VERSION

        if version not in self._OFCTL:
            raise OFPUnknownVersion(version=version)

        self.ofctl = self._OFCTL[version]

    # REST command template
    def rest_command(func):
        def _rest_command(*args, **kwargs):
            key, value = func(*args, **kwargs)
            switch_id = dpid_lib.dpid_to_str(args[0].dp.id)
            return {SWITCHID: switch_id,
                    key: value}
	return _rest_command

	# get rules
    @rest_command
    def get_rules(self, waiters):
        rules = {}
        msgs = self.ofctl.get_flow_stats(self.dp, waiters)

        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                priority = flow_stat[PRIORITY]
                if (priority != STATUS_FLOW_PRIORITY
                        and priority != ARP_FLOW_PRIORITY
                        and priority != LOG_FLOW_PRIORITY):
                    rule = self._to_rest_rule(flow_stat)
                    #rules.setdefault(vid, [])
                    rules.append(rule)

        get_data = []
        for rule in rules.items():
            rule_data = {REST_RULES: rule}
            get_data.append(vid_data)
        return ACL, get_data

    #add new rule
    @rest_command
    def add_rule(self, rule, cookie):
	#get priotiy to rule
	priority = int(rule.get(PRIORITY, ACL_FLOW_PRIORITY_MIN))

        if (priority < ACL_FLOW_PRIORITY_MIN
                or ACL_FLOW_PRIORITY_MAX < priority):
            raise ValueError('Invalid priority value. Set [%d-%d]'
                             % (ACL_FLOW_PRIORITY_MIN, ACL_FLOW_PRIORITY_MAX))

        match = Match.to_openflow(rule)
        actions = Action.to_openflow(rule)
        flow = self._to_of_flow(cookie=cookie, priority=priority, match=match, actions=actions)
	msgs = []
        cmd = self.dp.ofproto.OFPFC_ADD
        try:
            self.ofctl.mod_flow_entry(self.dp, flow, cmd)
        except:
            raise ValueError('Invalid rule parameter.')

        rule_id = Firewall_module._cookie_to_ruleid(cookie)
        msg = {'result': 'success', 'details': 'Rule added. : rule_id=%d' % rule_id}
	msgs.append(msg)
        return COMMAND_RESULT, msgs

    #delete existing rule(s)
    @rest_command
    def remove_rule(self, ruleid, waiters):
        try:
            if ruleid[RULE_ID] == ALL:
                rule_id = ALL
            else:
                rule_id = int(ruleid[RULE_ID])
        except:
            raise ValueError('Invalid ruleID.')

        delete_list = []

        msgs = self.ofctl.get_flow_stats(self.dp, waiters)
        if str(self.dp.id) in msgs:
            flow_stats = msgs[str(self.dp.id)]
            for flow_stat in flow_stats:
                cookie = flow_stat[COOKIE]
                ruleid = Firewall_module._cookie_to_ruleid(cookie)
                priority = flow_stat[PRIORITY]

                if (priority != STATUS_FLOW_PRIORITY
                        and priority != ARP_FLOW_PRIORITY
                        and priority != LOG_FLOW_PRIORITY):
                    if ((rule_id == ALL or rule_id == ruleid)):
                        match = Match.to_mod_openflow(flow_stat[MATCH])
                        delete_list.append([cookie, priority, match])

        if len(delete_list) == 0:
            msg_details = 'Rule is not exist.'
        if rule_id != ALL:
            msg_details += ' : ruleID=%d' % rule_id
            msg = {'result': 'failure', 'details': msg_details}
        else:
            cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
            actions = []
            msg = []
            for cookie, priority, match in delete_list:
                flow = self._to_of_flow(cookie=cookie, priority=priority,
                                        match=match, actions=actions)
                self.ofctl.mod_flow_entry(self.dp, flow, cmd)

                rule_ids = Firewall._cookie_to_ruleid(cookie)
                del_msg = {'result': 'success', 'details': 'Rule deleted. : ruleID=%s' % rule_ids}
                msg.append(del_msg)

        return COMMAND_RESULT, msg


    def flush_all(self, datapath):
#	parser = datapath.ofproto_parser
	ofproto = datapath.ofproto
	flow = {'table_id': ofproto.OFPTT_ALL}
	self.ofctl.mod_flow_entry(datapath, flow, ofproto.OFPFC_DELETE)
#	match = parser.OFPMatch()
#	instructions = []
#	flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, 0, ofproto.OFPFC_DELETE, 0, 0, 1, ofproto.OFPCML_NO_BUFFER, ofproto.OFPP_ANY, OFPG_ANY, 0, match, instructions)
#	datapath.send_msg(flow_mod)

    def set_arp_flow(self):
	cookie = 0
	priority = ARP_FLOW_PRIORITY
	match = {DL_TYPE: ether.ETH_TYPE_ARP}
	action = {ACTION: ACTION_ALLOW}
	actions = Action.to_openflow(action)
	flow = self._to_of_flow(cookie=cookie, priority=priority, match=match, actions=actions)
	cmd = self.dp.ofproto.OFPFC_ADD
	self.ofctl.mod_flow_entry(self.dp, flow, cmd)

    @staticmethod
    def _cookie_to_ruleid(cookie):
        return cookie & ofproto_v1_3_parser.UINT32_MAX

    def _to_of_flow(self, cookie, priority, match, actions):
        flow = {'cookie': cookie,
                'priority': priority,
                'flags': 0,
                'idle_timeout': 0,
                'hard_timeout': 0,
                'match': match,
                'actions': actions}
        return flow

    def _to_rest_rule(self, flow):
        ruleid = Firewall._cookie_to_ruleid(flow[COOKIE])
        rule = {RULE_ID: ruleid}
        rule.update({PRIORITY: flow[PRIORITY]})
        rule.update(Match.to_rest(flow))
        rule.update(Action.to_rest(flow))
        return rule

    @staticmethod
    def _pckt_in_(msg):
	#msg = ev.msg
	pkt = packet.Packet(msg.data)
        dpid_str = dpid_lib.dpid_to_str(msg.datapath.id)
        MainController._LOGGER.info('dpid=%s: Blocked packet = %s', dpid_str, pkt)

# switch module for learning switch
class Switch_module(object):

    OFP_VERSIONS = {ofproto_v1_3.OFP_VERSION: ofctl_v1_3, ofproto_v1_4.OFP_VERSION: ofctl_v1_4, ofproto_v1_5.OFP_VERSION: ofctl_v1_5}

    def __init__(self, dp):
        super(Switch_module, self).__init__()
	self.mac_to_port = {}
	version = dp.ofproto.OFP_VERSION
	if version not in self.OFP_VERSIONS:
	    raise OFPUnkownVersion(version=version)

	# adding table miss entry in switches
    def add_table_miss(self, datapath):
	ofproto = datapath.ofproto
	parser = datapath.ofproto_parser
	match = parser.OFPMatch()
	actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

	# packet_in handler for learning switch
    def _pckt_in_(self, msg):
	#msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        MainController._LOGGER.info("packet in from switch %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

#        match = parser.OFPMatch(in_port=in_port)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

class Match(object):

    _CONVERT = {DL_TYPE:
                {DL_TYPE_ARP: ether.ETH_TYPE_ARP,
                 DL_TYPE_IPV4: ether.ETH_TYPE_IP,
                 DL_TYPE_IPV6: ether.ETH_TYPE_IPV6},
                NW_PROTO:
                {NW_PROTO_TCP: inet.IPPROTO_TCP,
                 NW_PROTO_UDP: inet.IPPROTO_UDP,
                 NW_PROTO_ICMP: inet.IPPROTO_ICMP,
                 NW_PROTO_ICMPV6: inet.IPPROTO_ICMPV6}}

    _MATCHES = [IN_PORT,
                SRC_MAC,
                DST_MAC,
                DL_TYPE,
                DL_VLAN,
                SRC_IP,
                DST_IP,
                SRC_IPV6,
                DST_IPV6,
                NW_PROTO,
                TP_SRC,
                TP_DST]

    @staticmethod
    def to_openflow(rest):

        def __inv_combi(msg):
            raise ValueError('Invalid combination: [%s]' % msg)

        def __inv_2and1(*args):
            __inv_combi('%s=%s and %s' % (args[0], args[1], args[2]))

        def __inv_2and2(*args):
            __inv_combi('%s=%s and %s=%s' % (
                args[0], args[1], args[2], args[3]))

        def __inv_1and1(*args):
            __inv_combi('%s and %s' % (args[0], args[1]))

        def __inv_1and2(*args):
            __inv_combi('%s and %s=%s' % (args[0], args[1], args[2]))

        match = {}

        # error check
        dl_type = rest.get(DL_TYPE)
        nw_proto = rest.get(NW_PROTO)
        if dl_type is not None:
            if dl_type == DL_TYPE_ARP:
                if SRC_IPV6 in rest:
                    __inv_2and1(
                        DL_TYPE, DL_TYPE_ARP, SRC_IPV6)
                if DST_IPV6 in rest:
                    __inv_2and1(
                        DL_TYPE, DL_TYPE_ARP, DST_IPV6)
                if nw_proto:
                    __inv_2and1(
                        DL_TYPE, DL_TYPE_ARP, NW_PROTO)
            elif dl_type == DL_TYPE_IPV4:
                if SRC_IPV6 in rest:
                    __inv_2and1(
                        DL_TYPE, DL_TYPE_IPV4, SRC_IPV6)
                if DST_IPV6 in rest:
                    __inv_2and1(
                        DL_TYPE, DL_TYPE_IPV4, DST_IPV6)
                if nw_proto == NW_PROTO_ICMPV6:
                    __inv_2and2(
                        DL_TYPE, DL_TYPE_IPV4,
                        NW_PROTO, NW_PROTO_ICMPV6)
            elif dl_type == DL_TYPE_IPV6:
                if SRC_IP in rest:
                    __inv_2and1(
                        DL_TYPE, DL_TYPE_IPV6, SRC_IP)
                if DST_IP in rest:
                    __inv_2and1(
                        DL_TYPE, DL_TYPE_IPV6, DST_IP)
                if nw_proto == NW_PROTO_ICMP:
                    __inv_2and2(
                        DL_TYPE, DL_TYPE_IPV6,
                        NW_PROTO, NW_PROTO_ICMP)
            else:
                raise ValueError('Unknown dl_type : %s' % dl_type)
        else:
            if SRC_IP in rest:
                if SRC_IPV6 in rest:
                    __inv_1and1(SRC_IP, SRC_IPV6)
                if DST_IPV6 in rest:
                    __inv_1and1(SRC_IP, DST_IPV6)
                if nw_proto == NW_PROTO_ICMPV6:
                    __inv_1and2(
                        SRC_IP, NW_PROTO, NW_PROTO_ICMPV6)
                rest[DL_TYPE] = DL_TYPE_IPV4
            elif DST_IP in rest:
                if SRC_IPV6 in rest:
                    __inv_1and1(DST_IP, SRC_IPV6)
                if DST_IPV6 in rest:
                    __inv_1and1(DST_IP, DST_IPV6)
                if nw_proto == NW_PROTO_ICMPV6:
                    __inv_1and2(
                        DST_IP, NW_PROTO, NW_PROTO_ICMPV6)
                rest[DL_TYPE] = DL_TYPE_IPV4
            elif SRC_IPV6 in rest:
                if nw_proto == NW_PROTO_ICMP:
                    __inv_1and2(
                        SRC_IPV6, NW_PROTO, NW_PROTO_ICMP)
                rest[DL_TYPE] = DL_TYPE_IPV6
            elif DST_IPV6 in rest:
                if nw_proto == NW_PROTO_ICMP:
                    __inv_1and2(
                        DST_IPV6, NW_PROTO, NW_PROTO_ICMP)
                rest[DL_TYPE] = DL_TYPE_IPV6
            else:
                if nw_proto == NW_PROTO_ICMP:
                    rest[DL_TYPE] = DL_TYPE_IPV4
                elif nw_proto == NW_PROTO_ICMPV6:
                    rest[DL_TYPE] = DL_TYPE_IPV6
                elif nw_proto == NW_PROTO_TCP or \
                        nw_proto == NW_PROTO_UDP:
                    raise ValueError('no dl_type was specified')
                else:
                    raise ValueError('Unknown nw_proto: %s' % nw_proto)

        for key, value in rest.items():
            if key in Match._CONVERT:
                if value in Match._CONVERT[key]:
                    match.setdefault(key, Match._CONVERT[key][value])
                else:
                    raise ValueError('Invalid rule parameter. : key=%s' % key)
            elif key in Match._MATCHES:
                match.setdefault(key, value)

        return match

    @staticmethod
    def to_rest(openflow):
        of_match = openflow[MATCH]

        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'
        ipv6_dontcare = '::'

        match = {}
        for key, value in of_match.items():
            if key == SRC_MAC or key == DST_MAC:
                if value == mac_dontcare:
                    continue
            elif key == SRC_IP or key == DST_IP:
                if value == ip_dontcare:
                    continue
            elif key == SRC_IPV6 or key == DST_IPV6:
                if value == ipv6_dontcare:
                    continue
            elif value == 0:
                continue

            if key in Match._CONVERT:
                conv = Match._CONVERT[key]
                conv = dict((value, key) for key, value in conv.items())
                match.setdefault(key, conv[value])
            else:
                match.setdefault(key, value)

        return match

    @staticmethod
    def to_mod_openflow(of_match):
        mac_dontcare = mac.haddr_to_str(mac.DONTCARE)
        ip_dontcare = '0.0.0.0'
        ipv6_dontcare = '::'

        match = {}
        for key, value in of_match.items():
            if key == SRC_MAC or key == DST_MAC:
                if value == mac_dontcare:
                    continue
            elif key == SRC_IP or key == DST_IP:
                if value == ip_dontcare:
                    continue
            elif key == SRC_IPV6 or key == DST_IPV6:
                if value == ipv6_dontcare:
                    continue
            elif value == 0:
                continue

            match.setdefault(key, value)

        return match


class Action(object):

    @staticmethod
    def to_openflow(rest):
        value = rest.get(ACTION, ACTION_ALLOW)

        if value == ACTION_ALLOW:
            action = [{'type': 'OUTPUT',
                       'port': 'NORMAL'}]
        elif value == ACTION_DENY:
            action = []
        elif value == ACTION_PACKETIN:
            action = [{'type': 'OUTPUT',
                       'port': 'CONTROLLER',
                       'max_len': 128}]
        else:
            raise ValueError('Invalid action type.')

        return action

    @staticmethod
    def to_rest(openflow):
        if ACTION in openflow:
            action_allow = 'OUTPUT:NORMAL'
            if openflow[ACTION] == [action_allow]:
                action = {ACTION: ACTION_ALLOW}
            else:
                action = {ACTION: ACTION_DENY}
        else:
            action = {ACTION: 'Unknown action type.'}

        return action
