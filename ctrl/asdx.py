#  Author:
#  Rudiger Birkner (Networked Systems Group ETH Zurich)

import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app.wsgi import WSGIApplication
from ryu import cfg

from core import parse_config, SDX
from lib import *
from rest import aSDXController
from ss_rule_scheme import init_misc_rules, init_main_rules, init_inbound_rules

LOG = False

##
BGP = 179
BROADCAST = "ff:ff:ff:ff:ff:ff"

# TABLES
MAIN_TABLE = 0
OUTBOUND_TABLE = 1
INBOUND_TABLE = 2
ARP_BGP_TABLE = 3

# PRIORITIES (Values can be in [0,65535], 0 is miss)
FLOW_MISS_PRIORITY = 0

OUTBOUND_POLICY_PRIORITY = 1

DEFAULT_FORWARDING_PRIORITY = 2



# COOKIES
NO_COOKIE = 0

BEST_PATH_COOKIE = 1
OUTBOUND_POLICY_COOKIE = 2

DEFAULT_INBOUND_COOKIE = 3
INBOUND_POLICY_COOKIE = 4

DEFAULT_WITH_INBOUND_COOKIE = 5
DEFAULT_WO_INBOUND_COOKIE = 6

class aSDX(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):
        super(aSDX, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(aSDXController, self)

        
        self.mac_to_port = {}
        self.datapath = None
        
        self.metadata_mask = 4095
        self.cookie_mask = 15
        
        # parse aSDX config
        CONF = cfg.CONF
        dir = CONF['asdx']['dir']
        base_path = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","examples",dir,"controller"))
        config_file = os.path.join(base_path, "sdx_config", "sdx_global.cfg")
        policy_file = os.path.join(base_path, "sdx_config", "sdx_policies.cfg")
        
        self.sdx = parse_config(base_path, config_file, policy_file)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        init_misc_rules(self, ev)

        init_main_rules(self, ev)

        init_inbound_rules(self, ev)
        
    
    def supersets_changed(self, update):
        parser = self.datapath.ofproto_parser
    
        if (update["type"] == "new"):
            # delete all rules and continue
            match = parser.OFPMatch() 
            self.delete_flows(self.datapath, OUTBOUND_POLICY_COOKIE, OUTBOUND_TABLE, match)
            
        if LOG: 
            self.logger.info("SUPERSETS_CHANGED: changes - %s", update)
            
        # add flow rules
        changes = update["changes"]
        for change in changes:
            if "participant_id" in change:
                for policy in self.sdx.dst_participant_2_policies[change["participant_id"]]:
                    src_participant_name = policy["in_port"]
                    dst_participant_name = policy["action"]["fwd"]

                    # vmac bitmask - superset id and bit at position of participant
                    superset_id = change["superset"]
                    participant_index = change["position"]

                    vmac_bitmask = vmac_participant_match(2**self.sdx.superset_id_size-1, participant_index, self.sdx)
                    vmac = vmac_participant_match(superset_id, participant_index, self.sdx)
                                
                    match_args = policy["match"]
                    match_args["metadata"] = src_participant_name
                    match_args["eth_dst"] = (vmac, vmac_bitmask)
                    match = parser.OFPMatch(**match_args) 
                                
                    instructions = [parser.OFPInstructionWriteMetadata(dst_participant_name, self.metadata_mask), 
                                    parser.OFPInstructionGotoTable(INBOUND_TABLE)]
                                    
                    if LOG: 
                        self.logger.info("SUPERSETS_CHANGED: Install new flow rule according to outbound policy")
                        self.logger.info("SUPERSETS_CHANGED: policy - %s", policy)
                                
                    self.add_flow(self.datapath, OUTBOUND_POLICY_COOKIE, OUTBOUND_TABLE, OUTBOUND_POLICY_PRIORITY, match, None, instructions)
                
        return changes
    
    def add_flow(self, datapath, cookie, table, priority, match, actions, instructions=[], buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        if actions:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        else:
            inst = []

        if instructions is not None:
            inst.extend(instructions)
        
        cookie_mask = 0
        if (cookie <> 0):
            cookie_mask = self.cookie_mask
  
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=cookie_mask, table_id=table, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=cookie_mask, table_id=table, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def delete_flows(self, datapath, cookie, table, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
               
        cookie_mask = 0
        if (cookie <> 0):
            cookie_mask = cookie_mask

        mod = parser.OFPFlowMod(datapath=datapath, cookie=cookie, cookie_mask=cookie_mask, table_id=table, command=ofproto_v1_3.OFPFC_DELETE,
                                out_group=ofproto_v1_3.OFPG_ANY, out_port=ofproto_v1_3.OFPP_ANY, match=match)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        table_id = msg.table_id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src
        
        if eth.ethertype == 2048:
            eth_type = "IPv4"
        elif eth.ethertype == 2054: 
            eth_type = "ARP"
        elif eth.ethertype == 34525: 
            eth_type = "IPv6"
        else:
            eth_type = "unknown"

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        if LOG: 
            self.logger.info("PACKET_IN: packet in dpid: %s, table: %s, eth_type: %s, src: %s, dst: %s, in_port: %s", dpid, table_id, eth_type, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if (table_id == ARP_BGP_TABLE):
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, NO_COOKIE, table_id, DEFAULT_FORWARDING_PRIORITY, match, actions, None, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, NO_COOKIE, table_id, DEFAULT_FORWARDING_PRIORITY, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
