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
from lib import vmac_best_path_match, vmac_participant_match
from rest import aSDXController

from asdx import add_flow, delete_flows

LOG = True

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

# main switch priorities
ARP_BGP_PRIORITY = 4
OUTBOUND_NEEDED_PRIORITY = 3
DEFAULT_FORWARDING_PRIORITY = 2
INBOUND_NEEDED_PRIORITY = 1

# outbound switch priorities
OUTBOUND_POLICY_PRIORITY = 1

# inbound switch priorities
INBOUND_PRIORITY = 2
INBOUND_DEFAULT_PRIORITY = 1

# bgp table priority
GRATUITOUS_ARP_PRIORITY = 3
VNH_ARP_REQ_PRIORITY = 2
DEFAULT_PRIORITY = 1

# COOKIES
NO_COOKIE = 0

DEFAULT_FORWARDING_COOKIE = 1
OUTBOUND_POLICY_COOKIE = 2

DEFAULT_INBOUND_COOKIE = 3
INBOUND_POLICY_COOKIE = 4

OUTBOUND_REQUIRED_COOKIE = 5
INBOUND_REQUIRED_COOKIE = 6




def init_main_rules(self, ev):
    datapath = ev.msg.datapath
    self.datapath = datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    if LOG:
        self.logger.info("INIT: -- Installing main switch rule blocks --")



    if LOG:
        self.logger.info("INIT: Setting up bouncing for packets which require outbound policies")

    # install rules for traffic which must bounce to the outbound switch
    for participant_name in self.sdx.participants:
        participant = self.sdx.participants[participant_name]
        if ('outbound' in participant["policies"]):

        	# tag all packets for this participant with the mac of their first port
        	port0_mac = participant["ports"][0]["MAC"]

        	for port in participant["ports"]:

                match = parser.OFPMatch(in_port=port["ID"]))

				# tag it with the participant's port 0 mac and forward it to the outbound switch
				actions = [parser.OFPActionSetField(eth_src=port0_mac)]
                instructions = [parser.OFPInstructionGotoTable(OUTBOUND_TABLE)]

            	self.add_flow(datapath, OUTBOUND_REQUIRED_COOKIE, MAIN_TABLE, OUTBOUND_NEEDED_PRIORITY, match, actions, instructions)




	if LOG:
        self.logger.info("INIT: Setting up bouncing for packets which require inbound policies")

	# install the rule which bounces traffic if it has the inbound bit set
	only_first_bit = vmac_only_first_bit(self.sdx)
    match = parser.OFPMatch(eth_dst = (only_first_bit, only_first_bit))

    instructions = [parser.OFPInstructionGotoTable(INBOUND_TABLE)]

    self.add_flow(datapath, INBOUND_REQUIRED_COOKIE, MAIN_TABLE, INBOUND_NEEDED_PRIORITY, match, None, instructions)


    if LOG:
        self.logger.info("INIT: Install default best routes")


    # install default forwarding rules
    for participant_name in self.sdx.participants:
        participant = self.sdx.participants[participant_name]
        # traffic that hit inbound policies will have stage-2 vmacs (includes a port number)
        if ('inbound' in participant["policies"]):  
            for port in participant["ports"]:   
                port_num = participant["ports"].index(port)

                # number of bits to represent both a port and participant
                part_port_size = self.sdx.port_size + self.sdx.best_path_size

                # if the next-hop expressed inbound policies, we need to make sure the first bit has been zeroed
                # the first bit is 0 iff the packet has already hit inbound policies
                vmac_bitmask = vmac_part_port_mask(sdx, inbound_bit = True)

                # vmac which has part ID and port number (first bit is 0 intentionally)
                vmac = vmac_part_port_match(participant_name, port_num, self.sdx, inbound_bit = False)

                match = parser.OFPMatch(eth_dst = (vmac, vmac_bitmask))

                dst_mac = participant["ports"][port_num]["MAC"]
                out_port = participant["ports"][port_num]["ID"]

                # output the packet to the participant
                actions = [parser.OFPActionSetField(eth_dst=dst_mac), 
                           parser.OFPActionOutput(out_port)]
                
                self.add_flow(datapath, DEFAULT_FORWARDING_COOKIE, MAIN_TABLE, DEFAULT_FORWARDING_PRIORITY, match, actions)

        # if the destination participant had no inbound, then we don't match on port bits (and first bit doesnt matter)
        else:
            vmac_bitmask = vmac_next_hop_mask(self.sdx, inbound_bit = False)
            vmac = vmac_next_hop_match(participant_name, self.sdx, inbound_bit = False)

            match = parser.OFPMatch(eth_dst=(vmac, vmac_bitmask))

            # we send to the first port by default for participants with no inbound policy
            dst_mac = participant["ports"][0]["MAC"]
            out_port = participant["ports"][0]["ID"]

            # output the packet to the participant
            actions = [parser.OFPActionSetField(eth_dst=dst_mac), 
                       parser.OFPActionOutput(out_port)]

            self.add_flow(datapath, DEFAULT_FORWARDING_COOKIE, MAIN_TABLE, DEFAULT_FORWARDING_PRIORITY, match, actions)





def init_inbound_rules(self, ev):
    datapath = ev.msg.datapath
    self.datapath = datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    if LOG:
        self.logger.info("INIT: -- Installing inbound switch rules --")


    for participant_name in self.sdx.participants: 
        participant = self.sdx.participants[participant_name]
        # check if participant specified inbound policies
        if ('inbound' in participant["policies"]):
            policies = participant["policies"]["inbound"] 
            for policy in policies:
            	port_num = policy["action"]["fwd"]

                # match on the next-hop
                vmac_bitmask = vmac_next_hop_mask(self.sdx)
                vmac = vmac_next_hop_match(participant_name, self.sdx)


                match_args = policy["match"]
                match_args["eth_dst"] = (vmac, vmac_bitmask)
                match = parser.OFPMatch(**match_args) 

                port_num = policy["action"]["fwd"]
                if port_num < len(participant["ports"]):
                	port_num = 0


				new_vmac = vmac_part_port_match(participant_name, port_num, self.sdx)                

                            
                actions = [parser.OFPActionSetField(eth_dst=new_vmac)]
                instructions = [parser.OFPInstructionGotoTable(MAIN_TABLE)]
                
                self.add_flow(datapath, INBOUND_POLICY_COOKIE, INBOUND_TABLE, INBOUND_PRIORITY, match, actions, instructions)
            # end for

	        # if participant had inbound policies, we must also install default inbound policies

	        # match on the next-hop
	        vmac_bitmask = vmac_next_hop_mask(self.sdx)
	        vmac = vmac_next_hop_match(participant_name, self.sdx)


	        match = parser.OFPMatch(eth_dst=(vmac, vmac_bitmask))
	            
	        port_num = 0
	        new_vmac = vmac_part_port_match(participant_name, port_num, self.sdx)
	            
	        actions = [parser.OFPActionSetField(eth_dst=new_vmac)]
	        instructions = [parser.OFPInstructionGotoTable(MAIN_TABLE)]
	            
	        self.add_flow(datapath, DEFAULT_INBOUND_COOKIE, INBOUND_TABLE, INBOUND_DEFAULT_PRIORITY, match, actions, instructions)
        # end if
    # end for

    


# install bgp and arp and whatevs
def init_misc_rules(self, ev):
    datapath = ev.msg.datapath
    self.datapath = datapath
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    

    if LOG:
    	self.logger.info("INIT: -- Installing misc rules --")

    # install table-miss flow entry
    #
    # We specify NO BUFFER to max_len of the output action due to
    # OVS bug. At this moment, if we specify a lesser number, e.g.,
    # 128, OVS will send Packet-In with invalid buffer_id and
    # truncated packet data. In that case, we cannot output packets
    # correctly.  The bug has been fixed in OVS v2.1.0.
    match = parser.OFPMatch()

    # misses in the main table and bgp table go to controller
    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
    self.add_flow(datapath, NO_COOKIE, MAIN_TABLE, FLOW_MISS_PRIORITY, match, actions)
    self.add_flow(datapath, NO_COOKIE, ARP_BGP_TABLE, FLOW_MISS_PRIORITY, match, actions)

    # misses in the outbound and inbound table just pass the packet along the loop
    instructions = [parser.OFPInstructionGotoTable(INBOUND_TABLE)]
    self.add_flow(datapath, NO_COOKIE, OUTBOUND_TABLE, FLOW_MISS_PRIORITY, match, None, instructions)
    instructions = [parser.OFPInstructionGotoTable(MAIN_TABLE)]
    self.add_flow(datapath, NO_COOKIE, INBOUND_TABLE, FLOW_MISS_PRIORITY, match, None, instructions)

       
    if LOG:
        self.logger.info("INIT: Set up ARP handling")
       
    # set up ARP handler
    match = parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP)
    instructions = [parser.OFPInstructionGotoTable(ARP_BGP_TABLE)]
    self.add_flow(datapath, NO_COOKIE, MAIN_TABLE, ARP_BGP_PRIORITY, match, None, instructions)

    # send all ARP requests for VNHs to the route server
    match = parser.OFPMatch(arp_tpa=(str(self.sdx.VNHs.network), str(self.sdx.VNHs.netmask)))
    out_port = self.sdx.rs_outport
    actions = [parser.OFPActionOutput(out_port)]
    self.add_flow(datapath, NO_COOKIE, ARP_BGP_TABLE, VNH_ARP_REQ_PRIORITY, match, actions)
    
    # add gratuitous ARP rules - makes sure that the participant specific gratuitous ARPs are 
    # only sent to the respective participant
    for participant_name in self.sdx.participants: 
        participant = self.sdx.participants[participant_name]
        # check if participant specified inbound policies
        vmac_bitmask = vmac_next_hop_mask(self.sdx)
        vmac = vmac_next_hop_match(participant_name, self.sdx)
        
        match = parser.OFPMatch(in_port=self.sdx.rs_outport, eth_dst=(vmac, vmac_bitmask))
        
        actions = [parser.OFPActionSetField(eth_dst=BROADCAST)]
        for port in participant["ports"]:              
            out_port = port["ID"]
            actions.append(parser.OFPActionOutput(out_port))
                            
        self.add_flow(datapath, NO_COOKIE, ARP_BGP_TABLE, GRATUITOUS_ARP_PRIORITY, match, actions)

    if LOG:
        self.logger.info("INIT: Set up BGP handling")
        
    # set up BGP handler
    match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, tcp_src=BGP)
    instructions = [parser.OFPInstructionGotoTable(ARP_BGP_TABLE)]
    self.add_flow(datapath, NO_COOKIE, MAIN_TABLE, ARP_BGP_PRIORITY, match, None, instructions)
    
    match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, tcp_dst=BGP)
    instructions = [parser.OFPInstructionGotoTable(ARP_BGP_TABLE)]
    self.add_flow(datapath, NO_COOKIE, MAIN_TABLE, ARP_BGP_PRIORITY, match, None, instructions)  




