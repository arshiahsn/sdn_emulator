# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4 
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp

"""
class MyMatch():
    def __init__(self, tcp_src_, tcp_dst_, eth_src_, eth_dst_):
        self.tcp_src = tcp_src_
        self.tcp_dst = tcp_dst_
        self.eth_src = eth_src_
        self.eth_dst = eth_dst_
""" 


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self._tr_phy = {}
        self.trans_to_phy = {}
        #self.mymatch_to_port = {}
        #self.trans_to_phy = {}
        try:
            f = open("trans_to_phy.txt",'r')
            lines = f.readlines()[1:]
            for line in lines:
                words = line.split()
                self._tr_phy[int(words[0])] = int(words[1]) 
            f.close()
        except FileNotFoundError:
            print("File not accessible")
            

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #Whenever a new switch as discovered and handshake is completed
        #Runs this in order to install the table-miss entry in the table of the switch


        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        tcp_match = parser.OFPMatch(eth_type=0x0800, ip_proto=6)
        self.add_flow(datapath, 2, tcp_match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #Packet handler with unkown destinations

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

        pkt = packet.Packet(data=msg.data) 
        #self.logger.info("packet-in %s" % (pkt,))

        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_tcp = pkt.get_protocol(tcp.tcp)

 

        #my_match = MyMatch(tcp_src,tcp_dst,eth_src,eth_dst)

        #pkt = packet.Packet(msg.data)
        #eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = pkt_eth.dst
        src = pkt_eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.trans_to_phy.setdefault(dpid, {})
        for key in self._tr_phy:
            self.trans_to_phy[dpid][key] = self._tr_phy[key]
        #self.tcp_to_port.setdefault(dpid,{})
        # learn a mac address to avoid FLOOD next time.
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        self.mac_to_port[dpid][src] = in_port
        

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        #out_port = self.mymatch_to_port[my_match][tcp_dst]
        else:
            if in_port == 1:
                out_port = 2
            elif in_port == 2:
                out_port = 1
            else:
                out_port = 0

        if pkt_tcp:
            tcp_dst = pkt_tcp.dst_port
            tcp_src = pkt_tcp.src_port
            self.trans_to_phy[dpid][tcp_src] = in_port
            self.logger.info("TCP Port %s", tcp_dst)
            if in_port == 1:
                if tcp_dst in self.trans_to_phy[dpid]:
                    out_port = self.trans_to_phy[dpid][tcp_dst]
                    self.logger.info("Out Port %s", out_port)
            else:
                out_port = 1

        if out_port != 0:
            actions = [parser.OFPActionOutput(out_port)]
            
            # install a flow to avoid packet_in next time

            if pkt_tcp:
                match = parser.OFPMatch(in_port=in_port, tcp_dst=tcp_dst)
                self.add_flow(datapath, 3, match, actions)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
