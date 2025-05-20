from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
from ryu.base.app_manager import lookup_service_brick

import ArpHandler
from utils import is_connection_allowed, get_vlan_from_ip

class ShortestPath(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # _CONTEXTS = {
    #     "ArpHandler": ArpHandler.ArpHandler
    # }

    def __init__(self, *args, **kwargs):
        super(ShortestPath, self).__init__(*args, **kwargs)
        self.arp_handler = lookup_service_brick('ArpHandler')
        # self.arp_handler = kwargs["ArpHandler"]
        self.datapaths = {}
        self.gateway_mac = "02:00:00:00:00:FE"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self.datapaths[dpid] = datapath        

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        ignore_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        self.add_flow(datapath, 65534, ignore_match, [])


        # Regla para ARP → controller
        # match = parser.OFPMatch(eth_type=0x0806)
        # actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
        #                                 ofproto.OFPCML_NO_BUFFER)]
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
        #                                     actions)]
        # mod = parser.OFPFlowMod(datapath=datapath,
        #                         priority=300,
        #                         match=match,
        #                         instructions=inst)
        # datapath.send_msg(mod)

    def add_flow(self, dp, p, match, actions, idle_timeout=0, hard_timeout=0):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if ip_pkt and ip_pkt.dst == '224.0.0.22':
            # ignorar IGMPv3 membership reports
            return

        if arp_pkt:
            self.logger.info("Conección permitida")
            self.arp_reply(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if ip_pkt and is_connection_allowed(ip_pkt.src, ip_pkt.dst):
            self.logger.info(f"Conexión permitida: {ip_pkt.src} -> {ip_pkt.dst}")
            self.shortest_forwarding(msg, eth_pkt.ethertype, ip_pkt.src, ip_pkt.dst)

    def arp_reply(self, msg, src_ip, dst_ip):
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']

        self.logger.info("ARP REPLY: %s -> %s", src_ip, dst_ip)

        if dst_ip.endswith('.254'):
            dst_mac = self.gateway_mac          
        else:
            if dst_ip not in self.arp_handler.hosts:
                return
            _, _, _, dst_mac = self.arp_handler.hosts[dst_ip]

        # Construir ARP_REPLY
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_reply = packet.Packet()
        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_pkt.src,
            src=dst_mac))
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=dst_mac,
            src_ip=dst_ip,
            dst_mac=eth_pkt.src,
            dst_ip=src_ip))
        arp_reply.serialize()

        # Enviar el reply de vuelta al puerto de origen
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=arp_reply.data)
        dp.send_msg(out)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = [datapath.ofproto_parser.OFPActionOutput(dst_port)] if dst_port else []
        msg_data = data if buffer_id == datapath.ofproto.OFP_NO_BUFFER else None

        return datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        datapath = msg.datapath
        in_port = msg.match['in_port']
        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        pre_actions = []
        same_vlan = get_vlan_from_ip(ip_src) == get_vlan_from_ip(ip_dst)

        if result:
            src_sw, dst_sw, to_dst_port = result

            if dst_sw:

                if not same_vlan:
                    dst_mac = self.arp_handler.hosts[ip_dst][3]
                    gw_mac = self.gateway_mac

                    parser = datapath.ofproto_parser
                    pre_actions = [
                        parser.OFPActionSetField(eth_src=gw_mac),
                        parser.OFPActionSetField(eth_dst=dst_mac)
                    ]

                match = datapath.ofproto_parser.OFPMatch(
                    eth_type=eth_type, ipv4_dst=ip_dst)
                
                port_no = self.arp_handler.set_shortest_path(
                    ip_src, ip_dst, src_sw, dst_sw, to_dst_port, match, pre_actions)
                
                self.send_packet_out(datapath, msg.buffer_id, in_port, port_no, msg.data)

    def get_sw(self, dpid, in_port, src, dst):
        src_location = self.arp_handler.get_host_location(src)
        if in_port in self.arp_handler.access_ports[dpid]:
            if (dpid, in_port) == src_location:
                src_sw = dpid
            else:
                return None
        else:
            src_sw = dpid

        dst_location = self.arp_handler.get_host_location(dst)
        if dst_location:
            return src_sw, dst_location[0], dst_location[1]
        return None

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id, src_port, dst_port, data)
        if out:
            datapath.send_msg(out)