from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types

import ArpHandler

class ShortestPath(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "ArpHandler": ArpHandler.ArpHandler
    }

    def __init__(self, *args, **kwargs):
        super(ShortestPath, self).__init__(*args, **kwargs)
        self.arp_handler = kwargs["ArpHandler"]
        self.datapaths = {}

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

        if arp_pkt:
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if ip_pkt:
            self.shortest_forwarding(msg, eth_pkt.ethertype, ip_pkt.src, ip_pkt.dst)

    def arp_forwarding(self, msg, src_ip, dst_ip):
        datapath = msg.datapath
        ofproto = datapath.ofproto

        result = self.arp_handler.get_host_location(dst_ip)
        if result:
            datapath_dst, out_port = result
            datapath = self.datapaths[datapath_dst]
            out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                         ofproto.OFPP_CONTROLLER, out_port, msg.data)
            datapath.send_msg(out)
        else:
            self.controlled_arp_forwarding(msg, src_ip, dst_ip)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = [datapath.ofproto_parser.OFPActionOutput(dst_port)] if dst_port else []
        msg_data = data if buffer_id == datapath.ofproto.OFP_NO_BUFFER else None

        return datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)

    def controlled_arp_forwarding(self, msg, src_ip, dst_ip):
        """
        - Solo reenvía paquetes ARP si no se conoce el destino.
        - Solo reenvía a puertos de acceso no asociados aún a un host.
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto

        if self.arp_handler.get_host_location(dst_ip):
            # Ya conocemos la ubicación del destino, no hace falta hacer broadcast
            return

        self.logger.info(f"[ARP] Broadcast controlado para {dst_ip}, origen: {src_ip}")

        for dpid in self.arp_handler.access_ports:
            for port in self.arp_handler.access_ports[dpid]:
                # Si no está en la tabla de acceso, significa que aún no hay host conocido en ese puerto
                if (dpid, port) not in self.arp_handler.access_table:
                    if dpid not in self.datapaths:
                        continue  # Puede que el datapath aún no esté registrado
                    datapath = self.datapaths[dpid]
                    out = self._build_packet_out(
                        datapath, ofproto.OFP_NO_BUFFER,
                        ofproto.OFPP_CONTROLLER, port, msg.data)
                    datapath.send_msg(out)


    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        datapath = msg.datapath
        in_port = msg.match['in_port']
        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)

        if result:
            src_sw, dst_sw, to_dst_port = result
            if dst_sw:
                match = datapath.ofproto_parser.OFPMatch(
                    eth_type=eth_type, ipv4_dst=ip_dst)
                port_no = self.arp_handler.set_shortest_path(
                    ip_src, ip_dst, src_sw, dst_sw, to_dst_port, match)
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