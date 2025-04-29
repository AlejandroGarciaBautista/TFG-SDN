from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, vlan, ether_types
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
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        self.datapaths[dp.id] = dp

        # Enviar todo a controller por defecto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)

        # Ignorar IPv6
        ignore = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        self.add_flow(dp, 65534, ignore, [])

    def add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        fm = parser.OFPFlowMod(datapath=dp, priority=priority,
                               idle_timeout=idle_timeout,
                               hard_timeout=hard_timeout,
                               match=match, instructions=inst)
        dp.send_msg(fm)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # extraer VLAN (0 si no tagged)
        vlan_hdr = pkt.get_protocol(vlan.vlan)
        vid = vlan_hdr.vid if vlan_hdr else 0

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, vid)

        if ip_pkt:
            self.shortest_forwarding(msg, eth.ethertype,
                                     ip_pkt.src, ip_pkt.dst, vid)

    def arp_forwarding(self, msg, src_ip, dst_ip, vlan_id):
        dp = msg.datapath
        ofp = dp.ofproto

        # ahora consultamos también la VLAN
        result = self.arp_handler.get_host_location(dst_ip, vlan_id)
        if result:
            dst_dpid, out_port, _ = result
            dp_dst = self.datapaths.get(dst_dpid)
            if not dp_dst:
                return
            out = self._build_packet_out(dp_dst, ofp.OFP_NO_BUFFER,
                                         ofp.OFPP_CONTROLLER, out_port,
                                         msg.data)
            dp_dst.send_msg(out)
        else:
            self.controlled_arp_forwarding(msg, src_ip, dst_ip, vlan_id)

    def controlled_arp_forwarding(self, msg, src_ip, dst_ip, vlan_id):
        dp = msg.datapath
        ofp = dp.ofproto
        # si ya lo conocemos, no broadcast
        if self.arp_handler.get_host_location(dst_ip, vlan_id):
            return

        self.logger.info(f"[ARP] Broadcast VLAN {vlan_id} para {dst_ip}")
        for dpid, ports in self.arp_handler.access_ports.items():
            for port in ports:
                key = (dpid, port, vlan_id)
                # sólo a puertos sin host aprendido en esa VLAN
                if key not in self.arp_handler.access_table:
                    dp_iter = self.datapaths.get(dpid)
                    if not dp_iter:
                        continue
                    out = self._build_packet_out(dp_iter,
                                                 ofp.OFP_NO_BUFFER,
                                                 ofp.OFPP_CONTROLLER,
                                                 port, msg.data)
                    dp_iter.send_msg(out)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst, vlan_id):
        dp = msg.datapath
        in_port = msg.match['in_port']

        # determinar switch origen y destino (incluye VLAN)
        res = self.get_sw(dp.id, in_port, ip_src, ip_dst, vlan_id)
        if not res:
            return
        src_sw, dst_sw, out_port = res

        match = dp.ofproto_parser.OFPMatch(
            eth_type=eth_type,
            vlan_vid=(dp.ofproto.OFPVID_PRESENT | vlan_id)
                if vlan_id else eth_type,
            ipv4_dst=ip_dst
        )
        # instalar ruta y obtener puerto de salida en el primer switch
        port_no = self.arp_handler.set_shortest_path(
            ip_src, ip_dst, src_sw, dst_sw,
            to_port_no=out_port, vlan_id=vlan_id, pre_actions=[]
        )
        # reenviar el paquete original por ese puerto
        self.send_packet_out(dp, msg.buffer_id, in_port, port_no, msg.data)

    def get_sw(self, dpid, in_port, src_ip, dst_ip, vlan_id):
        # si viene de un puerto de acceso, validar que sea el host correcto
        src_loc = self.arp_handler.get_host_location(src_ip, vlan_id)
        if in_port in self.arp_handler.access_ports.get(dpid, ()):
            if (dpid, in_port, vlan_id) != src_loc:
                return None
            src_sw = dpid
        else:
            src_sw = dpid

        dst_loc = self.arp_handler.get_host_location(dst_ip, vlan_id)
        if dst_loc:
            return (src_sw, dst_loc[0], dst_loc[1])
        return None

    def _build_packet_out(self, dp, buffer_id, in_port, out_port, data):
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)] if out_port else []
        msg_data = data if buffer_id == dp.ofproto.OFP_NO_BUFFER else None
        return parser.OFPPacketOut(
            datapath=dp, buffer_id=buffer_id,
            in_port=in_port, data=msg_data, actions=actions
        )

    def send_packet_out(self, dp, buffer_id, in_port, out_port, data):
        out = self._build_packet_out(dp, buffer_id, in_port, out_port, data)
        if out:
            dp.send_msg(out)
