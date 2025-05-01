import ipaddress
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, vlan, ether_types

import ArpHandler


class ShortestPath(app_manager.RyuApp):
    """
    RyuApp que calcula rutas más cortas (ECMP) e implementa políticas
    de aislamiento de VLANs: sólo comunicaciones intra-VLAN y
    entre VLAN 10 ⇄ 30.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        "ArpHandler": ArpHandler.ArpHandler
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Módulo que mantiene la tabla ARP y topología
        self.arp_handler = kwargs["ArpHandler"]
        # Switches registrados
        self.datapaths = {}

        # Definición de rangos IP → VLAN
        self.vlan_subnets = {
            10: ipaddress.ip_network("10.0.10.0/24"),
            20: ipaddress.ip_network("10.0.20.0/24"),
            30: ipaddress.ip_network("10.0.30.0/24")
        }
        # Pares de VLAN permitidos
        self.allowed_pairs = {
            (10,10), (20,20), (30,30),
            (10,30), (30,10)
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Al conectar un switch, instalar:
          1) regla por defecto: enviar todo al controller.
          2) regla alta prioridad: descartar IPv6.
        """
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        self.datapaths[dp.id] = dp

        # 1) Enviar todo paquete al controlador
        match_all = parser.OFPMatch()
        actions_ctrl = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                               ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, priority=0, match=match_all, actions=actions_ctrl)

        # 2) Ignorar IPv6
        match_ipv6 = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IPV6)
        self.add_flow(dp, priority=65534, match=match_ipv6, actions=[])

    def add_flow(self, dp, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        """
        Método auxiliar para instalar un flujo OF.
        """
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        fm = parser.OFPFlowMod(datapath=dp,
                               priority=priority,
                               match=match,
                               instructions=inst,
                               idle_timeout=idle_timeout,
                               hard_timeout=hard_timeout)
        dp.send_msg(fm)

    def get_vlan_from_ip(self, ip_str):
        """
        Dada una IP como string, devuelve la VLAN (10/20/30)
        o None si no pertenece a ningún rango conocido.
        """
        ip = ipaddress.ip_address(ip_str)
        for vid, net in self.vlan_subnets.items():
            if ip in net:
                return vid
        return None



    # @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    # def _packet_in_handler(self, ev):
    #     """
    #     Manejador de PacketIn con soporte para:
    #       1) ARP en la red underlay (hosts “normales”) y en las VLAN overlay.
    #       2) Tráfico IP entre hosts “normales” (fuera de 10/20/30).
    #       3) Políticas de aislamiento para VLAN 10, 20 y 30 (solo intra-VLAN y 10⇄30).
    #     """
    #     msg = ev.msg
    #     dp = msg.datapath
    #     in_port = msg.match['in_port']
    #     pkt = packet.Packet(msg.data)

    #     # 1) Ignorar LLDP
    #     eth = pkt.get_protocol(ethernet.ethernet)
    #     if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
    #         return

    #     # 2) ARP: 
    #     #    - Ambos fuera de overlay → underlay (vlan_id=0)
    #     #    - Ambos en la misma VLAN → overlay intra-VLAN
    #     #    - Uno en overlay y otro no → DROP
    #     arp_pkt = pkt.get_protocol(arp.arp)
    #     if arp_pkt:
    #         src_vlan = self.get_vlan_from_ip(arp_pkt.src_ip)
    #         dst_vlan = self.get_vlan_from_ip(arp_pkt.dst_ip)

    #         if src_vlan is None and dst_vlan is None:
    #             # ARP en underlay
    #             vlan_id = 0
    #         elif src_vlan is None or dst_vlan is None:
    #             # Cruzado overlay-underlay → descartar
    #             self.logger.info(f"DROP ARP {arp_pkt.src_ip}→{arp_pkt.dst_ip}: "
    #                              f"desajuste de VLAN ({src_vlan},{dst_vlan})")
    #             return
    #         else:
    #             # ARP intra-VLAN overlay
    #             vlan_id = src_vlan

    #         self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, vlan_id)
    #         return

    #     # 3) IPv4: aplicamos política de VLAN/underlay
    #     ip_pkt = pkt.get_protocol(ipv4.ipv4)
    #     if not ip_pkt:
    #         return

    #     src_vlan = self.get_vlan_from_ip(ip_pkt.src)
    #     dst_vlan = self.get_vlan_from_ip(ip_pkt.dst)

    #     # A) Tráfico underlay: ambos fuera de overlay
    #     if src_vlan is None and dst_vlan is None:
    #         self.shortest_forwarding(msg, eth.ethertype,
    #                                  ip_pkt.src, ip_pkt.dst,
    #                                  vlan_id=0)
    #         return

    #     # B) Uno en overlay y otro no → DROP
    #     if src_vlan is None or dst_vlan is None:
    #         self.logger.info(f"DROP IP {ip_pkt.src}({src_vlan})→"
    #                          f"{ip_pkt.dst}({dst_vlan}): mixto overlay/underlay")
    #         return

    #     # C) Ambos en overlay → aplicar pares permitidos {(10,10),(20,20),(30,30),(10,30),(30,10)}
    #     if (src_vlan, dst_vlan) not in self.allowed_pairs:
    #         self.logger.info(f"DROP VLAN {src_vlan}→{dst_vlan}: no permitida")
    #         return

    #     # C1) Intra-VLAN overlay
    #     if src_vlan == dst_vlan:
    #         self.shortest_forwarding(msg, eth.ethertype,
    #                                  ip_pkt.src, ip_pkt.dst, src_vlan)
    #     # C2) Inter-VLAN overlay permitido (10⇄30)
    #     else:
    #         self.logger.info("AQUI")
    #         self.inter_vlan_forwarding(msg, eth.ethertype,
    #                                    ip_pkt.src, ip_pkt.dst,
    #                                    src_vlan, dst_vlan)


    def arp_forwarding(self, msg, src_ip, dst_ip, vlan_id):
        dp = msg.datapath
        ofp = dp.ofproto

        # Consultar ARP en esa VLAN
        result = self.arp_handler.get_host_location(dst_ip, vlan_id)
        if result:
            dst_dpid, out_port, _ = result
            dp_dst = self.datapaths.get(dst_dpid)
            if not dp_dst:
                return
            out = self._build_packet_out(
                dp_dst, ofp.OFP_NO_BUFFER,
                ofp.OFPP_CONTROLLER, out_port, msg.data
            )
            dp_dst.send_msg(out)
        else:
            self.controlled_arp_forwarding(
                msg, src_ip, dst_ip, vlan_id
            )

    def controlled_arp_forwarding(self, msg, src_ip, dst_ip, vlan_id):
        dp = msg.datapath
        ofp = dp.ofproto

        # Si ya lo conocemos, no broadcast
        if self.arp_handler.get_host_location(dst_ip, vlan_id):
            return

        self.logger.info(f"[ARP] Broadcast VLAN {vlan_id} para {dst_ip} desde {src_ip}")
        for dpid, ports in self.arp_handler.access_ports.items():
            for port in ports:
                key = (dpid, port, vlan_id)
                if key not in self.arp_handler.access_table:
                    dp_iter = self.datapaths.get(dpid)
                    if not dp_iter:
                        continue
                    out = self._build_packet_out(
                        dp_iter, ofp.OFP_NO_BUFFER,
                        ofp.OFPP_CONTROLLER, port, msg.data
                    )
                    dp_iter.send_msg(out)

    def shortest_forwarding(self, msg, eth_type,
                            ip_src, ip_dst, vlan_id):
        dp = msg.datapath
        in_port = msg.match['in_port']

        # Determinar switch origen y destino (incluye VLAN)
        res = self.get_sw(dp.id, in_port, ip_src, ip_dst, vlan_id)
        if not res:
            return
        src_sw, dst_sw, out_port = res

        # Instalar ruta (ECMP) y reenviar
        port_no = self.arp_handler.set_shortest_path(
            ip_src, ip_dst, src_sw, dst_sw,
            to_port_no=out_port,
            vlan_id=vlan_id, pre_actions=[]
        )

        self.send_packet_out(dp, msg.buffer_id,
                             in_port, port_no, msg.data)

    def inter_vlan_forwarding(self, msg, eth_type,
                              ip_src, ip_dst,
                              src_vlan, dst_vlan):
        dp = msg.datapath
        in_port = msg.match['in_port']
        parser = dp.ofproto_parser
        ofp = dp.ofproto

        # Ubicar host destino en VLAN destino
        dst_loc = self.arp_handler.get_host_location(ip_dst, dst_vlan)
        if not dst_loc:
            return
        dst_dpid, dst_port, _ = dst_loc

        # Calcular siguiente salto
        src_sw = dp.id
        _, _, out_port = self.get_sw(src_sw, in_port,
                                     ip_src, ip_dst, src_vlan)

        # 1) Instalar flujo en switch origen: POP src_vlan, PUSH dst_vlan
        match = parser.OFPMatch(
            eth_type=eth_type,
            vlan_vid=(ofp.OFPVID_PRESENT | src_vlan),
            ipv4_src=ip_src,
            ipv4_dst=ip_dst
        )
        actions = [
            parser.OFPActionPopVlan(),
            parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
            parser.OFPActionSetField(
                vlan_vid=(ofp.OFPVID_PRESENT | dst_vlan)
            ),
            parser.OFPActionOutput(out_port)
        ]
        self.add_flow(dp, priority=20, match=match, actions=actions)

        # 2) Delegar resto de la ruta al set_shortest_path (ahora con dst_vlan)
        self.arp_handler.set_shortest_path(
            ip_src, ip_dst,
            src_dpid=src_sw, dst_dpid=dst_dpid,
            to_port_no=dst_port,
            vlan_id=dst_vlan,
            pre_actions=[]
        )

        # 3) Reenviar paquete original inmediatamente
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            data=msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None,
            actions=actions
        )
        dp.send_msg(out)

    def get_sw(self, dpid, in_port, src_ip, dst_ip, vlan_id):
        # Validar puerto de acceso
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

    def _build_packet_out(self, dp, buffer_id,
                          in_port, out_port, data):
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)] if out_port else []
        msg_data = data if buffer_id == dp.ofproto.OFP_NO_BUFFER else None
        return parser.OFPPacketOut(
            datapath=dp, buffer_id=buffer_id,
            in_port=in_port, data=msg_data, actions=actions
        )

    def send_packet_out(self, dp, buffer_id,
                        in_port, out_port, data):
        out = self._build_packet_out(
            dp, buffer_id, in_port, out_port, data
        )
        if out:
            dp.send_msg(out)
