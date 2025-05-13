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
    de aislamiento de VLANs: sólo comunicaciones intra-VLANs
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Manejador de PacketIn con soporte para:
          1) ARP en la red underlay y en las VLAN overlay.
          2) Tráfico IP entre hosts de la red underlay (fuera de las VLANs 10/20/30).
          3) Políticas de aislamiento para VLAN 10, 20 y 30.
        """
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        
        # 1) Ignorar LLDP
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # 2) ARP: 
        #    - Ambos fuera de overlay → underlay (vlan_id=0)
        #    - Ambos en la misma VLAN → overlay intra-VLAN
        #    - Uno en overlay y otro no → DROP

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            src_vlan = self.get_vlan_from_ip(arp_pkt.src_ip)
            dst_vlan = self.get_vlan_from_ip(arp_pkt.dst_ip)

            if src_vlan is None and dst_vlan is None:
                # ARP en underlay
                vlan_id = 0
            elif src_vlan is None or dst_vlan is None:
                # Cruzado overlay-underlay → descartar
                self.logger.info(f"DROP ARP {arp_pkt.src_ip}→{arp_pkt.dst_ip}: desajuste de VLAN ({src_vlan},{dst_vlan})")
                return
            elif (src_vlan, dst_vlan) in self.allowed_pairs:
                self.logger.info(f"[CROSS-ARP] VLAN Destino: {arp_pkt.dst_ip} -> {dst_vlan}")
                self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, dst_vlan)
                return
            elif src_vlan != dst_vlan:
                # ARP entre VLANs distintas → descartar
                self.logger.info(f"DROP ARP {arp_pkt.src_ip}→{arp_pkt.dst_ip}: no permitida ({src_vlan},{dst_vlan})")
                return
            else:
                # ARP intra-VLAN overlay
                vlan_id = src_vlan

            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, vlan_id)
            return

        # 3) IPv4: aplicamos política de VLAN/underlay
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return

        src_vlan = self.get_vlan_from_ip(ip_pkt.src)
        dst_vlan = self.get_vlan_from_ip(ip_pkt.dst)

        # A) Tráfico underlay: ambos fuera de la red overlay
        if src_vlan is None and dst_vlan is None:
            self.shortest_forwarding(msg, ip_pkt.src, ip_pkt.dst)
            return

        # B) Uno en overlay y otro no → DROP
        if src_vlan is None or dst_vlan is None:
            self.logger.info(f"DROP IP {ip_pkt.src}({src_vlan})→{ip_pkt.dst}({dst_vlan}): mixto overlay/underlay")
            return

        # C) Ambos en overlay
        # C2) Intra-VLAN overlay
        if src_vlan == dst_vlan:
            self.shortest_forwarding(msg, ip_pkt.src, ip_pkt.dst)
        
        # C1) Diferentes VLANs --> No se permite la comunicación a no ser que este permitida
        if (src_vlan, dst_vlan) in self.allowed_pairs:
            self.logger.info(f"Conexión IP {ip_pkt.src}({src_vlan})→{ip_pkt.dst}({dst_vlan}): permitida")
            # Función de reenvío para VLAN cruzada
            self.cross_vlan_shortest_forwarding(msg, ip_pkt.src, ip_pkt.dst)
            return
        
        if src_vlan != dst_vlan:
            self.logger.info(f"DROP VLAN {src_vlan}→{dst_vlan}: no permitida")
            return


    def arp_forwarding(self, msg, src_ip, dst_ip, vlan_id):
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        # DEBUG INICIAL: qué ARP está llegando exactamente
        self.logger.info(f"ARP recibido: {src_ip} pregunta por {dst_ip} en VLAN {vlan_id}")

        # Verifica si la IP destino es el gateway ficticio (.254)
        if dst_ip.endswith('.254'):
            self.logger.info(f"[ARP-GATEWAY] Respondiendo ARP para gateway {dst_ip}")

            pkt = packet.Packet(msg.data)
            eth_pkt = pkt.get_protocol(ethernet.ethernet)
            arp_pkt = pkt.get_protocol(arp.arp)

            # Respuesta ARP ficticia desde controlador (router lógico)
            reply_pkt = packet.Packet()
            reply_pkt.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_8021Q,
                dst=eth_pkt.src,
                src="00:00:00:00:fe:fe"
            ))

            reply_pkt.add_protocol(vlan.vlan(
                vid=vlan_id,
                ethertype=ether_types.ETH_TYPE_ARP
            ))

            reply_pkt.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac="00:00:00:00:fe:fe",  # MAC ficticia del gateway
                src_ip=dst_ip,
                dst_mac=arp_pkt.src_mac,
                dst_ip=src_ip
            ))

            reply_pkt.serialize()

            actions = [parser.OFPActionOutput(msg.match['in_port'])]
            out = parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER,
                in_port=ofp.OFPP_CONTROLLER,
                actions=actions, data=reply_pkt.data)

            dp.send_msg(out)
            self.logger.info("[ARP-GATEWAY] ARP reply enviado.")
            return  # Finaliza tras responder el ARP ficticio

        # Resto del código original de arp_forwarding continúa aquí:
        # 1) ¿Conocemos la ubicación del destino?
        dst_loc = self.arp_handler.get_host_location(dst_ip, vlan_id)
        if dst_loc:
            # Unicast directo
            dst_dpid, out_port, dst_vid = dst_loc
            dp_dst = self.datapaths.get(dst_dpid)
            if not dp_dst:
                return

            # —————— RE-ETIQUETADO VLAN PARA UNICAST ——————
            parser_dst = dp_dst.ofproto_parser
            ofp_dst = dp_dst.ofproto

            # 1) Pop tag original (si existía)
            pkt = packet.Packet(msg.data)
            vlan_hdr = pkt.get_protocol(vlan.vlan)
            actions = []
            if vlan_hdr:
                actions.append(parser_dst.OFPActionPopVlan())

            # 2) Push nuevo tag según la VLAN del host destino
            if dst_vid:
                actions.append(parser_dst.OFPActionPushVlan(
                    ether_types.ETH_TYPE_8021Q))
                actions.append(parser_dst.OFPActionSetField(
                    vlan_vid=(ofp_dst.OFPVID_PRESENT | dst_vid)))

            # 3) Enviar a su puerto de acceso
            actions.append(parser_dst.OFPActionOutput(out_port))

            out = parser_dst.OFPPacketOut(
                datapath=dp_dst,
                buffer_id=ofp_dst.OFP_NO_BUFFER,
                in_port=ofp_dst.OFPP_CONTROLLER,
                data=msg.data,
                actions=actions
            )
            dp_dst.send_msg(out)
            return

        if self.get_vlan_from_ip(src_ip) != self.get_vlan_from_ip(dst_ip):
            self.logger.info(f"[CROSS-ARP] Broadcast VLAN {vlan_id} → {self.get_vlan_from_ip(dst_ip)} "
                            f"para {dst_ip} desde {src_ip}")
            dst_vlan = self.get_vlan_from_ip(dst_ip)

            for dpid, ports in self.arp_handler.access_ports.items():
                for port in ports:
                    key = (dpid, port, dst_vlan)
                    if key in self.arp_handler.access_table:
                        continue  # ya lo enviamos antes

                    dp_iter = self.datapaths.get(dpid)
                    if not dp_iter:
                        continue
                    parser_iter = dp_iter.ofproto_parser
                    ofp_iter = dp_iter.ofproto

                    actions = [parser_iter.OFPActionPopVlan(),
                            parser_iter.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                            parser_iter.OFPActionSetField(
                                vlan_vid=(ofp_iter.OFPVID_PRESENT | dst_vlan)),
                            parser_iter.OFPActionOutput(port)]

                    out = parser_iter.OFPPacketOut(
                        datapath=dp_iter,
                        buffer_id=ofp_iter.OFP_NO_BUFFER,
                        in_port=ofp_iter.OFPP_CONTROLLER,
                        data=msg.data,
                        actions=actions
                    )
                    dp_iter.send_msg(out)
        else:  # Broadcast controlado dentro de VLAN
            self.logger.info(f"[ARP] Broadcast VLAN {vlan_id} para {dst_ip} desde {src_ip}")
            for dpid, ports in self.arp_handler.access_ports.items():
                for port in ports:
                    key = (dpid, port, vlan_id)
                    if key not in self.arp_handler.access_table:
                        dp_iter = self.datapaths.get(dpid)
                        if not dp_iter:
                            continue
                        out = parser.OFPPacketOut(
                            datapath=dp_iter,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            in_port=ofp.OFPP_CONTROLLER,
                            data=msg.data,
                            actions=[parser.OFPActionOutput(port)]
                        )
                        dp_iter.send_msg(out)


    def shortest_forwarding(self, msg, ip_src, ip_dst):
        dp = msg.datapath
        in_port = msg.match['in_port']

        # Determinar switch origen y destino (incluye VLAN)
        res = self.get_sw(dp.id, in_port, ip_src, ip_dst)
        if not res:
            return
        src_sw, dst_sw, out_port = res
            
        # Instalar ruta (ECMP) y reenviar
        port_no = self.arp_handler.set_shortest_path(
            ip_src, ip_dst, src_sw, dst_sw,
            to_port_no=out_port
        )

        self.send_packet_out(dp, msg.buffer_id,
                            in_port, port_no, msg.data)


# ---------------------------------------------------


    def cross_vlan_shortest_forwarding(self, msg, ip_src, ip_dst):
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        self.logger.info(f"[IP-GATEWAY] IP {ip_src} → {ip_dst} en VLAN {self.get_vlan_from_ip(ip_src)}")

        self.logger.info(f"[IP-GATEWAY] Reenviando IP a gateway ficticio {ip_dst}")
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        final_ip_dst = ip_pkt.dst
        dst_vlan = self.get_vlan_from_ip(final_ip_dst)

        dst_loc = self.arp_handler.get_host_location(final_ip_dst, dst_vlan)
        if not dst_loc:
            # Si no conocemos la ubicación, lanzamos un ARP Request desde controlador
            self.logger.info(f"[IP-GATEWAY] Destino {final_ip_dst} desconocido, lanzando ARP Request en VLAN {dst_vlan}")

            arp_req = packet.Packet()
            arp_req.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_8021Q,
                dst="ff:ff:ff:ff:ff:ff",
                src="00:00:00:00:fe:fe"
            ))
            arp_req.add_protocol(vlan.vlan(
                vid=dst_vlan,
                ethertype=ether_types.ETH_TYPE_ARP
            ))
            arp_req.add_protocol(arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac="00:00:00:00:fe:fe",
                src_ip=f"10.0.{dst_vlan}.254",
                dst_mac="00:00:00:00:00:00",
                dst_ip=final_ip_dst
            ))
            arp_req.serialize()

            # Broadcast ARP en la VLAN destino (todos los puertos acceso VLAN destino)
            for dpid, ports in self.arp_handler.access_ports.items():
                for port in ports:
                    key = (dpid, port, dst_vlan)
                    if key not in self.arp_handler.access_table:
                        dp_dst = self.datapaths.get(dpid)
                        if dp_dst:
                            out = dp_dst.ofproto_parser.OFPPacketOut(
                                datapath=dp_dst,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=ofp.OFPP_CONTROLLER,
                                data=arp_req.data,
                                actions=[dp_dst.ofproto_parser.OFPActionOutput(port)]
                            )
                            dp_dst.send_msg(out)
            return  # Esperamos la respuesta ARP antes de continuar

        # Si conocemos la ubicación, reenviamos el paquete IP original:
        dst_dpid, out_port, _ = dst_loc
        dp_dst = self.datapaths.get(dst_dpid)
        if dp_dst:
            actions = [
                dp_dst.ofproto_parser.OFPActionPushVlan(ether_types.ETH_TYPE_8021Q),
                dp_dst.ofproto_parser.OFPActionSetField(vlan_vid=(ofp.OFPVID_PRESENT | dst_vlan)),
                dp_dst.ofproto_parser.OFPActionOutput(out_port)
            ]

            out = dp_dst.ofproto_parser.OFPPacketOut(
                datapath=dp_dst,
                buffer_id=ofp.OFP_NO_BUFFER,
                in_port=ofp.OFPP_CONTROLLER,
                actions=actions,
                data=msg.data
            )

            dp_dst.send_msg(out)
            self.logger.info(f"[IP-GATEWAY] IP reenviado a {final_ip_dst} VLAN {dst_vlan}")
            return

# ---------------------------------------------------

    def get_sw(self, dpid, in_port, src_ip, dst_ip):
        src_vlan = 0
        if self.get_vlan_from_ip(src_ip):
            src_vlan = self.get_vlan_from_ip(src_ip)
         
        src_loc = self.arp_handler.get_host_location(src_ip, self.get_vlan_from_ip(src_ip))
        if in_port in self.arp_handler.access_ports.get(dpid, ()):
            if (dpid, in_port, src_vlan) != src_loc:
                return None
            src_sw = dpid
        else:
            src_sw = dpid

        dst_loc = self.arp_handler.get_host_location(dst_ip, self.get_vlan_from_ip(dst_ip))
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
