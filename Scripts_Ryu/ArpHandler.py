from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, vlan
from ryu.topology import api as topo_api
from ryu.topology import event as topo_event
import networkx as nx
import logging
import random

class ArpHandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ArpHandler, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.link_to_port = {}
        # Ahora la tabla mapea (dpid, puerto, vlan_id) -> set de (ip, mac)
        self.access_table = {} # dict[(dpid, port_no, vlan)] = set((ip, mac))
        self.switch_port_table = {}
        self.access_ports = {}
        self.interior_ports = {}
        self.graph = nx.MultiDiGraph()
        self.dps = {}
        self.switches = set()
        self.logger.setLevel(logging.INFO)
        self.ecmp_rr_counters = {}  # (src_dpid, dst_dpid) -> index
        self.edge_rr_counters = {}  # (u, v) -> index

    @set_ev_cls(topo_event.EventSwitchEnter, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventSwitchLeave, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventLinkAdd, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventLinkDelete, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        self.update_topology(ev)
        self.print_graph_links()
        # Mostrar el grafo con Data = True
        # self.logger.info("Graph: %s", self.graph.edges(data=True))

    def update_topology(self, ev):
        if isinstance(ev, topo_event.EventSwitchEnter):
            switch = ev.switch
            dpid = switch.dp.id
            self.dps[dpid] = switch.dp
            self.switches.add(dpid)
            self.switch_port_table[dpid] = {p.port_no for p in switch.ports}
            self.interior_ports[dpid] = set()
            self.access_ports[dpid] = set()
            self.graph.add_node(dpid)

        elif isinstance(ev, topo_event.EventSwitchLeave):
            dpid = ev.switch.dp.id
            self.switches.discard(dpid)
            self.graph.remove_node(dpid)
            self.switch_port_table.pop(dpid, None)
            self.interior_ports.pop(dpid, None)
            self.access_ports.pop(dpid, None)

        elif isinstance(ev, topo_event.EventLinkAdd):
            src = ev.link.src
            dst = ev.link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            self.graph.add_edge(src.dpid, dst.dpid, src_port=src.port_no, dst_port=dst.port_no)
            self.logger.info(f"Link added: {src.dpid} -> {dst.dpid} ({src.port_no}, {dst.port_no})")
            self.interior_ports[src.dpid].add(src.port_no)
            self.interior_ports[dst.dpid].add(dst.port_no)

        elif isinstance(ev, topo_event.EventLinkDelete):
            src = ev.link.src
            dst = ev.link.dst
            self.link_to_port.pop((src.dpid, dst.dpid), None)

            edge_data = self.graph.get_edge_data(src.dpid, dst.dpid)
            if edge_data:
                for key, data in list(edge_data.items()):
                    if data.get('src_port') == src.port_no and data.get('dst_port') == dst.port_no:
                        self.graph.remove_edge(src.dpid, dst.dpid, key)
                        self.logger.info(f"Link deleted: {src.dpid} -> {dst.dpid} ({src.port_no}, {dst.port_no})")
                        break  # ya lo eliminamos, salimos del bucle

            self.interior_ports[src.dpid].discard(src.port_no)
            self.interior_ports[dst.dpid].discard(dst.port_no)

        for sw in self.switches:
            self.access_ports[sw] = self.switch_port_table.get(sw, set()) - self.interior_ports.get(sw, set())

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_type = eth_pkt.ethertype if eth_pkt else None
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        vlan_hdr = pkt.get_protocol(vlan.vlan)
        vid = vlan_hdr.vid if vlan_hdr else 0

        if eth_type == ether_types.ETH_TYPE_LLDP:
            return

        if ip_pkt:
            self.register_access_info(datapath.id, in_port, vid, ip_pkt.src, eth_pkt.src)
        if arp_pkt:
            self.register_access_info(datapath.id, in_port, vid, arp_pkt.src_ip, arp_pkt.src_mac)

    def register_access_info(self, dpid, port_no, vlan_id, ip, mac):
        """Guarda en self.access_table[(dpid,port,vlan_id)] un set de tuplas (ip,mac)."""
        if port_no not in self.access_ports.get(dpid, ()):
            return
        key = (dpid, port_no, vlan_id)
        hostset = self.access_table.setdefault(key, set())
        if (ip, mac) not in hostset:
            hostset.add((ip, mac))
            self.logger.info(f"Nuevo host en {dpid}/{port_no}/VLAN-{vlan_id}: {ip}/{mac}")

    def get_host_location(self, host_ip, vlan_id=None):
        """
        Si vlan_id es None busca en todas; si se da, busca sólo en esa VLAN.
        Devuelve tupla (dpid, puerto, vlan_id) o None.
        """
        for (dpid, port, vid), hosts in self.access_table.items():
            if vlan_id is not None and vid != vlan_id:
                continue
            for ip, mac in hosts:
                if ip == host_ip:
                    return (dpid, port, vid)
        return None

    def get_datapath(self, dpid):
        return self.dps.get(dpid) or topo_api.get_switch(self, dpid)[0].dp

    def set_shortest_path(self, ip_src, ip_dst, src_dpid, dst_dpid,
                          to_port_no, vlan_id=0, pre_actions=[]):
        """
        Instala en los switches el camino más corto (ECMP round-robin) entre
        src_dpid y dst_dpid para el par (ip_src, ip_dst), diferenciando por VLAN.
        Devuelve el puerto de salida en src_dpid por donde enviar el paquete.
        """
        # 1) ¿Hay camino?
        if not nx.has_path(self.graph, src_dpid, dst_dpid):
            self.logger.warning(f"No hay camino {src_dpid}→{dst_dpid}")
            return 0

        # 2) Selección ECMP de la ruta
        all_paths = list(nx.all_shortest_paths(self.graph, src_dpid, dst_dpid))
        key_ecmp = (src_dpid, dst_dpid)
        idx = self.ecmp_rr_counters.get(key_ecmp, 0)
        path = all_paths[idx % len(all_paths)]
        self.ecmp_rr_counters[key_ecmp] = idx + 1

        # 3) Construir el match OF, con o sin VLAN
        dp0 = self.get_datapath(src_dpid)
        parser = dp0.ofproto_parser
        ofp = dp0.ofproto

        if vlan_id and vlan_id != 0:
            # match VLAN-tagged
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                vlan_vid=(ofp.OFPVID_PRESENT | vlan_id),
                ipv4_src=ip_src,
                ipv4_dst=ip_dst
            )
            # antes de enviar al host final haremos pop_vlan()
            pop = parser.OFPActionPopVlan()
        else:
            # match untagged
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst
            )
            pop = None

        # 4) Si es camino de un solo salto (host en el mismo switch)
        if len(path) == 1:
            dp = dp0
            actions = []
            if pop: actions.append(pop)
            actions.append(parser.OFPActionOutput(to_port_no))
            self.add_flow(dp, 10, match, pre_actions + actions)
            return to_port_no

        # 5) Instalar flujos en todos los switches intermedios
        self.install_path(match, path, pre_actions)

        # 6) Instalar flujo en el switch destino (pop_vlan + salida a host)
        dst_dp = self.get_datapath(dst_dpid)
        parser_dst = dst_dp.ofproto_parser
        actions = []
        if pop: actions.append(parser_dst.OFPActionPopVlan())
        actions.append(parser_dst.OFPActionOutput(to_port_no))
        self.add_flow(dst_dp, 10, match, pre_actions + actions)

        # 7) Calcular puerto de salida en el primer switch (src_dpid)
        u, v = path[0], path[1]
        edges = list(self.graph.get_edge_data(u, v).items())
        if not edges:
            self.logger.warning(f"No hay enlace físico {u}→{v}")
            return 0

        key_edge = (u, v, len(edges))
        idx2 = self.edge_rr_counters.get(key_edge, 0)
        sel_edge = edges[idx2 % len(edges)][1]
        if len(edges) > 1:
            self.edge_rr_counters[key_edge] = idx2 + 1

        out_port = sel_edge['src_port']
        self.logger.info(
            f"ECMP enlace {u}→{v} puerto {out_port} "
            f"(opción {idx2 % len(edges)+1}/{len(edges)})"
        )
        return out_port


    def install_path(self, match, path, pre_actions=[]):
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            edge_data = list(self.graph.get_edge_data(u, v).items())
            key = (u, v)
            rr_index = self.edge_rr_counters.get(key, 0)
            edge = edge_data[rr_index % len(edge_data)][1]
            self.edge_rr_counters[key] = rr_index + 1

            port_no = edge['src_port']
            dp = self.get_datapath(u)
            actions = [dp.ofproto_parser.OFPActionOutput(port_no)]
            self.add_flow(dp, 10, match, pre_actions + actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=10, hard_timeout=5):
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def print_graph_links(self):
        self.logger.info("==== ENLACES ACTUALES EN EL GRAFO ====")
        for u, v, k, data in self.graph.edges(data=True, keys=True):
            self.logger.info(f"{u} -> {v} | key={k} | src_port={data['src_port']} dst_port={data['dst_port']}")
        self.logger.info("========================================")