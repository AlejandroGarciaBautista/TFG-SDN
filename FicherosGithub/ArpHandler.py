from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp
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
        self.access_table = {}
        self.switch_port_table = {}
        self.access_ports = {}
        self.interior_ports = {}
        self.graph = nx.DiGraph()
        self.dps = {}
        self.switches = set()
        self.logger.setLevel(logging.INFO)
        self.ecmp_rr_counters = {}  # (src_dpid, dst_dpid) -> index

    @set_ev_cls(topo_event.EventSwitchEnter, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventSwitchLeave, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventLinkAdd, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventLinkDelete, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        self.logger.info(f"Topología actualizada por evento: {type(ev).__name__}")
        self.update_topology(ev)
        # self.print_topology_state()

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
            self.logger.info(f"Switch añadido: {dpid}")

        elif isinstance(ev, topo_event.EventSwitchLeave):
            dpid = ev.switch.dp.id
            self.switches.discard(dpid)
            self.graph.remove_node(dpid)
            self.switch_port_table.pop(dpid, None)
            self.interior_ports.pop(dpid, None)
            self.access_ports.pop(dpid, None)
            self.logger.info(f"Switch eliminado: {dpid}")

        elif isinstance(ev, topo_event.EventLinkAdd):
            src = ev.link.src
            dst = ev.link.dst
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            self.graph.add_edge(src.dpid, dst.dpid, src_port=src.port_no, dst_port=dst.port_no)
            self.interior_ports[src.dpid].add(src.port_no)
            self.interior_ports[dst.dpid].add(dst.port_no)
            self.logger.info(f"Enlace añadido: {src.dpid}:{src.port_no} -> {dst.dpid}:{dst.port_no}")

        elif isinstance(ev, topo_event.EventLinkDelete):
            src = ev.link.src
            dst = ev.link.dst
            self.link_to_port.pop((src.dpid, dst.dpid), None)
            if self.graph.has_edge(src.dpid, dst.dpid):
                self.graph.remove_edge(src.dpid, dst.dpid)
            self.interior_ports[src.dpid].discard(src.port_no)
            self.interior_ports[dst.dpid].discard(dst.port_no)
            self.logger.info(f"Enlace eliminado: {src.dpid} -> {dst.dpid}")

        # Actualizar puertos de acceso tras cada cambio
        for sw in self.switches:
            self.access_ports[sw] = self.switch_port_table.get(sw, set()) - self.interior_ports.get(sw, set())

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_type = eth_pkt.ethertype if eth_pkt else None
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth_type == ether_types.ETH_TYPE_LLDP:
            return

        if ip_pkt:
            src_ipv4 = ip_pkt.src
            src_mac = eth_pkt.src
            if src_ipv4 not in ('0.0.0.0', '255.255.255.255'):
                self.register_access_info(datapath.id, in_port, src_ipv4, src_mac)

        if arp_pkt:
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip
            mac = arp_pkt.src_mac
            self.register_access_info(datapath.id, in_port, arp_src_ip, mac)

    def register_access_info(self, dpid, in_port, ip, mac):
        if in_port in self.access_ports.get(dpid, set()):
            current = self.access_table.get((dpid, in_port))
            if current != (ip, mac):
                self.access_table[(dpid, in_port)] = (ip, mac)

    def get_host_location(self, host_ip):
        for (dpid, port), (ip, _) in self.access_table.items():
            if ip == host_ip:
                return (dpid, port)
        self.logger.debug(f"{host_ip} location not found.")
        return None

    def get_datapath(self, dpid):
        if dpid not in self.dps:
            switch = topo_api.get_switch(self, dpid)[0]
            self.dps[dpid] = switch.dp
            return switch.dp
        return self.dps[dpid]

    def set_shortest_path(self, ip_src, ip_dst, src_dpid, dst_dpid, to_port_no, to_dst_match, pre_actions=[]):
        if not nx.has_path(self.graph, src_dpid, dst_dpid):
            self.logger.info("No hay camino entre los switches.")
            return 0

        all_paths = list(nx.all_shortest_paths(self.graph, src_dpid, dst_dpid))
        if not all_paths:
            self.logger.info("No se encontraron caminos de igual coste.")
            return 0

        # Identificador único para el par origen-destino
        key = (src_dpid, dst_dpid)
        rr_index = self.ecmp_rr_counters.get(key, 0)
        selected_path = all_paths[rr_index % len(all_paths)]
        self.ecmp_rr_counters[key] = (rr_index + 1)  # Round-robin para la próxima vez

        self.logger.info(f"ECMP entre {src_dpid} y {dst_dpid}. Caminos posibles: {len(all_paths)}. Usando el camino: {selected_path}")

        if len(selected_path) == 1:
            dp = self.get_datapath(src_dpid)
            actions = [dp.ofproto_parser.OFPActionOutput(to_port_no)]
            self.add_flow(dp, 10, to_dst_match, pre_actions + actions)
            return to_port_no
        else:
            self.install_path(to_dst_match, selected_path, pre_actions)
            dst_dp = self.get_datapath(dst_dpid)
            actions = [dst_dp.ofproto_parser.OFPActionOutput(to_port_no)]
            self.add_flow(dst_dp, 10, to_dst_match, pre_actions + actions)
            return self.graph[selected_path[0]][selected_path[1]]['src_port']


    def install_path(self, match, path, pre_actions=[]):
        for index, dpid in enumerate(path[:-1]):
            port_no = self.graph[path[index]][path[index + 1]]['src_port']
            dp = self.get_datapath(dpid)
            actions = [dp.ofproto_parser.OFPActionOutput(port_no)]
            self.add_flow(dp, 10, match, pre_actions + actions)

    def add_flow(self, dp, p, match, actions, idle_timeout=60, hard_timeout=0):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=p,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)

    def print_topology_state(self):
        self.logger.info("----- ESTADO ACTUAL DE LA TOPOLOGÍA -----")
        self.logger.info(f"Switches/nodos: {list(self.graph.nodes)}")
        self.logger.info("Enlaces:")
        for u, v in self.graph.edges:
            src_port = self.graph[u][v]['src_port']
            dst_port = self.graph[u][v]['dst_port']
            self.logger.info(f"  {u}:{src_port} --> {v}:{dst_port}")
        self.logger.info("Puertos de acceso:")
        for dpid in self.access_ports:
            self.logger.info(f"  Switch {dpid}: {sorted(self.access_ports[dpid])}")
        self.logger.info("-----------------------------------------")
