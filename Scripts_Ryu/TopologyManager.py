from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp
from ryu.topology import api as topo_api
from ryu.topology import event as topo_event
import networkx as nx
from utils import get_vlan_from_ip

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response


class TopologyManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # Contexto para levantar el servidor REST
    _CONTEXTS = { 'wsgi': WSGIApplication }

    def __init__(self, *args, **kwargs):        
        super(TopologyManager, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(RESTController, { 'TopologyManager': self })

        self.topology_api_app = self
        self.link_to_port = {}
        self.access_table = {} 
        self.hosts = {} # { ip: (dpid, port, vlan, mac) }
        self.switch_port_table = {}
        self.access_ports = {}
        self.interior_ports = {}
        self.graph = nx.MultiDiGraph()
        self.dps = {}
        self.switches = set()
        # self.logger.setLevel(logging.INFO)
        self.ecmp_rr_counters = {}  # (src_dpid, dst_dpid) -> index
        self.edge_rr_counters = {}  # (u, v) -> index

    @set_ev_cls(topo_event.EventSwitchEnter, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventSwitchLeave, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventLinkAdd, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventLinkDelete, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        self.update_topology(ev)

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
                        break

            self.interior_ports[src.dpid].discard(src.port_no)
            self.interior_ports[dst.dpid].discard(dst.port_no)

        for sw in self.switches:
            self.access_ports[sw] = self.switch_port_table.get(sw, set()) - self.interior_ports.get(sw, set())


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_type = eth_pkt.ethertype if eth_pkt else None
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth_type == ether_types.ETH_TYPE_LLDP: # Ignorar LLDP
            return

        if ip_pkt and ip_pkt.dst == '224.0.0.22': # Ingnorar IGMPv3 membership reports
            return


    def register_access_info(self, dpid, in_port, ip, mac):
        vlan = get_vlan_from_ip(ip)
        
        if vlan is None:
            return

        self.hosts[ip] = (dpid, in_port, vlan, mac)


    def get_host_location(self, host_ip):
        vlan = get_vlan_from_ip(host_ip)
        
        if vlan is None:
            return

        info = self.hosts.get(host_ip)

        if not info:
            return None
        
        dpid, port, _, _ = info
        return (dpid, port)


    def get_datapath(self, dpid):
        return self.dps.get(dpid) or topo_api.get_switch(self, dpid)[0].dp


    def set_shortest_path(self, ip_src, ip_dst, src_dpid, dst_dpid, to_port_no, to_dst_match, pre_actions=[]):
        if not nx.has_path(self.graph, src_dpid, dst_dpid):
            return 0

        all_paths = list(nx.all_shortest_paths(self.graph, src_dpid, dst_dpid))

        key = (src_dpid, dst_dpid)
        rr_index = self.ecmp_rr_counters.get(key, 0)
        selected_path = all_paths[rr_index % len(all_paths)]
        self.ecmp_rr_counters[key] = (rr_index + 1)

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

            u, v = selected_path[0], selected_path[1]
            edges_data = list(self.graph.get_edge_data(u, v).items())

            # Si no hay enlaces, retorna 0 (esto no debería pasar en caminos válidos)
            if not edges_data:
                self.logger.warning(f"No hay enlaces físicos entre {u} y {v}")
                return 0

            # Usamos una clave que también incluye el número total de enlaces posibles
            key = (u, v, len(edges_data))  # diferencia enlaces cambiantes
            rr_index = self.edge_rr_counters.get(key, 0)
            selected_edge = edges_data[rr_index % len(edges_data)][1]

            # Actualizamos el índice RR solo si hay más de un enlace
            if len(edges_data) > 1:
                self.edge_rr_counters[key] = rr_index + 1

            # self.logger.info(f"Usando enlace {u} -> {v} por puerto {selected_edge['src_port']} (opción {rr_index % len(edges_data) + 1} de {len(edges_data)})")
            return selected_edge['src_port']


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


    def add_flow(self, dp, p, match, actions, idle_timeout=15, hard_timeout=150):
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




class RESTController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RESTController, self).__init__(req, link, data, **config)
        self.TopologyManager = data['TopologyManager']

    @route('arp', '/hosts', methods=['POST'])
    def add_host(self, req, **kwargs):
        """
        Espera un JSON con campos:
            { dpid: int, in_port: int, ip: str, mac: str }
        y llama a register_access_info.
        """
        body = req.json if req.body else {}
        dpid    = body.get('dpid')
        port    = body.get('in_port')
        ip_addr = body.get('ip')
        mac     = body.get('mac')
        if None in (dpid, port, ip_addr, mac):
            return Response(status=400, body='Missing fields')
        # Llamamos al método que ya tienes implementado
        self.TopologyManager.register_access_info(dpid, port, ip_addr, mac)
        return Response(status=200)
    