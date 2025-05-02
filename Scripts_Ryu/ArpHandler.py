''' 
Módulo: arp_handler_comentado.py
Descripción:
Implementación de un manejador ARP con Ryu:
- Descubre la topología de red (switches y enlaces).
- Mantiene tablas de acceso de hosts por puerto y VLAN.
- Instala flujos ECMP para enrutar tráfico IP entre hosts.
'''

from ryu.base import app_manager  # Clase base para aplicaciones Ryu
from ryu.controller import ofp_event  # Eventos OpenFlow
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls  # Estados y decoradores de eventos
from ryu.ofproto import ofproto_v1_3  # Protocolo OpenFlow 1.3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, vlan  # Librería de parseo de paquetes
from ryu.topology import api as topo_api  # API de topología de Ryu
from ryu.topology import event as topo_event  # Eventos de topología (switch enter/leave, link add/delete)
import networkx as nx  # Estructuras de grafo para rutas
import logging  # Para registro de logs


class ArpHandler(app_manager.RyuApp):
    '''
    Clase principal de la aplicación Ryu para manejar ARP y establecer rutas ECMP.
    '''
    # Se indica la versión de OpenFlow soportada
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        # Llamada al constructor de la clase padre
        super(ArpHandler, self).__init__(*args, **kwargs)
        # Permite usar la API de topología en esta misma aplicación
        self.topology_api_app = self
        # Mapa de enlaces físicos: (dpid_origen, dpid_destino) -> (puerto_origen, puerto_destino)
        self.link_to_port = {}
        # Tabla de acceso de hosts: (dpid, port_no, vlan_id) -> set de (ip, mac)
        self.access_table = {}
        # Tabla de puertos de cada switch
        self.switch_port_table = {}
        # Conjuntos de puertos de acceso e interiores (uplinks)
        self.access_ports = {}
        self.interior_ports = {}
        # Grafo de la topología: nodos=dpid de switches, aristas=enlaces
        self.graph = nx.MultiDiGraph()
        # Diccionario de datapaths (dpid -> objeto datapath)
        self.dps = {}
        # Conjunto de dpids activos
        self.switches = set()
        # Nivel de registro de logs
        self.logger.setLevel(logging.INFO)
        # Contadores round-robin para ECMP: (src_dpid, dst_dpid) -> índice de camino
        self.ecmp_rr_counters = {}
        # Contadores round-robin por enlace: (u, v) -> índice de enlace
        self.edge_rr_counters = {}

    @set_ev_cls(topo_event.EventSwitchEnter, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventSwitchLeave, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventLinkAdd, MAIN_DISPATCHER)
    @set_ev_cls(topo_event.EventLinkDelete, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        '''
        Manejador para eventos de cambio de topología:
        switch entra/sale, enlace añade/elimina.
        '''
        self.update_topology(ev)

    def update_topology(self, ev):
        '''
        Actualiza las estructuras internas al producirse cambios en la topología.
        '''
        # Evento: switch se conecta a la red
        if isinstance(ev, topo_event.EventSwitchEnter):
            switch = ev.switch
            dpid = switch.dp.id
            # Guardar datapath y dpid
            self.dps[dpid] = switch.dp
            self.switches.add(dpid)
            # Obtener todos los puertos del switch
            self.switch_port_table[dpid] = {p.port_no for p in switch.ports}
            # Inicializar conjuntos de puertos interiores y de acceso
            self.interior_ports[dpid] = set()
            self.access_ports[dpid] = set()
            # Añadir nodo al grafo
            self.graph.add_node(dpid)

        # Evento: switch se desconecta
        elif isinstance(ev, topo_event.EventSwitchLeave):
            dpid = ev.switch.dp.id
            self.switches.discard(dpid)
            self.graph.remove_node(dpid)
            # Limpiar tablas relacionadas
            self.switch_port_table.pop(dpid, None)
            self.interior_ports.pop(dpid, None)
            self.access_ports.pop(dpid, None)

        # Evento: nuevo enlace entre switches
        elif isinstance(ev, topo_event.EventLinkAdd):
            src = ev.link.src
            dst = ev.link.dst
            # Mapear puertos físicos del enlace
            self.link_to_port[(src.dpid, dst.dpid)] = (src.port_no, dst.port_no)
            # Añadir arista al grafo con atributos de puertos
            self.graph.add_edge(src.dpid, dst.dpid,
                                src_port=src.port_no, dst_port=dst.port_no)
            # Marcar puertos como enlaces interiores
            self.interior_ports[src.dpid].add(src.port_no)
            self.interior_ports[dst.dpid].add(dst.port_no)

        # Evento: enlace eliminado
        elif isinstance(ev, topo_event.EventLinkDelete):
            src = ev.link.src
            dst = ev.link.dst
            # Eliminar mapeo de puertos
            self.link_to_port.pop((src.dpid, dst.dpid), None)
            # Eliminar arista del grafo
            edge_data = self.graph.get_edge_data(src.dpid, dst.dpid)
            if edge_data:
                for key, data in list(edge_data.items()):
                    if data.get('src_port') == src.port_no and \
                       data.get('dst_port') == dst.port_no:
                        self.graph.remove_edge(src.dpid, dst.dpid, key)
                        break
            # Quitar puertos de la lista de interiores
            self.interior_ports[src.dpid].discard(src.port_no)
            self.interior_ports[dst.dpid].discard(dst.port_no)

        # Calcular puertos de acceso: puertos físicos menos puertos interiores
        for sw in self.switches:
            self.access_ports[sw] = (
                self.switch_port_table.get(sw, set()) - 
                self.interior_ports.get(sw, set())
            )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        '''
        Manejador de paquetes entrantes (PacketIn).
        Registra información de accesos y procesa ARP/IP.
        '''
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        # Parsear el paquete completo
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        eth_type = eth_pkt.ethertype if eth_pkt else None
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        # Obtener VLAN si existe
        vlan_hdr = pkt.get_protocol(vlan.vlan)
        vid = vlan_hdr.vid if vlan_hdr else 0

        # Ignorar LLDP (usado para descubrimiento de topología)
        if eth_type == ether_types.ETH_TYPE_LLDP:
            return

        # Si es paquete IP, registrar tupla (ip, mac) en tabla de acceso
        if ip_pkt:
            self.register_access_info(
                datapath.id, in_port, vid, ip_pkt.src, eth_pkt.src)
        # Si es paquete ARP, registrar información ARP
        if arp_pkt:
            self.register_access_info(
                datapath.id, in_port, vid, arp_pkt.src_ip, arp_pkt.src_mac)

    def register_access_info(self, dpid, port_no, vlan_id, ip, mac):
        '''
        Almacena en self.access_table[(dpid, port_no, vlan_id)] un set de hosts.
        Sólo si el puerto es de acceso.
        '''
        # Verificar que el puerto sea de acceso (no interior)
        if port_no not in self.access_ports.get(dpid, ()): 
            return
        key = (dpid, port_no, vlan_id)
        hostset = self.access_table.setdefault(key, set())
        # Si es un nuevo host, añadirlo
        if (ip, mac) not in hostset:
            hostset.add((ip, mac))
            # self.logger.info(f"Nuevo host en {dpid}/{port_no}/VLAN-{vlan_id}: {ip}/{mac}")

    def get_host_location(self, host_ip, vlan_id=None):
        '''
        Devuelve la localización (dpid, puerto, vlan) de un host por IP.
        Si vlan_id es None busca en todas, sino filtra por VLAN.
        '''
        for (dpid, port, vid), hosts in self.access_table.items():
            if vlan_id is not None and vid != vlan_id:
                continue
            for ip, mac in hosts:
                if ip == host_ip:
                    return (dpid, port, vid)
        return None

    def get_datapath(self, dpid):
        '''
        Devuelve el objeto datapath para un dpid dado.
        '''
        return (self.dps.get(dpid) 
                or topo_api.get_switch(self, dpid)[0].dp)

    def set_shortest_path(self, ip_src, ip_dst, src_dpid, dst_dpid,
                          to_port_no, vlan_id=0, pre_actions=[]):
        '''
        Instala flujos a lo largo del camino más corto (ECMP)
        entre src_dpid y dst_dpid para el par (ip_src, ip_dst).
        No se elimina la etiqueta VLAN (pop_vlan).
        Devuelve el puerto de salida en src_dpid.
        '''
        # 1) Comprobar si existe ruta
        if not nx.has_path(self.graph, src_dpid, dst_dpid):
            self.logger.warning(f"No hay camino {src_dpid}→{dst_dpid}")
            return 0

        # 2) Selección de uno de los caminos más cortos (ECMP round-robin)
        all_paths = list(nx.all_shortest_paths(self.graph, src_dpid, dst_dpid))
        key_ecmp = (src_dpid, dst_dpid)
        idx = self.ecmp_rr_counters.get(key_ecmp, 0)
        path = all_paths[idx % len(all_paths)]
        self.ecmp_rr_counters[key_ecmp] = idx + 1

        # 3) Construir el match de OpenFlow con o sin VLAN
        dp0 = self.get_datapath(src_dpid)
        parser = dp0.ofproto_parser
        ofp = dp0.ofproto

        if vlan_id:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                vlan_vid=(ofp.OFPVID_PRESENT | vlan_id),
                ipv4_src=ip_src,
                ipv4_dst=ip_dst
            )
        else:
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip_src,
                ipv4_dst=ip_dst
            )

        # 4) Si origen y destino están en el mismo switch, flujo directo
        if len(path) == 1:
            actions = pre_actions + [parser.OFPActionOutput(to_port_no)]
            self.add_flow(dp0, 10, match, actions)
            return to_port_no

        # 5) Instalar flujos en todos los switches intermedios
        self.install_path(match, path, pre_actions)

        # 6) Instalar flujo en el switch destino
        dst_dp = self.get_datapath(dst_dpid)
        parser_dst = dst_dp.ofproto_parser
        actions = pre_actions + [parser_dst.OFPActionOutput(to_port_no)]
        self.add_flow(dst_dp, 10, match, actions)

        # 7) Calcular puerto de salida en el primer salto (round-robin si hay múltiples enlaces)
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
        '''
        Instala flujos a lo largo de un camino dado en la topología.
        '''
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            # Obtener datos de todos los enlaces entre u y v
            edge_data = list(self.graph.get_edge_data(u, v).items())
            key = (u, v)
            rr_index = self.edge_rr_counters.get(key, 0)
            # Selección round-robin de enlace
            edge = edge_data[rr_index % len(edge_data)][1]
            self.edge_rr_counters[key] = rr_index + 1

            port_no = edge['src_port']
            dp = self.get_datapath(u)
            actions = [dp.ofproto_parser.OFPActionOutput(port_no)]
            # Añadir flujo con las acciones acumuladas
            self.add_flow(dp, 10, match, pre_actions + actions)

    def add_flow(self, dp, priority, match, actions,
                 idle_timeout=10, hard_timeout=5):
        '''
        Crea y envía un mensaje FlowMod para añadir un flujo al switch.
        '''
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        # Instrucción para aplicar acciones
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # Configurar el mod de flujo
        mod = parser.OFPFlowMod(
            datapath=dp,
            priority=priority,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            match=match,
            instructions=inst
        )
        # Enviar mensaje al switch
        dp.send_msg(mod)

    def print_graph_links(self):
        '''
        Imprime en log todos los enlaces actuales del grafo de topología.
        '''
        self.logger.info("==== ENLACES ACTUALES EN EL GRAFO ====")
        for u, v, key, data in self.graph.edges(data=True, keys=True):
            self.logger.info(
                f"{u} -> {v} | key={key} | src_port={data['src_port']} "
                f"dst_port={data['dst_port']}"
            )
        self.logger.info("========================================")
