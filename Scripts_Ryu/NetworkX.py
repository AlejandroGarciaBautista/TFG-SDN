from ryu.base import app_manager
from ryu.controller import event, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.topology import event as topo_event
from ryu.topology.api import get_switch, get_link, get_host
import networkx as nx
from ryu.lib.packet import packet, ethernet, lldp
from ryu.ofproto import ether
import matplotlib.pyplot as plt

class NetworkDiscovery(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(NetworkDiscovery, self).__init__(*args, **kwargs)
        self.topology_graph = nx.Graph()
        self.monitor_thread = hub.spawn(self._monitor_topology)
    
    def generate_graph_image(self):
        pos = nx.spring_layout(self.topology_graph)  # Posición de los nodos
        plt.figure(figsize=(10, 10))
        
        # Dibujar el grafo
        nx.draw(self.topology_graph, pos, with_labels=True, node_color='lightblue', font_weight='bold', node_size=2000, font_size=10)
        
        # Guardar la imagen
        plt.savefig("/home/alejandro/Desktop/TFG-SDN/topology_graph.png")  # Guardar la imagen en el directorio temporal
        plt.close()

        self.logger.info("Imagen del grafo guardada como /home/alejandro/Desktop/TFG-SDN/topology_graph.png")

    def _monitor_topology(self):
        while True:
            self._discover_topology()
            self.generate_graph_image()  # Generar la imagen cada vez que se actualiza la topología
            hub.sleep(10)  # Monitoreo cada 10 segundos
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether.ETH_TYPE_LLDP:
            return  # Ignorar paquetes LLDP ya que se usan solo para descubrimiento

        self.logger.info("Paquete recibido en switch %s", msg.datapath.id)

    def _discover_topology(self):
        self.topology_graph.clear()
        switches = get_switch(self)
        links = get_link(self)
        hosts = get_host(self)
        
        # LOGS PARA DEPURACIÓN
        # self.logger.info("Switches detectados: %s", [s.dp.id for s in switches])
        self.logger.info("Switches detectados:")
        for switch in switches:
            mac_addresses = [port.hw_addr for port in switch.ports]
            self.logger.info("  Switch %s - MACs: %s", switch.dp.id, mac_addresses)
        
        self.logger.info("Enlaces detectados: %s", [(l.src.dpid, l.dst.dpid) for l in links])
        self.logger.info("Hosts detectados: %s", [h.mac for h in hosts])

        for switch in switches:
            self.topology_graph.add_node(switch.dp.id, type='switch')
        
        for link in links:
            self.topology_graph.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        for host in hosts:
            self.topology_graph.add_node(host.mac, type='host')
            self.topology_graph.add_edge(host.port.dpid, host.mac, port=host.port.port_no)
        
        self.logger.info("Topología descubierta: %s", self.topology_graph.edges)

    @set_ev_cls(topo_event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        for switch in get_switch(self):
            for port in switch.ports:
                self.logger.info("Enviando LLDP a switch %s puerto %s", switch.dp.id, port.port_no)
                datapath = switch.dp
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                actions = [parser.OFPActionOutput(port.port_no)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=None)
                datapath.send_msg(out)

        self.logger.info("Nuevo switch detectado: %s", ev.switch.dp.id)
        self._discover_topology()

    @set_ev_cls(topo_event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        self.logger.info("Switch eliminado: %s", ev.switch.dp.id)
        self._discover_topology()
    
    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self, ev):
        self.logger.info("Nuevo enlace detectado: %s -> %s", ev.link.src.dpid, ev.link.dst.dpid)
        self._discover_topology()

    @set_ev_cls(topo_event.EventLinkDelete)
    def link_delete_handler(self, ev):
        self.logger.info("Enlace eliminado: %s -> %s", ev.link.src.dpid, ev.link.dst.dpid)
        self._discover_topology()
    
    @set_ev_cls(topo_event.EventHostAdd)
    def host_add_handler(self, ev):
        self.logger.info("Nuevo host detectado: %s", ev.host.mac)
        self._discover_topology()
