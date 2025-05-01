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
from ryu.ofproto import ofproto_v1_3

class NetworkDiscovery(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkDiscovery, self).__init__(*args, **kwargs)
        self.topology_graph = nx.Graph()
    
    def generate_graph_image(self):
        pos = nx.spring_layout(self.topology_graph)  # Posición de los nodos
        plt.figure(figsize=(30, 20))
        
        # Dibujar el grafo
        nx.draw(self.topology_graph, pos, with_labels=True, node_color='lightblue', font_weight='bold', node_size=2000, font_size=10)
        
        # Guardar la imagen
        plt.savefig("/home/alejandro/Desktop/TFG-SDN/topology_graph.png")  # Guardar la imagen en el directorio temporal
        plt.close()

        # self.logger.info("Imagen del grafo guardada como /home/alejandro/Desktop/TFG-SDN/topology_graph.png")
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether.ETH_TYPE_LLDP:
            return  # Ignorar paquetes LLDP ya que se usan solo para descubrimiento

        # self.logger.info("Paquete recibido en switch %s", msg.datapath.id)

    @set_ev_cls(topo_event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        dpid = ev.switch.dp.id
        # self.logger.info("Nuevo switch detectado: %s", dpid)
        self.topology_graph.add_node(dpid, type='switch')
        self.generate_graph_image()

    @set_ev_cls(topo_event.EventSwitchLeave)
    def switch_leave_handler(self, ev):
        dpid = ev.switch.dp.id
        # self.logger.info("Switch eliminado: %s", dpid)
        if dpid in self.topology_graph:
            self.topology_graph.remove_node(dpid)
        self.generate_graph_image()
    
    @set_ev_cls(topo_event.EventLinkAdd)
    def link_add_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        # self.logger.info("Nuevo enlace detectado: %s -> %s", src.dpid, dst.dpid)
        self.topology_graph.add_edge(src.dpid, dst.dpid, port=src.port_no)
        self.generate_graph_image()

    @set_ev_cls(topo_event.EventLinkDelete)
    def link_delete_handler(self, ev):
        src = ev.link.src
        dst = ev.link.dst
        # self.logger.info("Enlace eliminado: %s -> %s", src.dpid, dst.dpid)
        if self.topology_graph.has_edge(src.dpid, dst.dpid):
            self.topology_graph.remove_edge(src.dpid, dst.dpid)
        self.generate_graph_image()
    
    @set_ev_cls(topo_event.EventHostAdd)
    def host_add_handler(self, ev):
        host = ev.host
        mac = host.mac
        dpid = host.port.dpid
        port_no = host.port.port_no

        # self.logger.info("Nuevo host detectado: %s", mac)
        self.topology_graph.add_node(mac, type='host')
        self.topology_graph.add_edge(dpid, mac, port=port_no)
        self.generate_graph_image()

    @set_ev_cls(topo_event.EventHostDelete)
    def host_delete_handler(self, ev):
        host = ev.host
        mac = host.mac
        # self.logger.info("Host eliminado: %s", mac)
        if mac in self.topology_graph:
            self.topology_graph.remove_node(mac)
        self.generate_graph_image()