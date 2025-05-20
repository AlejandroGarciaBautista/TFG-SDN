from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
from ryu.base.app_manager import lookup_service_brick

from utils import is_connection_allowed, get_vlan_from_ip

class RoutingManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RoutingManager, self).__init__(*args, **kwargs)
        self.topology_manager = lookup_service_brick('TopologyManager')
        self.datapaths = {}
        self.gateway_mac = "02:00:00:00:00:FE"

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
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP: # Ignorar LLDP
            return

        if ip_pkt and ip_pkt.dst == '224.0.0.22': # Ingnorar IGMPv3 membership reports
            return

        if arp_pkt: # Resolución ARP
            self.arp_reply(msg, arp_pkt.src_ip, arp_pkt.dst_ip)

        if ip_pkt and is_connection_allowed(ip_pkt.src, ip_pkt.dst): # Resolución IP 
            self.shortest_forwarding(msg, eth_pkt.ethertype, ip_pkt.src, ip_pkt.dst)

    def arp_reply(self, msg, src_ip, dst_ip):
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']

        if dst_ip.endswith('.254'): # Resolvemos si la petición es para la puerta de enlace
            dst_mac = self.gateway_mac          
        else: # En el caso de que no sea la puerta de enlace, se busca en la tabla hosts del controlador para que sea esta quien responda
            if dst_ip not in self.topology_manager.hosts:
                return
            _, _, _, dst_mac = self.topology_manager.hosts[dst_ip]

        # Construir ARP_REPLY
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_reply = packet.Packet()

        arp_reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=eth_pkt.src,
            src=dst_mac))
        
        arp_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=dst_mac,
            src_ip=dst_ip,
            dst_mac=eth_pkt.src,
            dst_ip=src_ip))
        
        arp_reply.serialize()

        # Enviar el reply de vuelta al puerto de origen
        out = parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=arp_reply.data)
        dp.send_msg(out)

    def shortest_forwarding(self, msg, eth_type, ip_src, ip_dst):
        datapath = msg.datapath
        in_port = msg.match['in_port']
        result = self.get_sw(datapath.id, in_port, ip_src, ip_dst)
        pre_actions = []
        same_vlan = get_vlan_from_ip(ip_src) == get_vlan_from_ip(ip_dst)

        if result:
            src_sw, dst_sw, to_dst_port = result

            if dst_sw:

                if not same_vlan:
                    dst_mac = self.topology_manager.hosts[ip_dst][3]
                    gw_mac = self.gateway_mac

                    parser = datapath.ofproto_parser
                    pre_actions = [
                        parser.OFPActionSetField(eth_src=gw_mac),
                        parser.OFPActionSetField(eth_dst=dst_mac)
                    ]

                match = datapath.ofproto_parser.OFPMatch(
                    eth_type=eth_type, ipv4_dst=ip_dst)
                
                port_no = self.topology_manager.set_shortest_path(
                    ip_src, ip_dst, src_sw, dst_sw, to_dst_port, match, pre_actions)
                
                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=[datapath.ofproto_parser.OFPActionOutput(port_no)],
                    data=msg.data)

                datapath.send_msg(out)

    def get_sw(self, dpid, in_port, src, dst):
        src_location = self.topology_manager.get_host_location(src)
        if in_port in self.topology_manager.access_ports[dpid]:
            if (dpid, in_port) == src_location:
                src_sw = dpid
            else:
                return None
        else:
            src_sw = dpid

        dst_location = self.topology_manager.get_host_location(dst)
        if dst_location:
            return src_sw, dst_location[0], dst_location[1]
        return None
