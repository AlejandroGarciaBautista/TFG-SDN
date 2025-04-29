#!/usr/bin/env python3
import argparse
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Simulación de una arquitectura Spine-Leaf en Mininet con VLANs taggeadas y OpenFlow"
    )
    parser.add_argument("--spine", type=int, default=2,
                        help="Número de switches spine (por defecto: 2)")
    parser.add_argument("--leaf", type=int, default=4,
                        help="Número de switches leaf (por defecto: 4)")
    parser.add_argument("--hosts", type=int, default=12,
                        help="Hosts por switch leaf (por defecto: 12)")
    parser.add_argument("--bw", type=int, default=1000,
                        help="BW de enlaces Spine-Leaf en Mbps (por defecto: 1000)")
    parser.add_argument("--rd", dest="rd", action="store_true",
                        help="Aplicar redundancia en enlaces Spine-Leaf")
    parser.add_argument("--no-rd", dest="rd", action="store_false",
                        help="Sin redundancia en enlaces Spine-Leaf")
    parser.set_defaults(rd=True)
    parser.add_argument("-c", type=str, default="192.168.56.101",
                        help="IP del controlador SDN (por defecto: 192.168.56.101)")
    return parser.parse_args()


def create_spine_leaf_topology(spine_count, leaf_count, hosts_per_leaf,
                               link_bw, redundancy, controller_ip):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)

    # Controlador remoto OpenFlow13
    net.addController('c0', controller=RemoteController,
                      ip=controller_ip, port=6633,
                      protocols='OpenFlow13')

    # Crear switches Spine y Leaf con OF1.3
    spines = [net.addSwitch(f"spine{i+1}",
                 dpid=f"{10000000000+i+1:016x}", protocols='OpenFlow13')
              for i in range(spine_count)]
    leaves = [net.addSwitch(f"leaf{i+1}",
                 dpid=f"{20000000000+i+1:016x}", protocols='OpenFlow13')
              for i in range(leaf_count)]

    # Conectar Spine-Leaf con TCLink y HTB
    for leaf in leaves:
        for spine in spines:
            net.addLink(leaf, spine, cls=TCLink, bw=link_bw, htb=True)
            if redundancy:
                net.addLink(leaf, spine, cls=TCLink, bw=link_bw, htb=True)

    # Calcular BW Leaf-Host (max 1000)
    uplinks = spine_count * (2 if redundancy else 1)
    bw_leaf2host = min((3 * uplinks * link_bw) / hosts_per_leaf, 1000)

    # Agregar hosts y enlaces Leaf-Host
    host_idx = 1
    for leaf in leaves:
        for _ in range(hosts_per_leaf):
            host = net.addHost(f"h{host_idx}")
            net.addLink(host, leaf, cls=TCLink,
                        bw=bw_leaf2host, htb=True)
            host_idx += 1

    # Iniciar la red antes de la configuración VLAN
    net.start()

    # Mapeo de hosts con VLANs y sus IPs
    hosts_vlan = {
        'h1':  {100: '10.0.100.1/24', 200: '10.0.200.1/24'},
        'h20': {100: '10.0.100.2/24', 200: '10.0.200.2/24'}
    }

    # Configurar subinterfaces VLAN y trunks en los switches
    for hname, vlan_info in hosts_vlan.items():
        host = net.get(hname)
        base_intf = host.intfNames()[0]  # ej. 'h1-eth0'

        # Crear y levantar subinterfaces VLAN
        for vid, ip in vlan_info.items():
            subintf = f"{base_intf}.{vid}"
            host.cmd(f"ip link add link {base_intf} name {subintf} type vlan id {vid}")
            host.cmd(f"ip addr add {ip} dev {subintf}")
            host.cmd(f"ip link set dev {subintf} up")
        host.cmd(f"ip link set dev {base_intf} up")

        # Encontrar el switch al otro extremo de forma segura
        link = None
        for sw in net.switches:
            conns = host.connectionsTo(sw)
            if conns:
                link = conns[0]
                break
        if not link:
            raise RuntimeError(f"No se encontró conexión entre {hname} y ningún switch")
        sw = link[1].node
        sw_intf = link[1].name

        # Aplicar trunks permitidas
        vids = ",".join(str(v) for v in vlan_info)
        sw.cmd(f"ovs-vsctl set port {sw_intf} trunks={vids}")

    # Lanzar CLI para interacción y luego detener
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    args = parse_arguments()
    create_spine_leaf_topology(args.spine, args.leaf,
                               args.hosts, args.bw,
                               args.rd, args.c)
