import argparse
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def parse_arguments():
    parser = argparse.ArgumentParser(description="Simulación de una arquitectura Spine-Leaf en Mininet.")

    parser.add_argument("--spine", type=int, default=2, help="Cantidad de switches spine (por defecto: 2)")
    parser.add_argument("--leaf", type=int, default=4, help="Cantidad de switches leaf (por defecto: 4)")
    parser.add_argument("--hosts", type=int, default=12, help="Cantidad de hosts por switch leaf (por defecto: 2)")
    parser.add_argument("--bw", type=int, default=1000, help="Capacidad de los enlaces Uplink en Mbps (por defecto: 1000 (máximo permitido))")
    parser.add_argument("-c", type=str, default="192.168.56.101", help="Dirección IP del controlador SDN (por defecto: 192.168.56.101)")

    parser.add_argument("--rd", dest='rd', action='store_true', help="Aplicar Redundancia en la red")
    parser.add_argument("--no-rd", dest='rd', action='store_false', help="No aplicar Redundancia en la red")

    parser.set_defaults(rd=True)

    return parser.parse_args()

def create_spine_leaf_topology(spine_switches, leaf_switches, hosts_per_leaf, link_bandwidth, redundancy, controller_ip):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)
    
    # Agregar el controlador remoto
    c0 = net.addController('c0', controller=RemoteController, ip=controller_ip, port=6633, protocols="OpenFlow13")

    # Crear switches spine y leaf con nombres más claros
    spines = [net.addSwitch(f"spine{i+1}", dpid=f"{10000000000 + i+1:016x}", protocols="OpenFlow13") for i in range(spine_switches)]
    leaves = [net.addSwitch(f"leaf{i+1}", dpid=f"{20000000000 + i+1:016x}", protocols="OpenFlow13") for i in range(leaf_switches)]

    uplinks = spine_switches
    if redundancy: uplinks = uplinks * 2
    # Conectar switches leaf a los switches spine con redundancia
    for leaf in leaves:
        for spine in spines:
            net.addLink(leaf, spine, cls=TCLink, bw=link_bandwidth, htb=True)
            if redundancy: 
                net.addLink(leaf, spine, cls=TCLink, bw=link_bandwidth, htb=True)

    bw_leaf2host = (3 * (uplinks * link_bandwidth)) / hosts_per_leaf
    if bw_leaf2host > 1000: 
        bw_leaf2host = 1000

    # Agregar hosts y conectarlos a los switches leaf
    host_count = 1
    for leaf in leaves:
        for _ in range(hosts_per_leaf):
            host = net.addHost(f"h{host_count}")
            net.addLink(host, leaf, cls=TCLink, bw=bw_leaf2host, htb=True)
            host_count += 1

    # Iniciar la red
    net.start()

    # Mostrar CLI de Mininet
    CLI(net)

    # Detener la red al salir
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    args = parse_arguments()
    create_spine_leaf_topology(args.spine, args.leaf, args.hosts, args.bw, args.rd, args.c)
