import argparse
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def parse_arguments():
    parser = argparse.ArgumentParser(description="Simulación de una arquitectura Spine-Leaf en Mininet.")

    parser.add_argument("--spine", type=int, default=2, help="Cantidad de switches spine (por defecto: 2)")
    parser.add_argument("--leaf", type=int, default=4, help="Cantidad de switches leaf (por defecto: 4)")
    parser.add_argument("--hosts", type=int, default=12, help="Cantidad de hosts por switch leaf (por defecto: 2)")
    parser.add_argument("--bw", type=int, default=1000, help="Capacidad de los enlaces Uplink en Mbps (por defecto: 1000 (máximo permitido))")
    parser.add_argument("--rd", type=bool, default=True, help="Aplicar Redundancia en la red (por defecto: True)")
    parser.add_argument("-c", type=str, default="192.168.56.101", help="Dirección IP del controlador SDN (por defecto: 192.168.56.101)")

    return parser.parse_args()

def ping_one_packet(net):
    # Realizar un ping desde cada host con un solo paquete
    for host in net.hosts:
        # Ping a otros hosts (no a sí mismo)
        for target in net.hosts:
            if host != target:
                # Ejecutar un ping desde host a target, enviando solo un paquete
                print(f"Enviando un paquete desde {host.name} a {target.name}")
                host.cmd(f"ping -c 1 {target.IP()}")
                break

def create_spine_leaf_topology(spine_switches, leaf_switches, hosts_per_leaf, link_bandwidth, redundancy, controller_ip):
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)
    
    # Agregar el controlador remoto
    c0 = net.addController('c0', controller=RemoteController, ip=controller_ip, port=6633, protocols="OpenFlow13")

    # Crear switches spine y leaf con nombres más claros
    spines = [net.addSwitch(f"spine{i+1}", dpid=f"10000000000{i+1}", protocols="OpenFlow13") for i in range(spine_switches)]
    leaves = [net.addSwitch(f"leaf{i+1}", dpid=f"20000000000{spine_switches + i+1}", protocols="OpenFlow13") for i in range(leaf_switches)]

    uplinks = spine_switches
    # Conectar switches leaf a los switches spine con redundancia
    for leaf in leaves:
        for spine in spines:
            net.addLink(leaf, spine, cls=TCLink, bw=link_bandwidth, htb=True)
            if redundancy: 
                net.addLink(leaf, spine, cls=TCLink, bw=link_bandwidth, htb=True)
                uplinks = uplinks * 2

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

    # Agregar las reglas necesarias para manejar tráfico desconocido, ARP y LLDP
    # Regla para permitir el tráfico ARP en los switches leaf
    for i in range(1, spine_switches + 1):
       net.get(f"spine{i}").cmd(f"ovs-ofctl -O OpenFlow13 add-flow spine{i} 'priority=10,arp,actions=controller'")
        
    for i in range(1, leaf_switches + 1):
       net.get(f"leaf{i}").cmd(f"ovs-ofctl -O OpenFlow13 add-flow leaf{i} 'priority=10,arp,actions=controller'")

    ping_one_packet(net)

    # Mostrar CLI de Mininet
    CLI(net)

    # Detener la red al salir
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    args = parse_arguments()
    create_spine_leaf_topology(args.spine, args.leaf, args.hosts, args.bw, args.rd, args.c)
