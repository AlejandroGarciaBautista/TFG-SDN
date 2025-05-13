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
    parser.add_argument("--hosts", type=int, default=12, help="Cantidad de hosts por switch leaf (por defecto: 12)")
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
            net.addLink(
                host, leaf, 
                cls=TCLink, bw=bw_leaf2host, htb=True
                )
            host_count += 1

    # Iniciar la red
    net.start()

    # --- CONFIGURACIÓN DE INTERFACES VLAN EN LOS HOSTS ---------------------
    # Mapeo de hosts con VLANs y sus IPs
    hosts_vlan = {
        'h1':  {10: '10.0.10.1/24'},
        'h20': {10: '10.0.10.2/24', 20: '10.0.20.1/24'},
        'h25': {10: '10.0.10.3/24', 20: '10.0.20.2/24'},
        'h40': {30: '10.0.30.1/24'}    
    }

    for hname, vlan_info in hosts_vlan.items():
        host = net.get(hname)
        base_intf = host.intfNames()[0]  # ej. 'h1-eth0'

        # 1) Crear y levantar subinterfaces VLAN + asignar IP
        for vid, ip in vlan_info.items():
            subintf = f"{base_intf}.{vid}"
            # gw_ip = f"{ip.rsplit('.', 1)[0]}.254"
            host.cmd(f"ip link add link {base_intf} name {subintf} type vlan id {vid}")
            host.cmd(f"ip addr add {ip} dev {subintf}")
            host.cmd(f"ip link set dev {subintf} up")
            # host.cmd(f"ip route add default via {gw_ip} dev {subintf}")

        # Activar la interfaz base también
        host.cmd(f"ip link set dev {base_intf} up")

        # 2) Configurar el trunk VLAN en el switch que conecta a este host
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
        vids = ",".join(str(v) for v in vlan_info) 
        sw.cmd(f"ovs-vsctl set port {sw_intf} vlan_mode=trunk trunks={vids}")

    # --- APLICAR MODO HYBRID EN ENLACES ENTRE SWITCHES ----------
    # Para cada link, si ambos extremos son OVSSwitch, configúralo
    for link in net.links:
        sw1, sw2 = link.intf1.node, link.intf2.node
        if isinstance(sw1, OVSSwitch) and isinstance(sw2, OVSSwitch):
            # en sw1
            port1 = link.intf1.name
            sw1.cmd(f"ovs-vsctl set port {port1} "
                    f"vlan_mode=hybrid trunks=10,20,30")
            # en sw2
            port2 = link.intf2.name
            sw2.cmd(f"ovs-vsctl set port {port2} "
                    f"vlan_mode=hybrid trunks=10,20,30")

    for hostname in ("h1", "h40"):
        host = net.get(hostname)
        # dentro del namespace de hX, las interfaces se llaman eth0, eth0.10, etc.
        interfaces = ["eth0", "eth0.10", "eth0.20", "eth0.30"]
        for iface in interfaces:
            host.cmd(f"sysctl -w net.ipv4.conf.{hostname}-{iface}.arp_accept=1")
            # host.cmd(f"sysctl -w net.ipv4.conf.{hostname}-{iface}.arp_filter=1")
            # host.cmd(f"sysctl -w net.ipv4.conf.{hostname}-{iface}.arp_ignore=1")
            # host.cmd(f"sysctl -w net.ipv4.conf.{hostname}-{iface}.arp_announce=2")
    #     host.cmd(f"arptables -A OUTPUT -o {hostname}-eth0 --source-ip 10.0.10.0/24 -j DROP")
    #     host.cmd(f"arptables -A OUTPUT -o {hostname}-eth0 --source-ip 10.0.30.0/24 -j DROP")
    #     host.cmd(f"arptables -A INPUT  -i {hostname}-eth0 --source-ip 10.0.10.0/24 -j DROP")
    #     host.cmd(f"arptables -A INPUT  -i {hostname}-eth0 --source-ip 10.0.30.0/24 -j DROP")
    

    h1 = net.get("h1")
    h40 = net.get("h40")

    # h1.cmd("ip route add 10.0.30.0/24 dev h1-eth0.10")
    # h40.cmd("ip route add 10.0.10.0/24 dev h40-eth0.30")

    h40.cmd("echo '100 overlay' >> /etc/iproute2/rt_tables")
    h40.cmd("ip rule add from 10.0.30.1/32 table overlay")
    h40.cmd("ip route add 10.0.10.0/24 dev h40-eth0.30 table overlay")

    h1.cmd("echo '100 overlay' >> /etc/iproute2/rt_tables")
    h1.cmd("ip rule add from 10.0.10.1/32 table overlay")
    h1.cmd("ip route add 10.0.30.0/24 dev h1-eth0.10 table overlay")

    # Mostrar CLI de Mininet
    CLI(net)

    # Detener la red al salir
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    args = parse_arguments()
    create_spine_leaf_topology(args.spine, args.leaf, args.hosts, args.bw, args.rd, args.c)