import argparse
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import subprocess
import requests

import time
import threading
import os
from datetime import datetime

API_URL = f'http://192.168.56.101:8080/hosts'

def launch_ping_tests(net):
    os.makedirs("resultados", exist_ok=True)

    def lanzar_ping(host, ns, destino):
        cmd = f"ip netns exec {ns} ping -c 50 {destino}"
        print(f"[PING] {ns} a {destino}")
        result = host.cmd(cmd)
        return result

    def generar_trafico(host, ns, destino):
        cmd = f"ip netns exec {ns} ping {destino}"
        print(f"[TRAFICO] {ns} a {destino}")
        return host.popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    escenarios = {
        "escenario_1": ["h20-C10-vm1", "h25-C10-vm1"],
        "escenario_2": ["h20-C10-vm1", "h25-C10-vm1", "h40-C30-vm1", "h1-C10-vm2"]
    }

    destinos = {
        "h1-C10-vm2": "10.0.10.2",
        "h20-C10-vm1": "10.0.10.3",
        "h40-C30-vm1": "10.0.30.1"
    }

    cliente_ns = "h1-C10-vm1"
    cliente_host = net.get("h1")

    # Escenario base sin tráfico
    lanzar_ping(cliente_host, cliente_ns, '10.0.10.2')
    print("\n--- Ejecutando escenario_0 ---\n")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    for nombre_dest, ip_dest in destinos.items():
        salida = lanzar_ping(cliente_host, cliente_ns, ip_dest)
        with open(f"resultados/escenario_0_{nombre_dest}_{timestamp}.log", "w") as f:
            f.write(salida)
    print("--- Fin de escenario_0 ---\n")

    # Escenarios con tráfico
    for nombre_escenario, generadoras in escenarios.items():
        print(f"\n--- Ejecutando {nombre_escenario} ---\n")
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

        procesos = []
        for ns in generadoras:
            h = ns.split("-")[0]
            procesos.append(generar_trafico(net.get(h), ns, "10.0.10.2"))
        time.sleep(5)  # estabilizar tráfico

        for nombre_dest, ip_dest in destinos.items():
            salida = lanzar_ping(cliente_host, cliente_ns, ip_dest)
            with open(f"resultados/{nombre_escenario}_{nombre_dest}_{timestamp}.log", "w") as f:
                f.write(salida)

        for p in procesos:
            p.terminate()
        time.sleep(1)
        print(f"--- Fin de {nombre_escenario} ---\n")




def register_host(net, host):
    ip  = host.IP()
    mac = host.MAC()
    # Obtenemos el switch leaf y el puerto físico de acceso
    # links: [(intf_host, intf_sw), …]
    links = [l for l in net.links if host in (l.intf1.node, l.intf2.node)]

    intf_h, intf_sw = links[0].intf1, links[0].intf2
    if intf_sw.node == host:
        intf_h, intf_sw = links[0].intf2, links[0].intf1

    leaf = intf_sw.node
    # leaf.ports mapea Intf -> número de puerto
    port = leaf.ports[intf_sw]
    # El dpid lo convertimos a entero de la representación hex
    dpid = int(leaf.dpid, 16)

    payload = {'dpid': dpid, 'in_port': port, 'ip': ip, 'mac': mac}
    try:
        r = requests.post(API_URL, json=payload, timeout=2)
        if r.status_code != 200:
            print(f"[REST] fallo al registrar {host.name}: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[REST] error al conectar con {API_URL}: {e}")

def register_vm(net, host, vm_ns, veth_v, ip_addr):
    """
    Registra una VM (namespace) igual que register_host,
    obteniendo su MAC e indicando el switch Leaf y puerto físicos.
    """
    # 1) Leer MAC desde el namespace
    mac = host.cmd(f'ip netns exec {vm_ns} cat /sys/class/net/{veth_v}/address').strip()

    # 2) Determinar el switch Leaf y el puerto físico de acceso
    #    Igual que en register_host, encontramos el enlace host<->switch
    links = [l for l in net.links if host in (l.intf1.node, l.intf2.node)]
    intf_h, intf_sw = links[0].intf1, links[0].intf2
    if intf_sw.node == host:
        intf_h, intf_sw = links[0].intf2, links[0].intf1

    leaf = intf_sw.node
    port = leaf.ports[intf_sw]
    dpid = int(leaf.dpid, 16)

    # 3) Payload y POST
    payload = {
        'dpid':   dpid,
        'in_port': port,
        'ip':     ip_addr,
        'mac':    mac
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=2)
        if r.status_code != 200:
            print(f"[REST-VM] fallo al registrar {vm_ns}: {r.status_code} {r.text}")
    except Exception as e:
        print(f"[REST-VM] error al conectar con {API_URL}: {e}")

def cleanup_netns():
    """
    Elimina todos los network namespaces existentes para evitar conflictos al reiniciar Mininet.
    """
    try:
        out = subprocess.check_output(['ip', 'netns', 'list']).decode().splitlines()
    except subprocess.CalledProcessError:
        return
    for line in out:
        ns = line.split()[0]
        # Eliminar namespace
        subprocess.run(['ip', 'netns', 'del', ns], check=False)

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
    cleanup_netns()
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
            net.addLink(leaf, spine, cls=TCLink, bw=link_bandwidth, htb=True, delay="1.5ms")
            if redundancy: 
                net.addLink(leaf, spine, cls=TCLink, bw=link_bandwidth, htb=True, delay="1.5ms")

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
                cls=TCLink, bw=bw_leaf2host, htb=True, delay="1.5ms"
                )
            host_count += 1

    # Iniciar la red
    net.start()

    # ——— Registrar todos los hosts en el controlador vía REST ———
    for host in net.hosts:
        register_host(net, host)


    # --- CONFIGURACIÓN DE UN ÚNICO BRIDGE (br0), NETNS Y VETH POR HOST -----
    hosts_vlan = {
        'h1' : {10: ['10.0.10.1/24', '10.0.10.2/24']},
        'h20': {10: ['10.0.10.3/24'], 20: ['10.0.20.1/24']},
        'h25': {10: ['10.0.10.4/24'], 20: ['10.0.20.2/24']},
        'h40': {30: ['10.0.30.1/24']}
    }

    for hname, vlan_map in hosts_vlan.items():
        host = net.get(hname)
        parent = host.defaultIntf().name    # interfaz física en Mininet
        host_ip = host.IP()
        prefix = host.defaultIntf().prefixLen

        # 1) Crear bridge local br0
        host.cmd('ip link add br0 type bridge')
        host.cmd('ip link set br0 up')

        # 2) Mover la interfaz física al bridge y reasignar IP
        host.cmd(f'ip addr flush dev {parent}')
        host.cmd(f'ip link set {parent} master br0')
        host.cmd(f'ip link set {parent} up')
        host.cmd(f'ip addr add {host_ip}/{prefix} dev br0')

        # 3) Crear namespaces y veths para cada VM, conectados a br0
        veth_count = 0
        for vlan, ip_list in vlan_map.items():
            for ip_addr in ip_list:
                veth_count += 1
                vm_ns = f"{hname}-C{vlan}-vm{veth_count}"
                veth_h = f"{hname}-vm{veth_count}-h"
                veth_v = f"{hname}-vm{veth_count}-v"

                # Crear namespace y par veth
                host.cmd(f'ip netns add {vm_ns}')
                host.cmd(f'ip link add {veth_h} type veth peer name {veth_v}')

                # Conectar extremo host al bridge
                host.cmd(f'ip link set {veth_h} master br0')
                host.cmd(f'ip link set {veth_h} up')

                # Configurar extremo VM dentro del namespace
                host.cmd(f'ip link set {veth_v} netns {vm_ns}')
                host.cmd(f'ip netns exec {vm_ns} ip link set {veth_v} up')
                host.cmd(f'ip netns exec {vm_ns} ip addr add {ip_addr} dev {veth_v}')
                host.cmd(f'ip netns exec {vm_ns} ip link set lo up')

                host.cmd(f'ip netns exec {vm_ns} ip route add default via 10.0.{vlan}.254 dev {veth_v}')

                register_vm(net, host, vm_ns, veth_v, ip_addr.split('/')[0])
    
    #time.sleep(10)
    launch_ping_tests(net)

    # Al salir, limpiar namespaces
    try:
        CLI(net)  
    finally:
        net.stop()
        cleanup_netns()

if __name__ == "__main__":
    setLogLevel("info")
    args = parse_arguments()
    create_spine_leaf_topology(args.spine, args.leaf, args.hosts, args.bw, args.rd, args.c)