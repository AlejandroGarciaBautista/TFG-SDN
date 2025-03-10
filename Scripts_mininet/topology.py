import argparse
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def parse_arguments():
  parser = argparse.ArgumentParser(description="Simulación de una arquitectura Spine-Leaf en Mininet.")
  
  parser.add_argument("--spine", type=int, default=2, help="Cantidad de switches spine (por defecto: 2)")
  parser.add_argument("--leaf", type=int, default=4, help="Cantidad de switches leaf (por defecto: 4)")
  parser.add_argument("--hosts", type=int, default=2, help="Cantidad de hosts por switch leaf (por defecto: 2)")
  parser.add_argument("--bw", type=int, default=1000, help="Capacidad de los enlaces en Mbps (por defecto: 1000)")
  
  return parser.parse_args()

def create_spine_leaf_topology(spine_switches, leaf_switches, hosts_per_leaf, link_bandwidth):
  net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink)

  # Agregar el controlador
  net.addController("c0")

  # Crear switches spine y leaf
  spines = [net.addSwitch(f"s{i+1}") for i in range(spine_switches)]
  leaves = [net.addSwitch(f"l{i+1}") for i in range(leaf_switches)]

  # Conectar switches leaf a los switches spine
  for leaf in leaves:
    for spine in spines:
      net.addLink(leaf, spine, bw=link_bandwidth)

  # Agregar hosts y conectarlos a los switches leaf
  host_count = 1
  for leaf in leaves:
    for _ in range(hosts_per_leaf):
      host = net.addHost(f"h{host_count}")
      net.addLink(host, leaf, bw=link_bandwidth)
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
  create_spine_leaf_topology(args.spine, args.leaf, args.hosts, args.bw)
