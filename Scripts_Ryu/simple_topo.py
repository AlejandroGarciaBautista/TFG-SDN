from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_topo():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)
    # Agregar el controlador remoto
    c0 = net.addController('c0', controller=RemoteController, ip="127.0.0.1", port=6633, protocols="OpenFlow13")

    sw1 = net.addSwitch("sw1")

    h1 = net.addHost("h1")
    h2 = net.addHost("h2")

    net.addLink(sw1, h1)
    net.addLink(sw1, h2)

    # Iniciar la red
    net.start()

    # Mostrar CLI de Mininet
    CLI(net)

    # Detener la red al salir
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    create_topo()
