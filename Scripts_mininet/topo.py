from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch, Host, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_spine_leaf_topology():
    # Crear una red de Mininet
    net = Mininet(controller=RemoteController, switch=OVSSwitch, link=TCLink)

    # Agregar el controlador (suponiendo que se usa Ryu)
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Crear 2 switches Spine
    spine1 = net.addSwitch('s1')
    spine2 = net.addSwitch('s2')

    # Crear 4 switches Leaf
    leaf1 = net.addSwitch('l1')
    leaf2 = net.addSwitch('l2')
    leaf3 = net.addSwitch('l3')
    leaf4 = net.addSwitch('l4')

    # Conectar los switches Spine con los Leaf
    net.addLink(spine1, leaf1)
    net.addLink(spine1, leaf2)
    net.addLink(spine2, leaf3)
    net.addLink(spine2, leaf4)

    # Crear 2 hosts por leaf switch
    host1 = net.addHost('h1')
    host2 = net.addHost('h2')
    host3 = net.addHost('h3')
    host4 = net.addHost('h4')
    host5 = net.addHost('h5')
    host6 = net.addHost('h6')
    host7 = net.addHost('h7')
    host8 = net.addHost('h8')

    # Conectar los hosts a los leaf switches
    net.addLink(leaf1, host1)
    net.addLink(leaf1, host2)
    net.addLink(leaf2, host3)
    net.addLink(leaf2, host4)
    net.addLink(leaf3, host5)
    net.addLink(leaf3, host6)
    net.addLink(leaf4, host7)
    net.addLink(leaf4, host8)

    # Iniciar la red
    net.start()

    # Ejecutar pingall para verificar conectividad
    #print("Ejecutando pingall para verificar conectividad entre los hosts...")
    #net.pingAll()

    # Mostrar CLI de Mininet
    CLI(net)

    # Detener la red al salir
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    create_spine_leaf_topology()
