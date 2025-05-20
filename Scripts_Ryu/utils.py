import os
import json
import ipaddress

# --- Paths a los ficheros ---
BASE_DIR     = os.path.dirname(__file__)
VLAN_FILE    = os.path.join(BASE_DIR, 'vlans.json')
ALLOWED_FILE = os.path.join(BASE_DIR, 'allowed_communications.json')

def load_configs():
    """
    Carga y parsea ambos ficheros JSON en cada invocación para asi poder realizar
    modificaciones en estos ficheros sin necesidad de reiniciar el controlador 
    """
    # 1) Leer rangos de VLAN
    with open(VLAN_FILE) as f:
        vlan_raw = json.load(f)
    vlan_networks = {
        int(vlan_id): ipaddress.ip_network(cidr)
        for vlan_id, cidr in vlan_raw.items()
    }

    # 2) Leer pares permitidos
    with open(ALLOWED_FILE) as f:
        comms_raw = json.load(f)
    allowed_comms = {tuple(pair) for pair in comms_raw}

    return vlan_networks, allowed_comms


def get_vlan_from_ip(ip, vlan_networks=None):
    """
    Dada una IP, devuelve el ID de VLAN al que pertenece, o None.
    Si no se pasa vlan_networks, lo carga de los JSON al momento.
    """
    if vlan_networks is None:
        vlan_networks, _ = load_configs()

    addr = ipaddress.ip_address(ip)
    for vlan_id, network in vlan_networks.items():
        if addr in network:
            return vlan_id
    return None


def is_connection_allowed(ip_src, ip_dst):
    """
    Dada un par de direcciones IP, comprueba si esa conexión esta permitida.
    Carga los JSONs necesarios en el momento de la ejecución.
    """
    vlan_networks, allowed_comms = load_configs()

    vlan_src = get_vlan_from_ip(ip_src, vlan_networks)
    vlan_dst = get_vlan_from_ip(ip_dst, vlan_networks)

    if vlan_src is None or vlan_dst is None:
        return False

    return (vlan_src, vlan_dst) in allowed_comms
