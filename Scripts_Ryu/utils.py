import os
import json
import ipaddress

# --- Carga de configuración ---
BASE_DIR = os.path.dirname(__file__)
VLAN_FILE = os.path.join(BASE_DIR, 'vlans.json')
ALLOWED_FILE = os.path.join(BASE_DIR, 'allowed_communications.json')

# Leer y convertir los rangos a objetos ip_network
with open(VLAN_FILE) as f:
    _vlan_raw = json.load(f)
VLAN_NETWORKS = {
    int(vlan_id): ipaddress.ip_network(cidr)
    for vlan_id, cidr in _vlan_raw.items()
}

# Leer y convertir pares permitidos a set de tuplas
with open(ALLOWED_FILE) as f:
    _comms_raw = json.load(f)
ALLOWED_COMMS = {tuple(pair) for pair in _comms_raw}


# --- Funciones públicas ---

def get_vlan_from_ip(ip):
    """
    Dada una dirección IP (string o IPv4Address), devuelve el ID de la VLAN
    a la que pertenece, o None si no está en ningún rango configurado.
    """
    addr = ipaddress.ip_address(ip)
    for vlan_id, network in VLAN_NETWORKS.items():
        if addr in network:
            return vlan_id
    return None


def is_connection_allowed(ip_src, ip_dst):
    """
    Dadas dos direcciones IP, comprueba:
      1. A qué VLAN pertenece cada una.
      2. Si ese par de VLANs está en la lista de comunicaciones permitidas.
    Devuelve True si la comunicación está permitida, False en caso contrario
    (incluyendo que alguna IP no esté en ninguna VLAN).
    """
    vlan_src = get_vlan_from_ip(ip_src)
    vlan_dst = get_vlan_from_ip(ip_dst)

    if vlan_src is None or vlan_dst is None:
        # Una de las IPs no cae en ningún rango de VLAN
        return False

    return (vlan_src, vlan_dst) in ALLOWED_COMMS
