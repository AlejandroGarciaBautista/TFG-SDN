import ipaddress

def generar_ips_enlaces(N, M, redundancia=False):
    # Rango de direcciones para enlaces Spine-Leaf: 10.0.0.0/16
    red_spine_leaf = ipaddress.IPv4Network('10.0.0.0/16')
    
    # Variables para el cálculo de direcciones IP
    enlace_ip_list = []
    
    # Generador de direcciones /30 para enlaces entre Spine y Leaf
    enlace_start = iter(red_spine_leaf.subnets(new_prefix=30))
    
    # Generar enlaces para cada combinación Spine-Leaf
    for spine in range(1, N + 1):
        for leaf in range(1, M + 1):
            # Para cada combinación, asignamos 1 o 2 enlaces, dependiendo de la redundancia
            num_enlaces = 2 if redundancia else 1
            
            for enlace_num in range(num_enlaces):
                subred = next(enlace_start)  # Obtener la siguiente subred /30
                ip1, ip2 = list(subred.hosts())[:2]  # Tomamos las 2 primeras IPs
                # Añadir el enlace con la subred y direcciones IP correspondientes
                enlace_ip_list.append({
                    "spine": f"Spine{spine}",
                    "leaf": f"Leaf{leaf}",
                    "subnet": str(subred),
                    "ip1": str(ip1),
                    "ip2": str(ip2)
                })
    
    return enlace_ip_list

def mostrar_resultado(N, M, redundancia=False):
    enlaces = generar_ips_enlaces(N, M, redundancia)

    print(f"Total de enlaces Spine-Leaf {'con redundancia' if redundancia else 'sin redundancia'}: {len(enlaces)}")
    
    # Mostrar los detalles de cada enlace (incluyendo Spine, Leaf, subred y direcciones IP)
    for enlace in enlaces:
        print(f"{enlace['spine']} - {enlace['leaf']}: Subred: {enlace['subnet']} | Enlace: {enlace['ip1']} <-> {enlace['ip2']}")
    
    print("\n...")
    print(f"Total de enlaces Spine-Leaf: {len(enlaces)}")

# Parámetros N y M, y redundancia
N = 80  # Número de Spine
M = 80  # Número de Leaf
redundancia = True  # Cambiar a False si no se quiere redundancia

mostrar_resultado(N, M, redundancia)
