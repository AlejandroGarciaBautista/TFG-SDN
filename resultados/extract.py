import os
import re
import json

# Ruta del directorio donde están los .log
directorio_logs = "./resultados/test_0_5_delay"  # Cambia esto si están en otra carpeta

# Diccionario para almacenar los resultados
resultados = {}

# Expresión regular para extraer los valores de time=... ms
regex_time = re.compile(r'time=([\d.]+)\s*ms')

# Recorremos todos los ficheros .log en el directorio
for archivo in os.listdir(directorio_logs):
    if archivo.endswith(".log"):
        tiempos = []
        ruta_fichero = os.path.join(directorio_logs, archivo)
        with open(ruta_fichero, "r") as f:
            for linea in f:
                match = regex_time.search(linea)
                if match:
                    tiempos.append(float(match.group(1)))
        resultados[archivo] = tiempos

# Guardamos en un JSON
with open("resultados_conn_delay.json", "w") as f_json:
    json.dump(resultados, f_json, indent=4)

print("Resultados guardados en 'resultados.json'")
