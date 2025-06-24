import json

# Cargar el JSON con los tiempos de cada log
with open("resultados_sin_delay.json", "r") as f:
    resultados = json.load(f)

# Función para calcular jitter como promedio de |ti+1 - ti|
def calcular_jitter(tiempos):
    if len(tiempos) < 2:
        return 0.0
    diferencias = [abs(tiempos[i+1] - tiempos[i]) for i in range(len(tiempos)-1)]
    return sum(diferencias) / len(diferencias)

# Calcular jitter por cada log
jitter_por_log = {}
for archivo, tiempos in resultados.items():
    jitter_por_log[archivo] = round(calcular_jitter(tiempos), 6)

# Guardar en un nuevo JSON
with open("jitter_sin_delay.json", "w") as f_jitter:
    json.dump(jitter_por_log, f_jitter, indent=4)

print("Jitter calculado y guardado en 'jitter.json'")
