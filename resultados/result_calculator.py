import json

# Cargar el JSON con los tiempos de cada log
with open("datos.json", "r") as f:
    resultados = json.load(f)

# Función para calcular el tiempo promedio
def calcular_media(tiempos):
    if not tiempos:
        return 0.0
    return sum(tiempos) / len(tiempos)

# Calcular promedio por cada log
media_por_log = {}
for archivo, tiempos in resultados.items():
    media_por_log[archivo] = round(calcular_media(tiempos), 6)

# Guardar en un nuevo JSON
with open("resultados_promedio.json", "w") as f_promedio:
    json.dump(media_por_log, f_promedio, indent=4)

print("Tiempo promedio calculado y guardado en 'resultados_promedio.json'")
