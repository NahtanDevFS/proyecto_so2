import subprocess
import tkinter as tk
from tkinter import messagebox
import threading

def liberar_puerto(puerto):
    #Verifica si hay un proceso en el puerto dado y lo termina.
    try:
        # Buscar procesos en el puerto
        #lsof: Lista archivos abiertos, -t: Muestra solo los IDs de proceso (PIDs), -i:[puerto]: Filtra procesos usando el puerto TCP especificado
        comando_buscar = ["lsof", "-t", f"-i:{puerto}"]
        procesos = subprocess.check_output(comando_buscar, text=True).strip().split("\n")
        
        if procesos:
            for pid in procesos:
                if pid:  # Asegurar que el PID no está vacío
                    # Terminar el proceso, kill: Envía una señal a un proceso, -9: Señal SIGKILL (terminación forzosa e inmediata)
                    subprocess.run(["kill", "-9", pid])
                    print(f"Proceso {pid} en el puerto {puerto} terminado.")
    except subprocess.CalledProcessError:
        # No hay procesos en el puerto
        print(f"No hay procesos usando el puerto {puerto}.")


def ejecutar_mitmdump(mitmdump_entry):
    
    # Ejecuta el comando mitmdump con el script redirect_URL.py en un hilo separado.
    
    def proceso_mitmdump():
        try:

            puerto = 8080
            
            # Liberar el puerto antes de ejecutar mitmdump
            liberar_puerto(puerto)

            # Ruta completa al comando mitmdump, s: Ejecuta un script Python personalizado
            comando = ["/home/jonathan/myenv/bin/mitmdump", "-s", "/home/jonathan/Desktop/proyecto_so2/modules/network_traffic_modification/redirect_traffic.py"]
            
            # Inicia el proceso
            proceso = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            mitmdump_entry.delete("1.0", tk.END)  # Limpiar el área de resultados
            mitmdump_entry.insert(tk.END, "mitmdump ha sido iniciado.\n")

            # Leer y mostrar la salida o errores en tiempo real
            for line in proceso.stdout:
                mitmdump_entry.insert(tk.END, f"Salida: {line.strip()}\n")
            for line in proceso.stderr:
                mitmdump_entry.insert(tk.END, f"Error: {line.strip()}\n")

            # Mensaje final al terminar el proceso
            # print("mitmdump ha terminado.")
        except FileNotFoundError:
            messagebox.showerror("Error", "mitmdump no está instalado o no se encontró el script redirect_URL.py.")
        except Exception as e:
            messagebox.showerror("Error", f"Se produjo un error: {e}")

    # Crea y ejecuta un hilo para no bloquear la interfaz
    hilo = threading.Thread(target=proceso_mitmdump)
    hilo.daemon = True  # Se asegura que el hilo termine al cerrar la aplicación
    hilo.start()

def parar_mitmdump(mitmdump_entry):
    puerto = 8080
            
    # Liberar el puerto
    liberar_puerto(puerto)

    mitmdump_entry.delete("1.0", tk.END)  # Limpiar el área de resultados
    mitmdump_entry.insert(tk.END, "mitmdump ha terminado.")
