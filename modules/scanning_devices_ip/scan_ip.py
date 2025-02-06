import tkinter as tk
import nmap
import socket


def get_local_ipv4():
    try:
        # Se conecta a un servidor externo para determinar la interfaz en uso
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # 8.8.8.8 es el servir DNS de google
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        print(f"Error: {e}")
        return None
    
def list_connected_devices(devices_text):
    devices_text.delete("1.0", tk.END)  # Limpiar el área de resultados
    try:
        nm = nmap.PortScanner()
        local_ipv4 = get_local_ipv4()
        subnet = f"{local_ipv4}/24"
        devices_text.insert(tk.END, f"Escaneando dispositivos en la red {subnet}...\n")
        devices_text.see(tk.END)  # Desplaza el texto automáticamente hacia abajo
        devices_text.update()  # Fuerza la actualización de la interfaz
        nm.scan(hosts=subnet, arguments="-sn")
        for host in nm.all_hosts():
            devices_text.insert(tk.END, f"Host: {host} ({nm[host].hostname()}) - Estado: {nm[host].state()}\n")
    except Exception as e:
        devices_text.insert(tk.END, f"Error al escanear la red: {e}\n")