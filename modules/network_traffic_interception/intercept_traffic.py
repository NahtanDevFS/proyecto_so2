from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
import threading
import tkinter as tk

# def process_packet(packet):
#     if packet.haslayer(HTTPRequest):
#         print(f"[HTTP] {packet[HTTPRequest].Host.decode()}{packet[HTTPRequest].Path.decode()}")
#         if packet.haslayer(Raw):
#             print(f"[DATA] {packet[Raw].load.decode(errors='ignore')}")

# # Capturar tráfico HTTP en la red
# sniff(filter="tcp port 80", prn=process_packet, store=False)

hilo = None  #Variable global para el hilo
detener_sniffing = True  #Variable para controlar la detención

def start_interception(interception_entry):
    global hilo, detener_sniffing
    
    if detener_sniffing == False:
        interception_entry.insert(tk.END, "La intercepción ya está en marcha\n")
        return
    
    detener_sniffing = False  #Reiniciar la bandera de detención

    interception_entry.delete("1.0", tk.END)
    interception_entry.insert(tk.END, "Escuchando...\n")

    #La interfaz es Wi-Fi en Windows
    def sniff_http_packets():
        try:
            sniff(
                iface="eth0",
                filter="tcp port 80",
                prn=lambda p: process_packet(p, interception_entry),
                stop_filter=lambda _: detener_sniffing,
                store=False,
                promisc=True
            )
        except Exception as e:
            interception_entry.insert(tk.END, f"Error: {str(e)}\n")

    hilo = threading.Thread(target=sniff_http_packets)
    hilo.daemon = True  #Permite que el hilo se detenga al cerrar la aplicación
    hilo.start()

def process_packet(packet, entry_widget):
    if packet.haslayer(HTTPRequest):
        try:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            
            output = f"Solicitud HTTP desde {src_ip} a {dst_ip}\nURL: {url}\n"
            
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                output += f"Datos: {raw_data.decode('utf-8', errors='ignore')}\n\n"
            
            entry_widget.insert(tk.END, output)
            entry_widget.see(tk.END)  #Desplazar al final del texto
        except Exception as e:
            entry_widget.insert(tk.END, f"Error procesando paquete: {str(e)}\n")

def stop_interception(interception_entry):
    global detener_sniffing
    detener_sniffing = True  #Activar la bandera de detención
    interception_entry.insert(tk.END, "Deteniendo la intercepción...\n")