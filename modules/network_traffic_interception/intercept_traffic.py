from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from scapy.packet import Raw
import threading
import tkinter as tk

# Variables globales
capturing = False
captured_requests = set()  # Almacenar URLs únicas

def start_packet_interception(interception_entry):
    global capturing
    capturing = True  # Activamos la captura
    captured_requests.clear()  # Limpiar historial al iniciar

    interception_entry.delete("1.0", tk.END)
    interception_entry.insert(tk.END, "Escuchando las solicitudes HTTP...\n")

    def process_packet(packet):
        global capturing
        if not capturing:  
            return  # Detener la captura si se solicitó
        
        if packet.haslayer(HTTPRequest):
            try:
                url = f"{packet[HTTPRequest].Host.decode()}{packet[HTTPRequest].Path.decode()}"
                if url not in captured_requests:  # Evita duplicados
                    captured_requests.add(url)
                    interception_entry.insert(tk.END, f"[HTTP] {url}\n")
                    
                    if packet.haslayer(Raw):
                        data = packet[Raw].load.decode(errors="ignore")
                        interception_entry.insert(tk.END, f"[DATA] {data}\n")
                    
                    interception_entry.see(tk.END)  # Auto-scroll

            except Exception as e:
                interception_entry.insert(tk.END, f"Error procesando paquete: {e}\n")

    # Capturar tráfico HTTP en la red mientras capturing sea True
    sniff(filter="tcp port 80", prn=process_packet, store=False, stop_filter=lambda x: not capturing)

def start_interception_en_hilo(interception_entry):
    global capturing
    if not capturing:  # Evita iniciar múltiples capturas
        hilo = threading.Thread(target=start_packet_interception, args=(interception_entry,))
        hilo.daemon = True  # Para que se cierre con la app
        hilo.start()

def stop_interception(interception_entry):
    global capturing
    capturing = False  # Se usa en stop_filter para detener sniff()
    interception_entry.insert(tk.END, "Dejando de escuchar...\n")
