from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
import threading
import queue
import sys

def sniff_http_packets(interface):
    # Filtrar tráfico HTTP (puerto 80)
    sniff(
        iface=interface,
        filter="tcp port 80",
        prn=process_packet,
        store=False  # Para NO almacenar paquetes en memoria
    )

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        # Extraer IP de origen y destino
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        
        # Mostrar información
        print(f"Solicitud HTTP desde {src_ip} a {dst_ip}")
        print(f"    URL: {url}")
        
        # Extraer headers
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            print(f"    Datos: {raw_data.decode('utf-8', errors='ignore')}")

if __name__ == "__main__":
    interface = "Wi-Fi"
    sniff_http_packets(interface)