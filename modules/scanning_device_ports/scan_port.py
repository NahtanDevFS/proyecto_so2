import nmap
import tkinter as tk

def list_device_ports(ip_entry, ports_entry, results_text):
    target = ip_entry.get()
    ports = ports_entry.get() or "1-1024"

    results_text.delete("1.0", tk.END)
    if not target:
        results_text.insert(tk.END, "Por favor, introduce una dirección IP o un rango de red.\n")
        return

    results_text.insert(tk.END, f"Escaneando {target} en los puertos {ports}...\n")
    results_text.see(tk.END)
    results_text.update()

    try:
        nm = nmap.PortScanner()
        nm.scan(target, ports)

        # Nuevo bloque: comprueba si no encontró hosts
        hosts = nm.all_hosts()
        if not hosts:
            results_text.insert(tk.END, f"No se encontró ningún host en {target}.\n")
            return

        for host in hosts:
            results_text.insert(tk.END, f"\nHost: {host} ({nm[host].hostname()})\n")
            results_text.insert(tk.END, f"Estado: {nm[host].state()}\n")
            for protocol in nm[host].all_protocols():
                results_text.insert(tk.END, f"Protocolo: {protocol}\n")
                for port in nm[host][protocol].keys():
                    state = nm[host][protocol][port]['state']
                    results_text.insert(tk.END, f"  Puerto: {port}\tEstado: {state}\n")

    except nmap.PortScannerError as nse:
        # Si el error es “Failed to resolve”, significa que la IP no fue encontrada:
        if "Failed to resolve" in str(nse):
            results_text.insert(tk.END, f"No se pudo resolver la dirección: {target}\n")
        else:
            results_text.insert(tk.END, f"Error al realizar el escaneo con nmap: {nse}\n")
    except Exception as e:
        results_text.insert(tk.END, f"Error inesperado: {e}\n")
