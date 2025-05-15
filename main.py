import tkinter as tk
from tkinter import ttk, scrolledtext
import sys
import os

modules = [
    "modules/password_generator",
    "modules/virus_scanner",
    "modules/scanning_devices_ip",
    "modules/scanning_device_ports",
    "modules/fake_form_server",
    "modules/network_traffic_interception",
    "modules/network_traffic_modification",
    "modules/denial_service_attack"
]

for module in modules:
        module_path = os.path.abspath(os.path.join(module))
        if module_path not in sys.path:
            sys.path.append(module_path)

from password_generator import generate_password
from virus_scanner import scan_for_virus
from scan_ip import list_connected_devices
from scan_port import list_device_ports
from run_server import start_http_server_en_hilo, stop_http_server, actualizar_consola_http_server
from intercept_traffic import start_interception_en_hilo, stop_interception
from start_ettercap import start_ettercap_en_hilo, stop_ettercap_en_hilo
from run_redirection import ejecutar_mitmdump, parar_mitmdump
from dos_attack import ejecutar_ataque_dos, parar_ataque_dos

# GUI principal
root = tk.Tk()
root.title("Herramienta de aprovechamiento de vulnerabilidades en sistemas")
root.geometry("1200x600")
root.configure(bg="black")  # Cambiar el fondo a negro

# Crear estilos personalizados
style = ttk.Style()
style.configure("TFrame", background="black")
style.configure("TLabel", background="black", foreground="#03bf00")
style.configure("TButton", background="black", foreground="#03bf00")

# Contenedor de pestañas
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Pestañas
home_tab = ttk.Frame(notebook, style="TFrame")
devices_tab = ttk.Frame(notebook, style="TFrame")
scan_tab = ttk.Frame(notebook, style="TFrame")
intercept_traffic_tab = ttk.Frame(notebook, style="TFrame")
modify_traffic_tab = ttk.Frame(notebook, style="TFrame")
start_fake_form_server = ttk.Frame(notebook, style="TFrame")
DoS_tab = ttk.Frame(notebook, style="TFrame")
# Pestañas extra
pass_generator_tab = ttk.Frame(notebook, style="TFrame")
scan_virus_tab = ttk.Frame(notebook, style="TFrame")

notebook.add(home_tab, text="Inicio")
notebook.add(devices_tab, text="Escanear Red")
notebook.add(scan_tab, text="Escanear Puertos")
notebook.add(intercept_traffic_tab, text="Iniciar intercepcion")
notebook.add(modify_traffic_tab, text="Iniciar redireccion")
notebook.add(start_fake_form_server, text="Iniciar server")
notebook.add(DoS_tab, text="Iniciar ataque DoS")
notebook.add(pass_generator_tab, text="Gen clave")
notebook.add(scan_virus_tab, text="Escanear archivo")

# Contenido de la pestaña Inicio
home_label = ttk.Label(home_tab, text="Aplicación de aprovechamiento de vulnerabilidades en los sistemas", font=("Arial", 15))
home_label.pack(pady=20)

devices_button = tk.Button(home_tab, text="Escanear Red", command=lambda: notebook.select(devices_tab), width=40, bg="#303030", fg="#03bf00")
devices_button.pack(pady=10)

scan_button = tk.Button(home_tab, text="Escanear puertos", command=lambda: notebook.select(scan_tab), width=40, bg="#303030", fg="#03bf00")
scan_button.pack(pady=10)

ettercap_button = tk.Button(home_tab, text="Iniciar intercepción", command=lambda: notebook.select(intercept_traffic_tab), width=40, bg="#303030", fg="#03bf00")
ettercap_button.pack(pady=10)

mitmdump_button = tk.Button(home_tab, text="Iniciar redirección", command=lambda: notebook.select(modify_traffic_tab), width=40, bg="#303030", fg="#03bf00")
mitmdump_button.pack(pady=10)

intercept_data_button = tk.Button(home_tab, text="Iniciar servidor de fake-form", command=lambda: notebook.select(start_fake_form_server), width=40, bg="#303030", fg="#03bf00")
intercept_data_button.pack(pady=10)

DoS_button = tk.Button(home_tab, text="Iniciar ataque DoS", command=lambda: notebook.select(DoS_tab), width=40, bg="#303030", fg="#03bf00")
DoS_button.pack(pady=10)


extras_label = ttk.Label(home_tab, text="Extras", font=("Arial", 16))
extras_label.pack(pady=20)

generator_password_button = tk.Button(home_tab, text="Generador de contraseñas", command=lambda: notebook.select(pass_generator_tab), width=40, bg="#303030", fg="#03bf00")
generator_password_button.pack(pady=10)

malware_scanner_button = tk.Button(home_tab, text="Escáneo de archivos para detectar malware", command=lambda: notebook.select(scan_virus_tab), width=40, bg="#303030", fg="#03bf00")
malware_scanner_button.pack(pady=10)


# Contenido de la pestaña Dispositivos Conectados
devices_label = ttk.Label(devices_tab, text="Dispositivos Conectados a la Red Wi-Fi", font=("Arial", 14))
devices_label.pack(pady=10)
# Botón para listar dispositivos
list_devices_button = tk.Button(devices_tab, text="Listar Dispositivos", command=lambda: list_connected_devices(devices_text), width=30, bg="#303030", fg="#03bf00")
list_devices_button.pack(pady=10)
# Área para mostrar los resultados
devices_text = scrolledtext.ScrolledText(devices_tab, width=80, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
devices_text.pack(pady=5)


# Contenido de la pestaña Escaneo de puertos
scan_label = ttk.Label(scan_tab, text="Herramientas de Escaneo de puertos", font=("Arial", 14))
scan_label.pack(pady=10)
# Campo de entrada para la IP o rango de red
ip_label = ttk.Label(scan_tab, text="Dirección IP o Rango de Red:")
ip_label.pack(pady=5)
ip_entry = tk.Entry(scan_tab, width=50, bg="#303030", fg="#03bf00")
ip_entry.pack(pady=5)
# Campo de entrada para los puertos
ports_label = ttk.Label(scan_tab, text="Puertos (ejemplo: 22,80 o 1-1024):")
ports_label.pack(pady=5)
ports_entry = tk.Entry(scan_tab, width=50, bg="#303030", fg="#03bf00")
ports_entry.pack(pady=5)
# Botón para ejecutar el escaneo
scan_action_button = tk.Button(scan_tab, text="Ejecutar Escaneo", command=lambda: list_device_ports(ip_entry, ports_entry, results_text), width=30, bg="#303030", fg="#03bf00")
scan_action_button.pack(pady=10)
# Área para mostrar los resultados
results_label = ttk.Label(scan_tab, text="Resultados:")
results_label.pack(pady=5)
results_text = scrolledtext.ScrolledText(scan_tab, width=80, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
results_text.pack(pady=5)



# Contenido de la pestaña para iniciar la intercepción de tráfico
interception_label = ttk.Label(intercept_traffic_tab, 
                               text="Manejo de intercepción de tráfico de red", 
                               font=("Arial", 16))
interception_label.pack(pady=10)

# Crear un frame para contener los botones
button_frame = tk.Frame(intercept_traffic_tab, bg="black")
button_frame.pack(pady=10)

# Botones para la primera columna
start_ettercap_button = tk.Button(button_frame, 
                                  text="Iniciar Ettercap", 
                                  command=lambda: start_ettercap_en_hilo(intercepcion_result_text), 
                                  width=30, bg="#303030", fg="#03bf00")
start_ettercap_button.grid(row=0, column=0, padx=5, pady=10)

stop_ettercap_button = tk.Button(button_frame, 
                                 text="Detener Ettercap", 
                                 command=lambda: stop_ettercap_en_hilo(intercepcion_result_text), 
                                 width=30, bg="#303030", fg="#03bf00")
stop_ettercap_button.grid(row=1, column=0, padx=5, pady=10)

# Botones para la segunda columna
start_interception_button = tk.Button(button_frame, 
                                      text="Iniciar intercepción HTTP", 
                                      command=lambda: start_interception_en_hilo(intercepcion_result_text), 
                                      width=30, bg="#303030", fg="#03bf00")
start_interception_button.grid(row=0, column=1, padx=5, pady=10)

stop_interception_button = tk.Button(button_frame, 
                                     text="Detener intercepción HTTP", 
                                     command=lambda: stop_interception(intercepcion_result_text), 
                                     width=30, bg="#303030", fg="#03bf00")
stop_interception_button.grid(row=1, column=1, padx=5, pady=10)

# Área de texto con scroll para mostrar resultados
intercepcion_result_text = scrolledtext.ScrolledText(intercept_traffic_tab, 
                                                      width=120, height=20, 
                                                      bg="#303030", fg="#03bf00", 
                                                      insertbackground="white")
intercepcion_result_text.pack(pady=5)
# interception_label = ttk.Label(intercept_traffic_tab, text="Manejo de intercepción de tráfico de red", font=("Arial", 16))
# interception_label.pack(pady=10)
# start_ettercap_button = tk.Button(intercept_traffic_tab, text="Iniciar Ettercap", command=lambda: start_ettercap_en_hilo(intercepcion_result_text), width=30, bg="#303030", fg="#03bf00")
# start_ettercap_button.pack(pady=10)
# stop_ettercap_button = tk.Button(intercept_traffic_tab, text="Detener Ettercap", command=lambda: stop_ettercap_en_hilo(intercepcion_result_text), width=30, bg="#303030", fg="#03bf00")
# stop_ettercap_button.pack(pady=10)

# start_interception_button = tk.Button(intercept_traffic_tab, text="Iniciar intercepción HTTP", command=lambda: start_interception_en_hilo(intercepcion_result_text), width=30, bg="#303030", fg="#03bf00")
# start_interception_button.pack(pady=10)
# stop_interception_button = tk.Button(intercept_traffic_tab, text="Detener intercepción HTTP", command=lambda: stop_interception(intercepcion_result_text), width=30, bg="#303030", fg="#03bf00")
# stop_interception_button.pack(pady=10)
# intercepcion_result_text = scrolledtext.ScrolledText(intercept_traffic_tab, width=120, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
# intercepcion_result_text.pack(pady=5)



#Contenido de la pestaña para iniciar la redirección
# Etiqueta principal en la pestaña
mitmdump_label = ttk.Label(modify_traffic_tab, 
                            text="Manejo de redirección de tráfico HTTP con mitmdump", 
                            font=("Arial", 16))
mitmdump_label.pack(pady=10)

# Crear un frame para contener los botones
button_frame = tk.Frame(modify_traffic_tab, bg="black")
button_frame.pack(pady=10)

# Botones para la primera columna
start_ettercap_redireccion_button = tk.Button(button_frame, 
                                              text="Iniciar Ettercap", 
                                              command=lambda: start_ettercap_en_hilo(mitmdump_result_text), 
                                              width=30, bg="#303030", fg="#03bf00")
start_ettercap_redireccion_button.grid(row=0, column=0, padx=5, pady=10)

stop_ettercap_redireccion_button = tk.Button(button_frame, 
                                             text="Detener Ettercap", 
                                             command=lambda: stop_ettercap_en_hilo(mitmdump_result_text), 
                                             width=30, bg="#303030", fg="#03bf00")
stop_ettercap_redireccion_button.grid(row=1, column=0, padx=5, pady=10)

# Botones para la segunda columna
start_mitmdump_button = tk.Button(button_frame, 
                                  text="Iniciar mitmdump", 
                                  command=lambda: ejecutar_mitmdump(mitmdump_result_text), 
                                  width=30, bg="#303030", fg="#03bf00")
start_mitmdump_button.grid(row=0, column=1, padx=5, pady=10)

# Es importante usar otro identificador para el botón de "Parar mitmdump"
stop_mitmdump_button = tk.Button(button_frame, 
                                 text="Detener mitmdump", 
                                 command=lambda: parar_mitmdump(mitmdump_result_text), 
                                 width=30, bg="#303030", fg="#03bf00")
stop_mitmdump_button.grid(row=1, column=1, padx=5, pady=10)

# Área de texto con scroll para mostrar resultados
mitmdump_result_text = scrolledtext.ScrolledText(modify_traffic_tab, 
                                                  width=100, height=20, 
                                                  bg="#303030", fg="#03bf00", 
                                                  insertbackground="white")
mitmdump_result_text.pack(pady=5)

# mitmdump_label = ttk.Label(modify_traffic_tab, text="Manejo de redirección de tráfico HTTP con mitmdump", font=("Arial", 16))
# mitmdump_label.pack(pady=10)
# start_ettercap_redireccion_button = tk.Button(modify_traffic_tab, text="Iniciar Ettercap", command=lambda: start_ettercap_en_hilo(mitmdump_result_text), width=30, bg="#303030", fg="#03bf00")
# start_ettercap_redireccion_button.pack(pady=10)
# stop_ettercap_redireccion_button = tk.Button(modify_traffic_tab, text="Detener Ettercap", command=lambda: stop_ettercap_en_hilo(mitmdump_result_text), width=30, bg="#303030", fg="#03bf00")
# stop_ettercap_redireccion_button.pack(pady=10)

# start_mitmdump_button = tk.Button(modify_traffic_tab, text="Iniciar mitmdump", command=lambda: ejecutar_mitmdump(mitmdump_result_text), width=30, bg="#303030", fg="#03bf00")
# start_mitmdump_button.pack(pady=10)
# start_mitmdump_button = tk.Button(modify_traffic_tab, text="Parar mitmdump", command=lambda: parar_mitmdump(mitmdump_result_text), width=30, bg="#303030", fg="#03bf00")
# start_mitmdump_button.pack(pady=10)
# mitmdump_result_text = scrolledtext.ScrolledText(modify_traffic_tab, width=100, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
# mitmdump_result_text.pack(pady=5)



#Contenido de la pestaña para iniciar el servidor con el formulario falso
interception_label = ttk.Label(start_fake_form_server, text="Manejo del servidor http", font=("Arial", 16))
interception_label.pack(pady=10)
start_http_server_button = tk.Button(start_fake_form_server, text="Iniciar http server", command=lambda: start_http_server_en_hilo(http_server_result_text), width=30, bg="#303030", fg="#03bf00")
start_http_server_button.pack(pady=10)
stop_http_server_button = tk.Button(start_fake_form_server, text="detener http server", command=lambda: stop_http_server(http_server_result_text), width=30, bg="#303030", fg="#03bf00")
stop_http_server_button.pack(pady=10)
http_server_result_text = scrolledtext.ScrolledText(start_fake_form_server, width=120, height=12, bg="#303030", fg="#03bf00", insertbackground="white")
http_server_result_text.pack(pady=5)
start_interception_button = tk.Button(start_fake_form_server, text="Actualizar consola", command=lambda: actualizar_consola_http_server(http_server_result_text), width=30, bg="#303030", fg="#03bf00")
start_interception_button.pack(pady=10)




#Contenido de la pestaña para iniciar el ataque DoS
DoS_label = ttk.Label(DoS_tab, text="Manejo de ataque DoS", font=("Arial", 16))
DoS_label.pack(pady=10)
DoS_ip_label = ttk.Label(DoS_tab, text="Dirección IP del objetivo:")
DoS_ip_label.pack(pady=5)
DoS_ip_entry = tk.Entry(DoS_tab, width=50, bg="#303030", fg="#03bf00")
DoS_ip_entry.pack(pady=5)
DoS_fake_ip_label = ttk.Label(DoS_tab, text="Dirección IP falsa para encubrimiento del ataque:")
DoS_fake_ip_label.pack(pady=5)
DoS_fake_ip_entry = tk.Entry(DoS_tab, width=50, bg="#303030", fg="#03bf00")
DoS_fake_ip_entry.pack(pady=5)
start_DoS_attack_button = tk.Button(DoS_tab, text="Iniciar ataque DoS", command=lambda: ejecutar_ataque_dos(DoS_attack_result_text, DoS_ip_entry, DoS_fake_ip_entry), width=30, bg="#303030", fg="#03bf00")
start_DoS_attack_button.pack(pady=10)
start_DoS_attack_button = tk.Button(DoS_tab, text="Parar ataque DoS", command=lambda: parar_ataque_dos(DoS_attack_result_text), width=30, bg="#303030", fg="#03bf00")
start_DoS_attack_button.pack(pady=10)
DoS_attack_result_text = scrolledtext.ScrolledText(DoS_tab, width=120, height=12, bg="#303030", fg="#03bf00", insertbackground="white")
DoS_attack_result_text.pack(pady=5)




#Contenido de la pestaña del generador de contraseñas seguras
pass_gen_label = ttk.Label(pass_generator_tab, text="Introduzca la longitud de la contraseña (longitud 12 recomendada)", font=("Arial", 16))
pass_gen_label.pack(pady=10)
pass_length_entry = tk.Entry(pass_generator_tab, width=20, bg="#303030", fg="#03bf00", font=("Arial", 16))
pass_length_entry.pack(pady=10)
pass_gen_label = ttk.Label(pass_generator_tab, text="Pulse el botón para crear una contraseña totalmente segura", font=("Arial", 16))
pass_gen_label.pack(pady=10)
list_devices_button = tk.Button(pass_generator_tab, text="Generar contraseña", command=lambda: generate_password(pass_entry, pass_length_entry), width=30, bg="#303030", fg="#03bf00")
list_devices_button.pack(pady=10)
pass_entry = tk.Entry(pass_generator_tab, width=50, bg="#303030", fg="#03bf00", font=("Arial", 14))
pass_entry.pack(pady=20)

#Contenido de la pestaña para escanear archivos maliciosos
pass_gen_label = ttk.Label(scan_virus_tab, text="Introduzca la ruta del archivo que quiere analizar", font=("Arial", 16))
pass_gen_label.pack(pady=10)
file_path_entry = tk.Entry(scan_virus_tab, width=50, bg="#303030", fg="#03bf00", font=("Arial", 14))
file_path_entry.pack(pady=20)
exec_scan_button = tk.Button(scan_virus_tab, text="Realizar escaneo", command=lambda: scan_for_virus(file_path_entry, analisis_result_text), width=30, bg="#303030", fg="#03bf00")
exec_scan_button.pack(pady=10)
analisis_result_text = scrolledtext.ScrolledText(scan_virus_tab, width=80, height=20, bg="#303030", fg="#03bf00", insertbackground="white")
analisis_result_text.pack(pady=5)

# Iniciar la GUI
root.mainloop()