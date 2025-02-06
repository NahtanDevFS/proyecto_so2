from mitmproxy import http

def request(flow: http.HTTPFlow):
    if flow.request.pretty_host == "www.google.com":
        flow.request.host = "192.168.1.210"
        flow.request.port = 9000
        flow.request.scheme = "http"