import logging

logger = logging.getLogger(__name__)


def start_http_server(vpn_client, port=8080):
    """Start a simple HTTP server that can be tested with curl"""
    import threading
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class SimpleHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Basic routing
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()

                # Gather some useful status information
                peers_info = [
                    f"{peer_id} ({info.get('ip_address', 'unknown')})"
                    for peer_id, info in vpn_client.peers.items()
                ]
                active_connections = len(vpn_client.connections)

                response = (
                    f"SMESH-VPN is working!\n\n"
                    f"Node ID: {vpn_client.node_id}\n"
                    f"VPN IP: {vpn_client.config['local_ip']}\n"
                    f"Interface: {vpn_client.config['interface']}\n"
                    f"Connected peers: {active_connections}\n\n"
                    f"Known peers:\n" + "\n".join(f"- {p}" for p in peers_info) + "\n\n"
                )

                self.wfile.write(response.encode())
            elif self.path == "/ping":
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"pong")
            else:
                self.send_response(404)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Not found")

        def log_message(self, format, *args):
            # Redirect logs to our logger
            logger.info(f"HTTP: {format % args}")

    # Start HTTP server in a separate thread
    def run_server():
        server_address = ("0.0.0.0", port)
        httpd = HTTPServer(server_address, SimpleHandler)
        logger.info(f"Starting HTTP server on port {port}")
        try:
            httpd.serve_forever()
        except Exception as e:
            logger.error(f"HTTP server error: {e}")

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    return thread
