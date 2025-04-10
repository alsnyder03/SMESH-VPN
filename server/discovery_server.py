import socket
import threading
import json
import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("discovery_server")


class MeshVPNDiscoveryServer:
    def __init__(self, port=8000):
        self.port = port
        self.peers = {}
        self.lock = threading.Lock()
        self.running = False

    def start(self):
        """Start the discovery server"""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind(("0.0.0.0", self.port))
            self.server_socket.listen(5)
            logger.info(f"Discovery server listening on port {self.port}")

            # Start cleanup thread
            cleanup_thread = threading.Thread(target=self.cleanup_inactive_peers)
            cleanup_thread.daemon = True
            cleanup_thread.start()

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_handler = threading.Thread(
                        target=self.handle_client, args=(client_socket, address)
                    )
                    client_handler.daemon = True
                    client_handler.start()
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the discovery server"""
        self.running = False
        if hasattr(self, "server_socket"):
            self.server_socket.close()
        logger.info("Discovery server stopped")

    def handle_client(self, client_socket, address):
        """Handle client connection"""
        try:
            logger.info(f"New connection from {address}")
            data = client_socket.recv(4096)
            if not data:
                return

            peer_info = json.loads(data.decode())

            # Add external IP and timestamp
            peer_info["host"] = address[0]
            peer_info["last_seen"] = time.time()

            # Update peer list
            with self.lock:
                self.peers[peer_info["node_id"]] = peer_info

            # Send peer list to client
            peer_list = []
            with self.lock:
                for peer_id, info in self.peers.items():
                    # Don't send the client's own info back
                    if peer_id != peer_info["node_id"]:
                        # Clone and remove sensitive data
                        peer_data = info.copy()
                        peer_data.pop("last_seen", None)
                        peer_list.append(peer_data)

            client_socket.sendall(json.dumps(peer_list).encode())
            logger.info(f"Sent peer list to {address}")

        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def cleanup_inactive_peers(self):
        """Remove peers that haven't connected in a while"""
        while self.running:
            time.sleep(60)  # Check every minute
            current_time = time.time()
            inactive_peers = []

            with self.lock:
                for peer_id, info in self.peers.items():
                    # Remove peers inactive for more than 10 minutes
                    if current_time - info["last_seen"] > 600:
                        inactive_peers.append(peer_id)

                for peer_id in inactive_peers:
                    self.peers.pop(peer_id, None)

            if inactive_peers:
                logger.info(f"Removed {len(inactive_peers)} inactive peers")


if __name__ == "__main__":
    server = MeshVPNDiscoveryServer()
    server.start()
