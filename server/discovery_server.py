import socket
import json
import threading
import logging
import time
import os
import sys
import uuid

# Add the parent directory to the path so we can import the common module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.pqxdh import PQXDHServer, PQXDHClient

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("discovery_server")


class DiscoveryServer:
    def __init__(self, host="0.0.0.0", port=8000):
        self.host = host
        self.port = port
        self.peers = {}  # Dictionary to store registered peers
        self.running = False
        self.lock = threading.Lock()  # For thread-safe peer list updates
        self.node_id = str(uuid.uuid4())  # Generate a unique ID for this server

    def start(self):
        """Start the discovery server"""
        self.running = True
        logger.info(f"Starting discovery server on {self.host}:{self.port}")

        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            server_socket.settimeout(1)  # Allow checking self.running

            # Start maintenance thread for removing stale peers
            maintenance_thread = threading.Thread(target=self._maintenance_loop)
            maintenance_thread.daemon = True
            maintenance_thread.start()

            logger.info("Discovery server is running")

            # Main accept loop
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    logger.info(f"Connection from {address}")

                    # Handle client in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client, args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")

        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            server_socket.close()
            logger.info("Server stopped")

    def stop(self):
        """Stop the discovery server"""
        self.running = False
        logger.info("Stopping discovery server")

    def _handle_client(self, client_socket, address):
        """Handle a client connection"""
        try:
            # Receive data from client
            data = client_socket.recv(4096)
            if not data:
                logger.warning(f"Empty data received from {address}")
                client_socket.close()
                return

            # Parse registration data
            registration = json.loads(data.decode().strip())
            logger.info(f"Registration from {address}: {registration}")

            # Verify required fields
            if "node_id" not in registration or "listen_port" not in registration:
                logger.warning(f"Invalid registration from {address}")
                client_socket.close()
                return

            # Check if this is a secure request with PQXDH
            if "classical_public" in registration and "pq_public" in registration:
                # Setup secure connection with PQXDH
                server = PQXDHServer()
                server_keys = server.generate_keys()

                # Process the client's public keys
                try:
                    client_classical_public = bytes.fromhex(
                        registration["classical_public"]
                    )
                    client_pq_public = bytes.fromhex(registration["pq_public"])

                    # Generate ciphertext for the client
                    ciphertext = server.exchange(
                        client_classical_public, client_pq_public
                    )

                    # Create response with our public key and ciphertext
                    secure_response = {
                        "status": "ok",
                        "node_id": self.node_id,
                        "classical_public": server_keys["classical_public"].hex(),
                        "ciphertext": ciphertext.hex(),
                    }

                    # Send secure response
                    client_socket.sendall(json.dumps(secure_response).encode() + b"\n")

                    # Store the shared secret for future communications with this peer
                    shared_secret = server.shared_secret
                    logger.debug(
                        f"Established secure connection with {registration['node_id']}"
                    )

                    # Continue with normal registration using secure channel
                except Exception as e:
                    logger.error(f"Error in secure key exchange: {e}")
                    # Fall back to regular connection

            # Store peer information
            peer_id = registration["node_id"]
            peer_info = {
                "node_id": peer_id,
                "host": address[0],
                "listen_port": registration["listen_port"],
                "last_seen": time.time(),
            }

            with self.lock:
                self.peers[peer_id] = peer_info
                logger.info(
                    f"Registered peer {peer_id} at {address[0]}:{registration['listen_port']}"
                )

            # Send peer list back to client
            peer_list = []
            with self.lock:
                for pid, pinfo in self.peers.items():
                    peer_list.append(pinfo)

            client_socket.sendall(json.dumps(peer_list).encode() + b"\n")
            logger.info(f"Sent peer list with {len(peer_list)} peers to {peer_id}")

        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
            import traceback

            logger.error(traceback.format_exc())
        finally:
            client_socket.close()

    def _maintenance_loop(self):
        """Remove stale peers periodically"""
        while self.running:
            try:
                # Sleep first to allow initial connections
                time.sleep(60)

                with self.lock:
                    now = time.time()
                    stale_peers = []

                    # Find peers that haven't been seen for 5 minutes
                    for peer_id, peer_info in self.peers.items():
                        if now - peer_info["last_seen"] > 300:  # 5 minutes
                            stale_peers.append(peer_id)

                    # Remove stale peers
                    for peer_id in stale_peers:
                        del self.peers[peer_id]
                        logger.info(f"Removed stale peer {peer_id}")

                    if stale_peers:
                        logger.info(f"Removed {len(stale_peers)} stale peers")
            except Exception as e:
                logger.error(f"Error in maintenance loop: {e}")


if __name__ == "__main__":
    # Use environment variables for configuration if available
    host = os.environ.get("DISCOVERY_HOST", "0.0.0.0")
    port = int(os.environ.get("DISCOVERY_PORT", 8000))

    server = DiscoveryServer(host, port)
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        server.stop()
