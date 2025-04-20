import socket
import threading
import json
import time
import os
import sys
import uuid
import logging
import argparse
from pqxdh import PQXDHServer, PQXDHClient

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("mesh_vpn")

# parse args for -p (port) and -i (ip) as well as -c (config file)
parser = argparse.ArgumentParser(description="Mesh VPN Client")
parser.add_argument(
    "-p", "--port", type=int, default=9000, help="Port to listen on (default: 9000)"
)
parser.add_argument("-i", "--ip", type=str, default="10.10.0.1")
parser.add_argument(
    "-c",
    "--config",
    type=str,
    default=None,
    help="Path to config file (default: None)",
)
args = parser.parse_args()


def print_banner():
    """Print a banner with usage information"""
    banner = """
    ███████╗███╗   ███╗███████╗███████╗██╗  ██╗    ██╗   ██╗██████╗ ███╗   ██╗
    ██╔════╝████╗ ████║██╔════╝██╔════╝██║  ██║    ██║   ██║██╔══██╗████╗  ██║
    ███████╗██╔████╔██║█████╗  ███████╗███████║    ██║   ██║██████╔╝██╔██╗ ██║
    ╚════██║██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║    ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
    ███████║██║ ╚═╝ ██║███████╗███████║██║  ██║     ╚████╔╝ ██║     ██║ ╚████║
    ╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝      ╚═══╝  ╚═╝     ╚═╝  ╚═══╝
    
    Post-Quantum Secure Mesh VPN Client
    -----------------------------------
    """
    print(banner)


class MeshVPNClient:
    def __init__(self, config_path=None):
        self.node_id = str(uuid.uuid4())
        self.peers = {}
        self.connections = {}
        self.running = False
        self.config = self.load_config(config_path)
        self.discovery_connection: socket.socket = None

    def load_config(self, config_path):
        default_config = {
            "listen_port": 9000,
            "discovery_servers": ["127.0.0.1:8000"],
            "interface": "tun0",
            "subnet": "10.10.0.0/24",
            "local_ip": "10.10.0.1",
            "keepalive_interval": 15,
        }

        if args.ip:
            default_config["local_ip"] = args.ip
        if args.port:
            default_config["listen_port"] = args.port

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
                    return {**default_config, **config}
            except Exception as e:
                logger.error(f"Failed to load config: {e}")

        return default_config

    def discover_peers(self):
        """Connect to discovery servers to find peers"""
        for server in self.config["discovery_servers"]:
            try:
                # Register with discovery server
                registration = {
                    "node_id": self.node_id,
                    "listen_port": self.config["listen_port"],
                }

                logger.debug(
                    f"Registering with discovery server {server}: {registration}"
                )
                host, port = server.split(":")
                self.discovery_connection = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                self.discovery_connection.connect((host, int(port)))
                self.discovery_connection.settimeout(5)

                self.discovery_connection.sendall(
                    json.dumps(registration).encode() + b"\n"
                )

                # Get peer list
                data = self.discovery_connection.recv(4096)
                peer_list = json.loads(data.decode())
                for peer in peer_list:
                    if peer["node_id"] != self.node_id:
                        self.peers[peer["node_id"]] = peer
            except Exception as e:
                logger.error(f"Failed to discover peers via {server}: {e}")
                self.discovery_connection.close()
                self.discovery_connection = None

    def setup_virtual_interface(self):
        """Set up virtual network interface for VPN tunnel"""
        # This is platform-specific and would require different implementations
        # for Windows, Linux, MacOS, etc.
        # Example for Linux:
        try:
            if sys.platform.startswith("linux"):
                os.system(f"ip tuntap add dev {self.config['interface']} mode tun")
                os.system(
                    f"ip addr add {self.config['local_ip']}/24 dev {self.config['interface']}"
                )
                os.system(f"ip link set dev {self.config['interface']} up")
                logger.info(f"Virtual interface {self.config['interface']} set up")
            else:
                logger.warning(
                    f"Virtual interface setup not implemented for platform {sys.platform}"
                )
        except Exception as e:
            logger.error(f"Failed to set up virtual interface: {e}")

    def listen_for_connections(self):
        """Listen for incoming connections from peers"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("0.0.0.0", self.config["listen_port"]))
                s.listen()
                s.settimeout(1)  # Allow for checking self.running

                logger.info(
                    f"Listening for connections on port {self.config['listen_port']}"
                )

                while self.running:
                    try:
                        client_socket, addr = s.accept()
                        threading.Thread(
                            target=self.handle_new_connection,
                            args=(client_socket, addr),
                        ).start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"Failed to start listener: {e}")

    def handle_connection(self, peer_id, s: socket.socket, key: bytes):
        # Create a peer connection object
        connection = {
            "socket": s,
            "last_seen": time.time(),
            "encrypt_thread": None,
            "decrypt_thread": None,
            "key": key,
        }

        self.connections[peer_id] = connection

        # Start connection handling threads
        connection["encrypt_thread"] = threading.Thread(
            target=self.handle_outgoing_traffic, args=(peer_id,), daemon=True
        )

        connection["decrypt_thread"] = threading.Thread(
            target=self.handle_incoming_traffic, args=(peer_id,), daemon=True
        )

        connection["encrypt_thread"].start()
        connection["decrypt_thread"].start()

        logger.info(f"Connected to peer {peer_id}")

    def connect_to_peer(self, peer_id, peer_info):
        """Establish connection to a peer"""

        # TODO: Implement mutual authentication with SSL/TLS
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((peer_info["host"], peer_info["listen_port"]))

            # PQXDH key exchange
            client = PQXDHClient()
            keys = client.generate_keys()

            key_exchange = {
                "node_id": self.node_id,
                "classical_public": keys["classical_public"].hex(),
                "pq_public": keys["pq_public"].hex(),
            }

            logger.debug(f"Key exchange data: {key_exchange}")
            s.sendall(json.dumps(key_exchange).encode() + b"\n")

            resp = s.recv(4096)

            resp = json.loads(resp.decode())

            client.exchange(
                bytes.fromhex(resp["classical_public"]),
                bytes.fromhex(resp["ciphertext"]),
            )

            self.handle_connection(peer_id, s, client.shared_secret)
            return True
        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            return False

    def handle_new_connection(self, client_socket: socket.socket, addr):
        """Handle a new incoming connection"""
        try:
            # TODO: Implement authentication

            server = PQXDHServer()
            classical_public = server.generate_keys()

            # For now, just a simple handshake
            data = client_socket.recv(4096)
            handshake = json.loads(data.decode())

            if "node_id" in handshake:
                peer_id = handshake["node_id"]
                ciphertext = server.exchange(
                    bytes.fromhex(handshake["classical_public"]),
                    bytes.fromhex(handshake["pq_public"]),
                )

                key_exchange = {
                    "node_id": self.node_id,
                    "classical_public": classical_public["classical_public"].hex(),
                    "ciphertext": ciphertext.hex(),
                }

                client_socket.sendall(json.dumps(key_exchange).encode() + b"\n")

                self.handle_connection(peer_id, client_socket, server.shared_secret)
            else:
                client_socket.close()
                logger.warning(f"Rejected connection from {addr} - invalid handshake")
        except Exception as e:
            logger.error(f"Error handling new connection: {e}")
            client_socket.close()

    def handle_outgoing_traffic(self, peer_id):
        """Handle traffic going to the peer"""
        # This would capture traffic from the tun interface and forward to the peer
        pass

    def handle_incoming_traffic(self, peer_id: str):
        """Handle traffic coming from the peer"""
        # This would receive traffic from the peer and send to the tun interface
        connection = self.connections[peer_id]
        if not connection:
            return

        socket = connection["socket"]
        socket.settimeout(1)

        while self.running and peer_id in self.connections:
            try:
                data = socket.recv(4096)
                if not data:
                    self.remove_connection(peer_id)
                    break

                # Process received data
                # TODO: Write data to tun interface
                connection["last_seen"] = time.time()
            except TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error receiving data from peer {peer_id}: {e}")
                self.remove_connection(peer_id)
                break

    def remove_connection(self, peer_id):
        """Close and remove a peer connection"""
        if peer_id in self.connections:
            try:
                self.connections[peer_id]["socket"].close()
            except:
                pass
            del self.connections[peer_id]
            logger.info(f"Removed connection to peer {peer_id}")

    def start(self):
        """Start the VPN client"""
        self.running = True
        self.setup_virtual_interface()

        # Start listener thread
        listener_thread = threading.Thread(target=self.listen_for_connections)
        listener_thread.daemon = True
        listener_thread.start()

        # Start discovery and connection
        self.discover_peers()
        for peer_id, peer_info in self.peers.items():
            self.connect_to_peer(peer_id, peer_info)

        # Main maintenance loop
        try:
            while self.running:
                # Rediscover peers periodically
                if time.time() % 60 < 1:  # Roughly every minute
                    self.discover_peers()

                # Check connection health
                for peer_id in list(self.connections.keys()):
                    conn = self.connections.get(peer_id)
                    if not conn:
                        continue

                    # Reconnect if needed
                    if (
                        time.time() - conn["last_seen"]
                        > self.config["keepalive_interval"] * 3
                    ):
                        self.remove_connection(peer_id)
                        if peer_id in self.peers:
                            self.connect_to_peer(peer_id, self.peers[peer_id])

                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        finally:
            self.stop()

    def stop(self):
        """Stop the VPN client"""
        self.running = False

        # Close all connections
        for peer_id in list(self.connections.keys()):
            self.remove_connection(peer_id)

        # Clean up virtual interface
        if sys.platform.startswith("linux"):
            os.system(f"ip link set dev {self.config['interface']} down")
            os.system(f"ip tuntap del dev {self.config['interface']} mode tun")

        logger.info("VPN client stopped")


if __name__ == "__main__":
    print_banner()
    client = MeshVPNClient(args.config)
    client.start()
