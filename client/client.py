import socket
import threading
import json
import time
import os
import sys
import uuid
import logging
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("mesh_vpn")


class MeshVPNClient:
    def __init__(self, config_path=None):
        self.node_id = str(uuid.uuid4())
        self.peers = {}
        self.connections = {}
        self.running = False
        self.config = self.load_config(config_path)
        self.private_key = self.load_or_create_keys()

    def load_config(self, config_path):
        default_config = {
            "listen_port": 9000,
            "discovery_servers": ["mesh-discovery.example.com:8000"],
            "interface": "tun0",
            "subnet": "10.10.0.0/24",
            "local_ip": "10.10.0.1",
            "keepalive_interval": 15,
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)
                    return {**default_config, **config}
            except Exception as e:
                logger.error(f"Failed to load config: {e}")

        return default_config

    def load_or_create_keys(self):
        key_path = Path.home() / ".mesh_vpn" / "keys"
        key_path.mkdir(parents=True, exist_ok=True)
        private_key_path = key_path / "private_key.pem"

        if private_key_path.exists():
            # Load existing keys
            with open(private_key_path, "rb") as key_file:
                private_key = rsa.load_der_private_key(key_file.read(), password=None)
        else:
            # Generate new keys
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # Save the private key
            with open(private_key_path, "wb") as key_file:
                key_file.write(
                    private_key.private_bytes(
                        encoding=Encoding.DER,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption(),
                    )
                )

            # Save the public key
            public_key = private_key.public_key()
            with open(key_path / "public_key.pem", "wb") as key_file:
                key_file.write(
                    public_key.public_bytes(
                        encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
                    )
                )

        return private_key

    def discover_peers(self):
        """Connect to discovery servers to find peers"""
        for server in self.config["discovery_servers"]:
            try:
                host, port = server.split(":")
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((host, int(port)))
                    # Register with discovery server
                    registration = {
                        "node_id": self.node_id,
                        "listen_port": self.config["listen_port"],
                        "public_key": self.private_key.public_key()
                        .public_bytes(
                            encoding=Encoding.DER,
                            format=PublicFormat.SubjectPublicKeyInfo,
                        )
                        .hex(),
                    }
                    s.sendall(json.dumps(registration).encode() + b"\n")

                    # Get peer list
                    data = s.recv(4096)
                    peer_list = json.loads(data.decode())
                    for peer in peer_list:
                        if peer["node_id"] != self.node_id:
                            self.peers[peer["node_id"]] = peer
            except Exception as e:
                logger.error(f"Failed to discover peers via {server}: {e}")

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

    def connect_to_peer(self, peer_id, peer_info):
        """Establish connection to a peer"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((peer_info["host"], peer_info["listen_port"]))

            # TODO: Implement mutual authentication with SSL/TLS

            # Create a peer connection object
            connection = {
                "socket": s,
                "peer_id": peer_id,
                "last_seen": time.time(),
                "encrypt_thread": None,
                "decrypt_thread": None,
            }

            self.connections[peer_id] = connection

            # Start connection handling threads
            connection["encrypt_thread"] = threading.Thread(
                target=self.handle_outgoing_traffic, args=(peer_id,)
            )
            connection["decrypt_thread"] = threading.Thread(
                target=self.handle_incoming_traffic, args=(peer_id,)
            )

            connection["encrypt_thread"].daemon = True
            connection["decrypt_thread"].daemon = True

            connection["encrypt_thread"].start()
            connection["decrypt_thread"].start()

            logger.info(f"Connected to peer {peer_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            return False

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

    def handle_new_connection(self, client_socket, addr):
        """Handle a new incoming connection"""
        try:
            # TODO: Implement authentication

            # For now, just a simple handshake
            data = client_socket.recv(1024)
            handshake = json.loads(data.decode())

            if "node_id" in handshake:
                peer_id = handshake["node_id"]

                # Create connection object
                connection = {
                    "socket": client_socket,
                    "peer_id": peer_id,
                    "last_seen": time.time(),
                    "encrypt_thread": None,
                    "decrypt_thread": None,
                }

                self.connections[peer_id] = connection

                # Send response
                response = {"node_id": self.node_id, "status": "connected"}
                client_socket.sendall(json.dumps(response).encode())

                # Start handling threads
                connection["encrypt_thread"] = threading.Thread(
                    target=self.handle_outgoing_traffic, args=(peer_id,)
                )
                connection["decrypt_thread"] = threading.Thread(
                    target=self.handle_incoming_traffic, args=(peer_id,)
                )

                connection["encrypt_thread"].daemon = True
                connection["decrypt_thread"].daemon = True

                connection["encrypt_thread"].start()
                connection["decrypt_thread"].start()

                logger.info(f"Accepted connection from peer {peer_id}")
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

    def handle_incoming_traffic(self, peer_id):
        """Handle traffic coming from the peer"""
        # This would receive traffic from the peer and send to the tun interface
        connection = self.connections.get(peer_id)
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
            except socket.timeout:
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
    client = MeshVPNClient()
    client.start()
