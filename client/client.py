import socket
import threading
import json
import time
import os
import sys
import uuid
import logging
import argparse
import struct
import atexit
import signal
import base64
from pathlib import Path

# Add the parent directory to the path so we can import the common module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.pqxdh import PQXDHServer, PQXDHClient
from common.aesgcm import decrypt_aes_gcm, encrypt_aes_gcm
from tunnel import Tunnel
from http_server import start_http_server
from common.certificates import CertificateAuthority

from ipaddress import IPv4Address, IPv4Network

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("mesh_vpn")

# Packet type constants
PACKET_TYPE_DATA = 0
PACKET_TYPE_KEEPALIVE = 1

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
parser.add_argument(
    "--interface",
    type=str,
    default="tun_smesh0",
    help="Name of TUN interface to create (default: tun_smesh0)",
)
parser.add_argument(
    "-d", "--discovery", type=str, help="Discovery server address (format: host:port)"
)
parser.add_argument(
    "--http-server",
    action="store_true",
    help="Start HTTP server for testing",
)
parser.add_argument(
    "--http-port",
    type=int,
    default=8080,
    help="Port for the HTTP server (default: 8080)",
)
parser.add_argument(
    "--cert-dir", type=str, help="Directory containing client certificates"
)
parser.add_argument(
    "--client-id",
    type=str,
    help="Client ID for certificate authentication (defaults to node_id if not specified)",
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
    print(banner.replace(" ", "\u00a0"))


class MeshVPNClient:
    def __init__(self, config_path=None):
        self.node_id = str(uuid.uuid4())

        self.peers = {}
        self.connections = {}
        self.running = False
        self.config = self.load_config(config_path)
        self.discovery_connection: socket.socket = None
        self.tunnel: Tunnel | None = None  # Use the Tunnel type hint
        self.last_keepalive_check = time.time()  # Track last keepalive check time
        self.ca = CertificateAuthority(
            ca_dir=self.config.get("cert_dir"), create_if_missing=False
        )

        # Load client certificates if specified
        self.client_cert = None
        self.client_key = None
        self.ca_cert = None

        self.load_certificates()

    def load_config(self, config_path):
        default_config = {
            "listen_port": 9000,
            "discovery_servers": ["127.0.0.1:8000"],
            "interface": "smesh_tun0",
            "subnet": IPv4Network("10.10.0.0/24"),
            "local_ip": IPv4Address("10.10.0.1"),
            "keepalive_interval": 15,
            "cert_dir": None,
            "client_id": None,
        }

        # Override with command line arguments
        if args.ip:
            print(f"IP address from command line: {args.ip}")
            ip = IPv4Address(args.ip)
            if ip in default_config["subnet"]:
                default_config["local_ip"] = ip
        if args.port:
            default_config["listen_port"] = args.port
        if args.interface:
            default_config["interface"] = args.interface
        if args.discovery:
            default_config["discovery_servers"] = [args.discovery]
            logger.info(
                f"Using discovery server from command line: {default_config['discovery_servers']}"
            )
        if args.cert_dir:
            default_config["cert_dir"] = args.cert_dir
        if args.client_id:
            default_config["client_id"] = args.client_id
            # Use the client ID as the node ID for certificate auth
            self.node_id = args.client_id

        # Load from config file (lowest priority)
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    config = json.load(f)

                    # If client_id specified in config, use it as the node_id
                    if "client_id" in config and config["client_id"]:
                        self.node_id = config["client_id"]

                    return {**default_config, **config}
            except Exception as e:
                logger.error(f"Failed to load config: {e}")

        # Override with environment variables if available
        if "DISCOVERY_SERVER" in os.environ:
            default_config["discovery_servers"] = [os.environ["DISCOVERY_SERVER"]]
            logger.info(
                f"Using discovery server from environment: {default_config['discovery_servers']}"
            )
        if "PORT" in os.environ:
            default_config["listen_port"] = int(os.environ["PORT"])
            logger.info(f"Using port from environment: {default_config['listen_port']}")
        if "IP_ADDRESS" in os.environ:
            ip = IPv4Address(os.environ["IP_ADDRESS"])
            if ip in default_config["subnet"]:
                default_config["local_ip"] = ip
                logger.info(f"Using IP from environment: {default_config['local_ip']}")
        if "INTERFACE_NAME" in os.environ:
            default_config["interface"] = os.environ["INTERFACE_NAME"]
            logger.info(
                f"Using interface name from environment: {default_config['interface']}"
            )
        if "CERT_DIR" in os.environ:
            default_config["cert_dir"] = os.environ["CERT_DIR"]
            logger.info(
                f"Using certificate directory from environment: {default_config['cert_dir']}"
            )
        if "CLIENT_ID" in os.environ:
            default_config["client_id"] = os.environ["CLIENT_ID"]
            # Use the client ID as the node ID for certificate auth
            self.node_id = os.environ["CLIENT_ID"]
            logger.info(f"Using client ID from environment: {self.node_id}")

        return default_config

    def load_certificates(self):
        """Load client certificates from the specified directory or environment variables"""
        cert_dir = self.config.get("cert_dir")
        client_id = self.config.get("client_id") or self.node_id

        # First try to load certificates from environment variables
        if "CLIENT_CERT" in os.environ and "CLIENT_KEY" in os.environ:
            try:
                self.client_cert = base64.b64decode(os.environ["CLIENT_CERT"])
                self.client_key = base64.b64decode(os.environ["CLIENT_KEY"])

                if "CA_CERT" in os.environ:
                    self.ca_cert = base64.b64decode(os.environ["CA_CERT"])

                logger.info(
                    f"Loaded client certificate from environment variables for ID: {client_id}"
                )

                return
            except Exception as e:
                logger.error(
                    f"Error loading certificates from environment variables: {e}"
                )

        # If environment variables aren't set, try to load from files
        if not cert_dir:
            logger.warning(
                "No certificate directory specified, will try to connect without certificates"
            )
            return

        cert_dir_path = Path(cert_dir)
        if not cert_dir_path.exists():
            logger.error(f"Certificate directory {cert_dir} does not exist")
            return

        try:
            # Try to load from client subdirectory if it exists
            client_dir = cert_dir_path / "clients" / client_id
            if client_dir.exists():
                cert_path = client_dir / "client_cert.pem"
                key_path = client_dir / "client_key.pem"
                ca_path = client_dir / "ca_cert.pem"

                # If ca_cert.pem doesn't exist in the client directory, check the main CA directory
                if not ca_path.exists():
                    ca_path = cert_dir_path / "ca_cert.pem"
            else:
                # Otherwise, try to load from the main directory
                cert_path = cert_dir_path / "client_cert.pem"
                key_path = cert_dir_path / "client_key.pem"
                ca_path = cert_dir_path / "ca_cert.pem"

            # Load the certificate files
            if cert_path.exists() and key_path.exists():
                with open(cert_path, "rb") as f:
                    self.client_cert = f.read()
                with open(key_path, "rb") as f:
                    self.client_key = f.read()

                if ca_path.exists():
                    with open(ca_path, "rb") as f:
                        self.ca_cert = f.read()
                    logger.info(f"Loaded CA certificate from {ca_path}")
                else:
                    logger.error(f"CA certificate not found at {ca_path}")

                logger.info(f"Loaded client certificate for ID: {client_id}")
            else:
                logger.error(f"Client certificate files not found in {cert_dir}")

        except Exception as e:
            logger.error(f"Error loading certificates: {e}")
            import traceback

            logger.error(traceback.format_exc())

    def discover_peers(self):
        """Connect to discovery servers to find peers with secure key exchange and decryption"""
        for server in self.config["discovery_servers"]:
            try:
                # Perform PQXDH key exchange
                client = PQXDHClient()
                keys = client.generate_keys()

                # Register with discovery server
                registration = {
                    "node_id": self.node_id,
                    "ip_address": str(self.config["local_ip"]),
                    "listen_port": self.config["listen_port"],
                    "classical_public": keys["classical_public"].hex(),
                    "pq_public": keys["pq_public"].hex(),
                }

                # Add certificate if available
                if self.client_cert:
                    registration["certificate"] = base64.b64encode(
                        self.client_cert
                    ).decode("utf-8")

                    # Add digital signature to prove ownership of the private key
                    if self.client_key:
                        try:
                            # Create a message to sign that includes key exchange data
                            # This binds the signature to this specific connection request
                            message = f"{self.node_id}:{keys['classical_public'].hex()}:{keys['pq_public'].hex()}".encode()

                            # Use the existing certificate.py functionality
                            from cryptography.hazmat.primitives.serialization import (
                                load_pem_private_key,
                            )
                            from cryptography.hazmat.primitives.asymmetric import (
                                padding,
                            )
                            from cryptography.hazmat.primitives import hashes

                            # Load the private key
                            private_key = load_pem_private_key(
                                self.client_key, password=None
                            )

                            # Sign the message
                            signature = private_key.sign(
                                message,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256(),
                            )

                            # Add signature and message to registration data
                            registration["signature"] = base64.b64encode(
                                signature
                            ).decode("utf-8")
                            registration["signed_message"] = base64.b64encode(
                                message
                            ).decode("utf-8")

                            logger.debug("Added digital signature to registration data")
                        except Exception as e:
                            logger.error(f"Failed to sign registration data: {e}")
                else:
                    logger.warning(
                        "No client certificate available. Authentication may fail."
                    )

                logger.debug(
                    f"Registering with discovery server {server}: {registration}"
                )
                host, port = server.split(":")
                self.discovery_connection = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM
                )
                self.discovery_connection.connect((host, int(port)))
                self.discovery_connection.settimeout(5)

                # Send registration data with length prefix
                registration_data = json.dumps(registration).encode()
                data_length = len(registration_data).to_bytes(4, byteorder="big")
                self.discovery_connection.sendall(data_length + registration_data)

                # Read the length prefix (4 bytes)
                length_bytes = self.discovery_connection.recv(4)
                if not length_bytes or len(length_bytes) < 4:
                    logger.error(f"No valid response length received from {server}")
                    if self.discovery_connection:
                        self.discovery_connection.close()
                        self.discovery_connection = None
                    continue

                # Get the actual length and read exactly that many bytes
                response_length = int.from_bytes(length_bytes, byteorder="big")

                # Sanity check on response size
                if response_length <= 0 or response_length > 1048576:  # Max 1MB
                    logger.error(
                        f"Invalid response length {response_length} from server {server}"
                    )
                    if self.discovery_connection:
                        self.discovery_connection.close()
                        self.discovery_connection = None
                    continue

                # Read the complete response based on the length
                data = b""
                remaining = response_length
                while remaining > 0:
                    chunk = self.discovery_connection.recv(min(4096, remaining))
                    if not chunk:
                        logger.error(
                            f"Connection closed by server {server} before receiving complete response"
                        )
                        if self.discovery_connection:
                            self.discovery_connection.close()
                            self.discovery_connection = None
                        continue
                    data += chunk
                    remaining -= len(chunk)

                try:
                    server_response = json.loads(data.decode("utf-8"))
                    logger.debug(f"Decoded server response: {server_response}")

                    # Check if server rejected the connection
                    if server_response.get("status") == "error":
                        error_msg = server_response.get("error", "Unknown error")
                        logger.error(f"Server rejected connection: {error_msg}")
                        self.discovery_connection.close()
                        self.discovery_connection = None
                        continue

                except (UnicodeDecodeError, json.JSONDecodeError) as e:
                    logger.error(f"Failed to decode server response from {server}: {e}")

                server_classical_public = bytes.fromhex(
                    server_response["classical_public"]
                )
                server_ciphertext = bytes.fromhex(server_response["ciphertext"])

                # Derive shared secret
                retries = 3
                while retries > 0:
                    try:
                        client.exchange(server_classical_public, server_ciphertext)
                        shared_secret = client.shared_secret
                        break
                    except Exception as e:
                        logger.warning(
                            f"Key exchange failed, retrying... ({3 - retries + 1}/3)"
                        )
                        retries -= 1
                        time.sleep(1)
                if retries == 0:
                    logger.error("Key exchange failed after retries")
                    continue

                # Receive encrypted peer list with length prefix
                length_bytes = self.discovery_connection.recv(4)
                if not length_bytes or len(length_bytes) < 4:
                    logger.error(f"No valid peer list length received from {server}")
                    self.discovery_connection.close()
                    self.discovery_connection = None
                    continue

                peer_list_length = int.from_bytes(length_bytes, byteorder="big")

                # Sanity check on peer list size
                if peer_list_length <= 0 or peer_list_length > 1048576:  # Max 1MB
                    logger.error(
                        f"Invalid peer list length {peer_list_length} from server {server}"
                    )
                    self.discovery_connection.close()
                    self.discovery_connection = None
                    continue

                # Read the complete peer list based on the length
                encrypted_data = b""
                remaining = peer_list_length
                while remaining > 0:
                    chunk = self.discovery_connection.recv(min(4096, remaining))
                    if not chunk:
                        logger.error(
                            f"Connection closed by server {server} before receiving complete peer list"
                        )
                        self.discovery_connection.close()
                        self.discovery_connection = None
                        continue
                    encrypted_data += chunk
                    remaining -= len(chunk)

                if isinstance(encrypted_data, bytes):
                    try:
                        plaintext = decrypt_aes_gcm(shared_secret, encrypted_data)
                        peer_list = json.loads(plaintext.decode("utf-8"))
                    except Exception as e:
                        logger.error(
                            f"Failed to decrypt or decode server response: {e}"
                        )
                        self.discovery_connection.close()
                        return

                # Process the peer list
                if isinstance(peer_list, list):
                    for peer in peer_list:
                        # Check if the peer is not self
                        if peer["node_id"] != self.node_id:
                            self.peers[peer["node_id"]] = peer
                        else:
                            logger.debug(f"Excluded self from peer list: {peer}")
                    logger.info(
                        f"Discovered {len(self.peers)} peers from discovery server"
                    )
                else:
                    logger.error(
                        "Unexpected decrypted peer list format. Expected a list."
                    )

            except ValueError as ve:
                logger.error(f"Value error during peer discovery via {server}: {ve}")
            except Exception as e:
                logger.error(f"Failed to discover peers via {server}: {e}")
            finally:
                if self.discovery_connection:
                    self.discovery_connection.close()
                self.discovery_connection = None

    def setup_virtual_interface(self):
        """Set up virtual network interface using the Tunnel class."""
        try:
            self.tunnel = Tunnel(
                interface_name=self.config["interface"],
                local_ip=str(self.config["local_ip"]),
                prefix_len=str(self.config["subnet"].prefixlen),
            )
            if self.tunnel.setup():
                logger.info(
                    f"Virtual interface {self.config['interface']} set up via Tunnel class."
                )
                self.tunnel.start()  # Start the tunnel after setup
            else:
                logger.error(
                    f"Failed to set up virtual interface {self.config['interface']} via Tunnel class."
                )
                self.tunnel = None  # Ensure tunnel is None if setup failed

        except Exception as e:
            logger.error(f"Failed to set up virtual interface: {e}")
            if hasattr(e, "errno") and e.errno == 1:  # Operation not permitted
                logger.error("Permission denied. Try running with sudo or use setcap.")
            self.tunnel = None  # Ensure tunnel is None on exception

    def listen_for_connections(self):
        """Listen for incoming connections from peers"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                # Add this line to allow socket reuse
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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
        current_time = time.time()
        connection = {
            "socket": s,
            "last_seen": current_time,
            "last_received": current_time,  # Track when we last received data
            "keepalive_thread": None,
            "decrypt_thread": None,
            "key": key,
        }

        self.connections[peer_id] = connection

        # Get peer IP information from peers dictionary if available
        peer_info = self.peers.get(peer_id, {})

        self.register_ip_callbacks(peer_id, peer_info)

        # Start connection handling threads
        connection["keepalive_thread"] = threading.Thread(
            target=self.keepalive_loop, args=(peer_id,), daemon=True
        )

        connection["decrypt_thread"] = threading.Thread(
            target=self.handle_incoming_traffic, args=(peer_id,), daemon=True
        )

        connection["keepalive_thread"].start()
        connection["decrypt_thread"].start()

        logger.info(f"Connected to peer {peer_id}")

    def connect_to_peer(self, peer_id, peer_info):
        """Establish connection to a peer"""
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
                "ip_address": self.config["local_ip"].compressed,
            }

            # Add certificate - now required for authentication
            if self.client_cert:
                key_exchange["certificate"] = base64.b64encode(self.client_cert).decode(
                    "utf-8"
                )

                # Add digital signature to prove ownership of the private key
                if self.client_key:
                    try:
                        # Create a message to sign that includes key exchange data
                        # This binds the signature to this specific connection request
                        message = f"{self.node_id}:{keys['classical_public'].hex()}:{keys['pq_public'].hex()}".encode()

                        # Load the private key
                        from cryptography.hazmat.primitives.serialization import (
                            load_pem_private_key,
                        )
                        from cryptography.hazmat.primitives.asymmetric import padding
                        from cryptography.hazmat.primitives import hashes

                        private_key = load_pem_private_key(
                            self.client_key, password=None
                        )

                        # Sign the message
                        signature = private_key.sign(
                            message,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH,
                            ),
                            hashes.SHA256(),
                        )

                        # Add signature and message to key exchange data
                        key_exchange["signature"] = base64.b64encode(signature).decode(
                            "utf-8"
                        )
                        key_exchange["signed_message"] = base64.b64encode(
                            message
                        ).decode("utf-8")

                        logger.debug(
                            "Added digital signature to peer connection request"
                        )
                    except Exception as e:
                        logger.error(f"Failed to sign peer connection data: {e}")
            else:
                logger.error("No client certificate available - cannot connect to peer")
                s.close()
                return False

            # Send key exchange data with length prefix
            exchange_data = json.dumps(key_exchange).encode()
            data_length = len(exchange_data).to_bytes(4, byteorder="big")
            s.sendall(data_length + exchange_data)

            # Receive peer's key exchange response - strictly require length prefix
            data_length_bytes = s.recv(4)
            if not data_length_bytes or len(data_length_bytes) < 4:
                logger.error(f"No valid response from peer {peer_id}")
                s.close()
                return False

            # Parse the message length
            data_length = int.from_bytes(data_length_bytes, byteorder="big")

            # Sanity check on message size
            if data_length <= 0 or data_length > 1048576:  # Max 1MB
                logger.error(
                    f"Invalid response length {data_length} from peer {peer_id}"
                )
                s.close()
                return False

            # Read the complete message based on the length
            response_data = b""
            remaining = data_length

            while remaining > 0:
                chunk = s.recv(min(4096, remaining))
                if not chunk:
                    logger.error(
                        f"Connection closed by peer {peer_id} before receiving complete response"
                    )
                    s.close()
                    return False
                response_data += chunk
                remaining -= len(chunk)

            try:
                peer_response = json.loads(response_data.decode("utf-8"))
                logger.debug(
                    f"Received key exchange response from peer: {peer_response}"
                )

                # Check if peer rejected the connection
                if peer_response.get("status") == "error":
                    error_msg = peer_response.get("error", "Unknown error")
                    logger.error(f"Peer {peer_id} rejected connection: {error_msg}")
                    s.close()
                    return False

                # Verify peer's certificate if available
                if "certificate" in peer_response:
                    try:
                        peer_cert = base64.b64decode(peer_response["certificate"])

                        # Verify the peer's certificate
                        if not self.ca.verify_client_certificate(peer_id, peer_cert):
                            logger.error(
                                f"Peer {peer_id} provided an invalid certificate"
                            )
                            s.close()
                            return False

                        logger.info(
                            f"Successfully verified certificate for peer {peer_id}"
                        )
                    except Exception as e:
                        logger.error(f"Error verifying peer certificate: {e}")
                        s.close()
                        return False
                else:
                    logger.error(f"Peer {peer_id} did not provide a certificate")
                    s.close()
                    return False
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON response from peer {peer_id}: {e}")
                s.close()
                return False

            # Extract peer's public keys
            peer_classical_public = bytes.fromhex(peer_response["classical_public"])
            peer_ciphertext = bytes.fromhex(peer_response["ciphertext"])

            # Complete the key exchange
            try:
                client.exchange(peer_classical_public, peer_ciphertext)
            except Exception as e:
                logger.error(f"PQXDH key exchange failed with peer {peer_id}: {e}")
                s.close()
                return False

            # Successful key exchange, get the shared secret
            key = client.shared_secret

            # Set up connection
            self.handle_connection(peer_id, s, key)
            return True

        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            return False

    def handle_new_connection(self, client_socket: socket.socket, addr):
        """Handle a new incoming connection"""
        try:
            # Set up the PQXDH server for key exchange
            server = PQXDHServer()
            classical_public = server.generate_keys()

            # Read the handshake data using length-prefixed protocol
            try:
                # First read exactly 4 bytes for the length prefix
                length_prefix = client_socket.recv(4)
                if not length_prefix or len(length_prefix) < 4:
                    logger.error(f"No valid length prefix received from {addr}")
                    client_socket.close()
                    return

                # Parse the message length
                message_length = int.from_bytes(length_prefix, byteorder="big")

                # Sanity check on message size
                if message_length <= 0 or message_length > 1048576:  # Max 1MB
                    logger.error(f"Invalid message length {message_length} from {addr}")
                    self._send_error(client_socket, "Invalid message length")
                    client_socket.close()
                    return

                # Read the complete message based on the length
                data = b""
                remaining = message_length

                while remaining > 0:
                    chunk = client_socket.recv(min(4096, remaining))
                    if not chunk:
                        logger.error(
                            f"Connection closed before complete message received from {addr}"
                        )
                        client_socket.close()
                        return
                    data += chunk
                    remaining -= len(chunk)

                # Parse the JSON data
                handshake = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(f"Invalid handshake data from {addr}: {e}")
                if isinstance(e, json.JSONDecodeError) and hasattr(e, "doc") and e.doc:
                    # Log a portion of the problematic data for debugging
                    error_context = e.doc[
                        max(0, e.pos - 50) : min(len(e.doc), e.pos + 50)
                    ]
                    logger.error(f"Context around error: {repr(error_context)}")
                self._send_error(client_socket, "Invalid handshake format")
                client_socket.close()
                return
            except Exception as e:
                logger.error(f"Error reading handshake data: {e}")
                client_socket.close()
                return

            # Now handle the handshake data
            if "node_id" in handshake:
                peer_id = handshake["node_id"]
                peer_ip = handshake["ip_address"]

                # Certificate-based mutual authentication - REQUIRE certificate
                if "certificate" not in handshake:
                    logger.error(
                        f"Rejecting connection from {peer_id}: No certificate provided"
                    )
                    self._send_error(
                        client_socket, "Certificate required for authentication"
                    )
                    client_socket.close()
                    return

                # Verify the peer's certificate
                try:
                    cert_dir = self.config.get("cert_dir")
                    if not cert_dir:
                        logger.error(
                            "No CA directory specified - cannot verify peer certificates"
                        )
                        self._send_error(
                            client_socket,
                            "Server not configured for certificate verification",
                        )
                        client_socket.close()
                        return

                    client_cert = base64.b64decode(handshake["certificate"])

                    # Verify certificate using the CA
                    if not self.ca.verify_client_certificate(peer_id, client_cert):
                        logger.error(
                            f"Rejecting connection from {peer_id}: Invalid certificate"
                        )
                        self._send_error(client_socket, "Certificate validation failed")
                        client_socket.close()
                        return

                    logger.info(f"Successfully verified certificate for peer {peer_id}")

                    # Verify signature to confirm possession of the private key
                    if "signature" in handshake and "signed_message" in handshake:
                        try:
                            from cryptography.hazmat.primitives.asymmetric import (
                                padding,
                            )
                            from cryptography.hazmat.primitives import hashes
                            from cryptography.exceptions import InvalidSignature

                            # Load the certificate and extract the public key
                            cert = CertificateAuthority.load_certificate_from_pem(
                                client_cert
                            )
                            public_key = cert.public_key()

                            # Get signature and message
                            signature = base64.b64decode(handshake["signature"])
                            message = base64.b64decode(handshake["signed_message"])

                            try:
                                # Verify the signature
                                public_key.verify(
                                    signature,
                                    message,
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH,
                                    ),
                                    hashes.SHA256(),
                                )
                                logger.info(
                                    f"Successfully verified signature from peer {peer_id}"
                                )
                            except InvalidSignature:
                                logger.error(f"Invalid signature from peer {peer_id}")
                                self._send_error(client_socket, "Invalid signature")
                                client_socket.close()
                                return
                        except Exception as e:
                            logger.error(f"Error verifying peer signature: {e}")
                            self._send_error(
                                client_socket, "Signature verification error"
                            )
                            client_socket.close()
                            return
                    else:
                        logger.warning(
                            f"Peer {peer_id} did not provide a signature - authentication incomplete"
                        )
                        # For backward compatibility, we'll allow connections without signatures
                        # but will log a warning. In a future version, this should be required.

                except Exception as e:
                    logger.error(f"Error verifying peer certificate: {e}")
                    self._send_error(client_socket, "Certificate verification error")
                    client_socket.close()
                    return

                # Continue with PQXDH key exchange
                ciphertext = server.exchange(
                    bytes.fromhex(handshake["classical_public"]),
                    bytes.fromhex(handshake["pq_public"]),
                )

                # Add IP address to peer info
                if peer_id not in self.peers:
                    self.peers[peer_id] = {
                        "ip_address": peer_ip,
                    }

                # Send our response with key exchange data and certificate
                key_exchange = {
                    "node_id": self.node_id,
                    "classical_public": classical_public["classical_public"].hex(),
                    "ciphertext": ciphertext.hex(),
                    "status": "authorized",
                }

                # Include our certificate for mutual authentication
                if self.client_cert:
                    key_exchange["certificate"] = base64.b64encode(
                        self.client_cert
                    ).decode("utf-8")
                else:
                    logger.error("No client certificate available to send to peer")
                    self._send_error(
                        client_socket,
                        "Server not properly configured with a certificate",
                    )
                    client_socket.close()
                    return

                response_data = json.dumps(key_exchange).encode()
                # Send with length prefix
                response_length = len(response_data)
                client_socket.sendall(response_length.to_bytes(4, byteorder="big"))
                client_socket.sendall(response_data)

                # Handle the established connection
                self.handle_connection(peer_id, client_socket, server.shared_secret)
            else:
                client_socket.close()
                logger.warning(f"Rejected connection from {addr} - invalid handshake")
        except Exception as e:
            logger.error(f"Error handling new connection: {e}")
            client_socket.close()

    def _send_error(self, client_socket, error_message):
        """Send an error response to the client"""
        error_response = {"status": "error", "error": error_message}
        try:
            # Use length-prefixed format for error responses
            response_data = json.dumps(error_response).encode()
            response_length = len(response_data).to_bytes(4, byteorder="big")
            client_socket.sendall(response_length + response_data)
        except Exception as e:
            logger.error(f"Error sending error response: {e}")

    def handle_incoming_traffic(self, peer_id: str):
        """Handle incoming traffic from a specific peer."""
        connection = self.connections.get(peer_id)
        if not connection:
            return

        sock = connection["socket"]
        key = connection["key"]

        # Set a small timeout on the socket to make it non-blocking with timeout
        sock.settimeout(0.1)

        if not self.tunnel:
            logger.error("Tunnel not initialized for incoming traffic.")
            return

        buffer = b""
        expected_length = None

        try:
            while self.running and peer_id in self.connections:
                try:
                    # Direct approach with socket timeout instead of select
                    try:
                        chunk = sock.recv(4096)
                        if not chunk:
                            # Connection closed by peer
                            if peer_id in self.connections:
                                logger.warning(f"Connection closed by peer {peer_id}.")
                                self.remove_connection(peer_id)
                            break

                        # Update activity timestamps - specifically tracking when we RECEIVED data
                        current_time = time.time()
                        connection["last_received"] = (
                            current_time  # Explicitly track when we received data
                        )
                        connection["last_seen"] = current_time
                        buffer += chunk
                    except socket.timeout:
                        # No data available within timeout period, just continue loop
                        # Check if connection still exists
                        if peer_id not in self.connections:
                            break
                        continue

                    # Process complete packets from the buffer - always using length-prefixed format
                    while True:
                        if expected_length is None:
                            # Need at least 4 bytes for the length prefix
                            if len(buffer) >= 4:
                                expected_length = int.from_bytes(
                                    buffer[:4], byteorder="big"
                                )
                                # Sanity check on length to avoid excessive memory usage
                                if (
                                    expected_length <= 0 or expected_length > 1048576
                                ):  # Max 1MB
                                    logger.error(
                                        f"Invalid packet length {expected_length} from peer {peer_id}"
                                    )
                                    self.remove_connection(peer_id)
                                    break
                                buffer = buffer[
                                    4:
                                ]  # Remove the length prefix from buffer
                            else:
                                break  # Need more data for length

                        if len(buffer) >= expected_length:
                            # We have a complete packet
                            encrypted_packet = buffer[:expected_length]
                            buffer = buffer[expected_length:]
                            expected_length = None  # Reset for next packet

                            # Check connection status before decrypting/writing
                            if peer_id not in self.connections:
                                break

                            try:
                                packet = decrypt_aes_gcm(key, encrypted_packet)

                                # Check for keepalive packet (first byte is packet type)
                                if (
                                    len(packet) > 0
                                    and packet[0] == PACKET_TYPE_KEEPALIVE
                                ):
                                    logger.debug(
                                        f"Received keepalive packet from peer {peer_id}"
                                    )
                                    continue  # Skip further processing for keepalives

                                if len(packet) > 0 and packet[0] == PACKET_TYPE_DATA:
                                    # Remove the packet type byte for data packets
                                    packet = packet[1:]

                                logger.debug(
                                    f"Decrypted {len(packet)} bytes from peer {peer_id}"
                                )
                                self.tunnel.write(packet)
                            except ValueError as e:
                                logger.error(
                                    f"Decryption error for peer {peer_id}: {e}"
                                )
                                # Continue processing other packets
                            except Exception as e:
                                if peer_id in self.connections:
                                    logger.error(
                                        f"Error writing to tunnel for peer {peer_id}: {e}"
                                    )
                                    import traceback

                                    logger.error(traceback.format_exc())
                                    self.remove_connection(peer_id)
                                break
                        else:
                            break  # Need more data for the packet

                    # Connection status check after processing packets
                    if peer_id not in self.connections:
                        break

                except ConnectionResetError:
                    if peer_id in self.connections:
                        logger.warning(f"Connection reset by peer {peer_id}.")
                        self.remove_connection(peer_id)
                    break
                except Exception as e:
                    if peer_id in self.connections:
                        logger.error(f"Error processing data from peer {peer_id}: {e}")
                        import traceback

                        logger.error(traceback.format_exc())
                        self.remove_connection(peer_id)
                    break
        except Exception as e:
            if peer_id in self.connections:
                logger.error(
                    f"Unhandled error in incoming traffic handler for {peer_id}: {e}"
                )
                import traceback

                logger.error(traceback.format_exc())
                self.remove_connection(peer_id)

    def remove_connection(self, peer_id: str):
        """Close and remove a peer connection"""
        if peer_id in self.connections:
            try:
                try:
                    self.connections[peer_id]["socket"].close()
                except:
                    pass
                del self.connections[peer_id]
                logger.info(f"Removed connection to peer {peer_id}")
            except Exception as e:
                logger.error(f"Error removing connection to peer {peer_id}: {e}")

    def send_keepalive(self, peer_id: str):
        """Send a keepalive packet to a specific peer"""
        connection = self.connections.get(peer_id)
        if not connection or not self.running:
            return False

        try:
            sock = connection["socket"]
            key = connection["key"]

            # Create a simple keepalive packet
            # Format: 1-byte packet type (1 for keepalive)
            keepalive_packet = struct.pack("!B", PACKET_TYPE_KEEPALIVE)

            # Encrypt the keepalive packet using the common utility function
            encrypted_data = encrypt_aes_gcm(key, keepalive_packet)

            # Send the packet with its length prefix
            packet_length = len(encrypted_data).to_bytes(4, byteorder="big")
            sock.sendall(packet_length + encrypted_data)

            logger.debug(f"Sent keepalive packet to peer {peer_id}")
            return True
        except Exception as e:
            logger.error(f"Error sending keepalive to peer {peer_id}: {e}")
            self.remove_connection(peer_id)
            return False

    def register_ip_callbacks(self, peer_id: str, peer_info):
        """
        Register IP-specific callbacks for a peer.
        This allows packets to be routed directly to the correct peer based on destination IP.
        """
        if not self.tunnel:
            logger.error("Cannot register IP callbacks - tunnel not initialized")
            return False

        # Get the peer's IP address from the peer info
        peer_ip = peer_info["ip_address"]
        logger.info(f"Using IP address {peer_ip} for peer {peer_id}")

        # First, clear any existing callback for this IP to prevent duplicates
        self.tunnel.unregister_packet_callback(peer_ip)

        # Create a callback function that will handle packets for this specific IP
        def ip_packet_handler(packet: bytes):
            try:
                # Get the connection details
                connection = self.connections.get(peer_id)
                if not connection:
                    logger.warning(
                        f"Attempted to route packet to peer {peer_id} but connection doesn't exist"
                    )
                    # TODO handle this case more gracefully, maybe try to reconnect or something
                    return

                sock = connection["socket"]
                key = connection["key"]

                # Prepend packet type (DATA = 0)
                data_packet = bytes([PACKET_TYPE_DATA]) + packet

                # Encrypt the packet
                encrypted_data = encrypt_aes_gcm(key, data_packet)

                # Send with length prefix
                packet_length = len(encrypted_data).to_bytes(4, byteorder="big")
                sock.sendall(packet_length + encrypted_data)

                # Update activity timestamps
                current_time = time.time()
                connection["last_seen"] = current_time

                logger.debug(
                    f"Routed packet of {len(packet)} bytes to peer {peer_id} for IP {peer_ip}"
                )
            except Exception as e:
                logger.error(f"Error routing packet to peer {peer_id}: {e}")
                import traceback

                logger.error(traceback.format_exc())

        # Register the callback for this specific IP
        self.tunnel.register_packet_callback(peer_ip, ip_packet_handler)
        logger.info(f"Registered IP-based routing for {peer_ip} to peer {peer_id}")

        # Log all registered callbacks for debugging
        logger.info(
            f"Current registered callbacks: {list(self.tunnel.packet_callbacks.keys())}"
        )
        return True

    def keepalive_loop(self, peer_id: str):
        """
        Dedicated thread to send periodic keepalives to a peer every 45 seconds.
        This replaces the old handle_outgoing_traffic polling approach.
        """
        try:
            while self.running and peer_id in self.connections:
                # Send the keepalive
                self.send_keepalive(peer_id)

                # Sleep for 45 seconds before sending the next one
                # Using a series of short sleeps to check if we're still running
                for _ in range(45):
                    if not self.running or peer_id not in self.connections:
                        break
                    time.sleep(1)

        except Exception as e:
            logger.error(f"Error in keepalive loop for peer {peer_id}: {e}")
            if peer_id in self.connections:
                self.remove_connection(peer_id)

    def start(self):
        """Start the VPN client"""
        self.running = True
        self.setup_virtual_interface()

        # Start listener thread
        listener_thread = threading.Thread(target=self.listen_for_connections)
        listener_thread.daemon = True
        listener_thread.start()

        # Initial discovery (with retry on failure)
        discovery_success = False
        for _ in range(3):  # Try up to 3 times
            try:
                self.discover_peers()
                if self.peers:
                    discovery_success = True
                    break
            except Exception as e:
                logger.error(f"Discovery attempt failed: {e}")
                time.sleep(2)

        if not discovery_success:
            if not self.client_cert:
                logger.error(
                    "Failed to discover peers - missing client certificate may be the cause"
                )
            else:
                logger.warning("Could not discover peers after multiple attempts")

        # Start discovery and connection
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

                    # Reconnect if needed based on last received data
                    if (
                        time.time() - conn["last_received"]
                        > self.config["keepalive_interval"] * 3
                    ):
                        logger.info(f"Connection to peer {peer_id} timed out")
                        self.remove_connection(peer_id)
                        if peer_id in self.peers:
                            self.connect_to_peer(peer_id, self.peers[peer_id])

                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            logger.info("Stopping VPN client...")
            self.stop()

    def stop(self):
        """Stop the VPN client"""
        if not self.running:
            logger.info("VPN client is already stopped.")
            return

        logger.info("Stopping VPN client...")
        self.running = False

        # Close all connections
        for peer_id in list(self.connections.keys()):
            self.remove_connection(peer_id)

        # Close discovery connection
        if self.discovery_connection:
            try:
                self.discovery_connection.close()
                logger.info("Closed discovery server connection.")
            except Exception as e:
                logger.error(f"Error closing discovery connection: {e}")

        # Close the Tunnel device
        if self.tunnel:
            try:
                self.tunnel.stop()
                self.tunnel.close()
                logger.info("Closed TUN device via Tunnel class.")
            except Exception as e:
                logger.error(f"Error closing TUN device via Tunnel class: {e}")

        logger.info("VPN client stopped")


if __name__ == "__main__":
    print_banner()
    client = MeshVPNClient(args.config)
    atexit.register(client.stop)

    # Start HTTP server if requested by args or environment variable
    if args.http_server or os.environ.get("HTTP_SERVER", "").lower() in [
        "1",
        "true",
        "yes",
    ]:
        http_port = args.http_port
        if "HTTP_PORT" in os.environ:
            try:
                http_port = int(os.environ["HTTP_PORT"])
            except ValueError:
                logger.warning(
                    f"Invalid HTTP_PORT environment variable: {os.environ['HTTP_PORT']}"
                )
        start_http_server(client, http_port)

    client.start()
