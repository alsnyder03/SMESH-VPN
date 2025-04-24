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

# import fcntl

# Add the parent directory to the path so we can import the common module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.pqxdh import PQXDHServer, PQXDHClient

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ipaddress import ip_address, IPv4Network

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
parser.add_argument(
    "--interface",
    type=str,
    default="tun0",
    help="Name of TUN interface to create (default: tun0)",
)
parser.add_argument(
    "--instance",
    type=int,
    default=1,
    help="Instance number (1 or 2) - sets sensible defaults",
)
parser.add_argument(
    "-d", "--discovery", type=str, help="Discovery server address (format: host:port)"
)
args = parser.parse_args()

if args.instance == 2:
    args.port = 9020
    args.ip = "10.10.0.20"
    args.interface = "tun1"
elif args.instance == 1:
    args.port = 9010
    args.ip = "10.10.0.10"
    args.interface = "tun0"


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
        self.tun_fd = None  # Initialize tun device file descriptor

    def load_config(self, config_path):
        default_config = {
            "listen_port": 9000,
            "discovery_servers": ["127.0.0.1:8000"],
            "interface": "tun0",
            "subnet": IPv4Network("10.10.0.0/24"),
            "local_ip": ip_address("10.10.0.1"),
            "keepalive_interval": 15,
        }

        # Override with environment variables if available
        if "DISCOVERY_SERVER" in os.environ:
            default_config["discovery_servers"] = [os.environ["DISCOVERY_SERVER"]]
            logger.info(
                f"Using discovery server from environment: {default_config['discovery_servers']}"
            )

        # Override with command line arguments
        if args.ip:
            ip = ip_address(args.ip)
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

        # Load from config file (lowest priority)
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
        try:
            if sys.platform.startswith("linux"):
                # Create TUN device using proper system calls instead of os.system
                TUNSETIFF = 0x400454CA  # from <linux/if_tun.h>
                IFF_TUN = 0x0001
                IFF_NO_PI = 0x1000

                # Open the TUN device file
                tun_fd = os.open("/dev/net/tun", os.O_RDWR)

                # Set up TUN interface with ioctl
                ifr = struct.pack(
                    "16sH", self.config["interface"].encode(), IFF_TUN | IFF_NO_PI
                )
                try:
                    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
                    self.tun_fd = tun_fd  # Store the file descriptor

                    # Configure IP address using os.system (could be improved with pyroute2)
                    os.system(
                        f"ip addr add {self.config['subnet']} dev {self.config['interface']}"
                    )
                    os.system(f"ip link set dev {self.config['interface']} up")
                    logger.info(f"Virtual interface {self.config['interface']} set up")
                except Exception as e:
                    os.close(tun_fd)
                    raise e
            else:
                logger.warning(
                    f"Virtual interface setup not implemented for platform {sys.platform}"
                )
        except Exception as e:
            logger.error(f"Failed to set up virtual interface: {e}")
            if hasattr(e, "errno") and e.errno == 1:  # Operation not permitted
                logger.error("Permission denied. Try running with sudo or use setcap.")

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
        connection = self.connections[peer_id]
        if not connection:
            logger.error(f"No connection found for peer {peer_id}")
            return

        if not self.tun_fd:
            logger.error("TUN device not initialized")
            return

        # Generate a random IV for each packet
        def encrypt_packet(data):
            iv = os.urandom(16)  # 16 bytes IV for AES
            encryptor = Cipher(
                algorithms.AES(connection["key"]),
                modes.GCM(iv),
                backend=default_backend(),
            ).encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return iv + encryptor.tag + ciphertext

        try:
            # Use the shared TUN file descriptor instead of creating a new one
            while self.running and peer_id in self.connections:
                try:
                    # Read a packet from TUN device (MTU sized)
                    packet = os.read(self.tun_fd, 4096)
                    if packet:
                        # Encrypt the packet
                        encrypted_packet = encrypt_packet(packet)

                        # Send to peer with length prefix
                        packet_length = len(encrypted_packet).to_bytes(
                            4, byteorder="big"
                        )
                        connection["socket"].sendall(packet_length + encrypted_packet)
                except BlockingIOError:
                    # No data available, sleep briefly
                    time.sleep(0.01)
                    continue
                except TimeoutError:
                    # send keepalive packets
                    keepalive_packet = b"KEEPALIVE"
                    encrypted_packet = encrypt_packet(keepalive_packet)
                    packet_length = len(encrypted_packet).to_bytes(4, byteorder="big")
                    connection["socket"].sendall(packet_length + encrypted_packet)
                    continue
                except Exception as e:
                    logger.error(f"Error sending packet to peer {peer_id}: {e}")
                    self.remove_connection(peer_id)
                    break
        except Exception as e:
            logger.error(f"Error in outgoing traffic handler: {e}")
            import traceback

            logger.error(traceback.format_exc())

    def handle_incoming_traffic(self, peer_id: str):
        """Handle traffic coming from the peer"""
        connection = self.connections[peer_id]
        if not connection:
            logger.error(f"No connection found for peer {peer_id}")
            return

        socket = connection["socket"]
        socket.settimeout(1)  # Set timeout to avoid blocking forever

        if not self.tun_fd:
            logger.error("TUN device not initialized")
            return

        def decrypt_packet(encrypted_data):
            iv = encrypted_data[:16]  # First 16 bytes are the IV
            tag = encrypted_data[16:32]  # Next 16 bytes are GCM tag
            ciphertext = encrypted_data[32:]  # Rest is ciphertext

            decryptor = Cipher(
                algorithms.AES(connection["key"]),
                modes.GCM(iv, tag),
                backend=default_backend(),
            ).decryptor()

            return decryptor.update(ciphertext) + decryptor.finalize()

        try:
            while self.running and peer_id in self.connections:
                try:
                    # First read the packet length (4 bytes)
                    length_bytes = socket.recv(4)
                    if not length_bytes:
                        self.remove_connection(peer_id)
                        break

                    packet_length = int.from_bytes(length_bytes, byteorder="big")
                    encrypted_data = socket.recv(packet_length)

                    # Decrypt the packet
                    packet = decrypt_packet(encrypted_data)
                    connection["last_seen"] = time.time()

                    # Write to TUN device if not keepalive
                    if packet != b"KEEPALIVE":
                        os.write(self.tun_fd, packet)
                    else:
                        logger.debug(f"Received keepalive from {peer_id}")

                except TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error receiving data from peer {peer_id}: {e}")
                    self.remove_connection(peer_id)
                    break
        except Exception as e:
            logger.error(f"Error in incoming traffic handler: {e}")
            import traceback

            logger.error(traceback.format_exc())

    def remove_connection(self, peer_id):
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

                    # Reconnect if needed
                    if (
                        time.time() - conn["last_seen"]
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
        self.running = False

        # Close all connections
        for peer_id in list(self.connections.keys()):
            self.remove_connection(peer_id)

        # Close TUN device if open
        if self.tun_fd is not None:
            try:
                os.close(self.tun_fd)
                logger.info("Closed TUN device")
            except Exception as e:
                logger.error(f"Error closing TUN device: {e}")

        # Clean up virtual interface
        if sys.platform.startswith("linux"):
            os.system(f"ip link set dev {self.config['interface']} down")
            os.system(f"ip tuntap del dev {self.config['interface']} mode tun")

        logger.info("VPN client stopped")


if __name__ == "__main__":
    print_banner()
    client = MeshVPNClient(args.config)
    client.start()
