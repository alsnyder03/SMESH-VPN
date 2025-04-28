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


# Add the parent directory to the path so we can import the common module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.pqxdh import PQXDHServer, PQXDHClient
from tunnel import Tunnel  # Import the Tunnel class

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ipaddress import ip_address, IPv4Network

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

    def load_config(self, config_path):
        default_config = {
            "listen_port": 9000,
            "discovery_servers": ["127.0.0.1:8000"],
            "interface": "smesh_tun0",
            "subnet": IPv4Network("10.10.0.0/24"),
            "local_ip": ip_address("10.10.0.1"),
            "keepalive_interval": 15,
        }

        # Override with command line arguments
        if args.ip:
            print(f"IP address from command line: {args.ip}")
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
            ip = ip_address(os.environ["IP_ADDRESS"])
            if ip in default_config["subnet"]:
                default_config["local_ip"] = ip
                logger.info(f"Using IP from environment: {default_config['local_ip']}")
        if "INTERFACE_NAME" in os.environ:
            default_config["interface"] = os.environ["INTERFACE_NAME"]
            logger.info(
                f"Using interface name from environment: {default_config['interface']}"
            )

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
            "last_sent": current_time,  # Track when we last sent data
            "last_received": current_time,  # Track when we last received data
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

    def handle_outgoing_traffic(self, peer_id: str):
        """Handle traffic going out to the peer using the Tunnel."""
        connection = self.connections.get(peer_id)
        if not connection:
            return

        sock = connection["socket"]
        key = connection["key"]

        if not self.tunnel:
            logger.error("Tunnel not initialized for outgoing traffic.")
            return

        def encrypt_packet(packet):
            iv = os.urandom(16)  # Generate a fresh IV for each packet
            encryptor = Cipher(
                algorithms.AES(key), modes.GCM(iv), backend=default_backend()
            ).encryptor()
            ciphertext = encryptor.update(packet) + encryptor.finalize()
            return iv + encryptor.tag + ciphertext  # Prepend IV and tag

        try:
            while self.running and peer_id in self.connections:
                try:
                    # Use the tunnel's read() method directly - it already handles non-blocking I/O
                    packet = self.tunnel.read(
                        4096
                    )  # Using default MTU if not specified

                    if not packet:
                        # No data available, sleep briefly to prevent CPU hogging
                        time.sleep(0.01)
                        # Check connection status
                        if peer_id not in self.connections:
                            break
                        continue

                    # Check connection status before encrypting/sending
                    if peer_id not in self.connections:
                        break

                    logger.debug(f"Read {len(packet)} bytes from tunnel for {peer_id}")

                    # Encrypt and send the packet
                    encrypted_data = encrypt_packet(packet)
                    packet_length = len(encrypted_data).to_bytes(4, byteorder="big")

                    # Check connection status one last time before sending
                    if peer_id not in self.connections:
                        break

                    sock.sendall(packet_length + encrypted_data)
                    # Update activity timestamps - specifically tracking when WE sent data
                    current_time = time.time()
                    connection["last_sent"] = (
                        current_time  # Explicitly track when we sent data
                    )
                    connection["last_seen"] = current_time

                    logger.debug(f"Read {len(packet)} bytes from tunnel for {peer_id}")

                except OSError as e:
                    # Check connection status before logging/removing
                    if peer_id in self.connections:
                        if e.errno == 9:  # Bad file descriptor
                            logger.warning(
                                f"Tunnel or socket for peer {peer_id} closed unexpectedly (errno 9) in outgoing handler. Connection likely removed."
                            )
                        elif (
                            e.errno == 10038
                        ):  # An operation was attempted on something that is not a socket (Windows)
                            logger.warning(
                                f"Socket for peer {peer_id} closed unexpectedly (errno 10038) in outgoing handler. Connection likely removed."
                            )
                        elif (
                            e.errno == 10053
                        ):  # An established connection was aborted by the software in your host machine (Windows)
                            logger.warning(
                                f"Connection aborted for peer {peer_id} (errno 10053) in outgoing handler."
                            )
                        elif e.errno == 10054:  # Connection reset by peer (Windows)
                            logger.warning(
                                f"Connection reset by peer {peer_id} (errno 10054) in outgoing handler."
                            )
                        else:
                            logger.error(f"Tunnel I/O error for peer {peer_id}: {e}")
                        self.remove_connection(peer_id)  # Attempt removal
                    break  # Exit loop on error
                except Exception as e:
                    # Check connection status before logging/removing
                    if peer_id in self.connections:
                        logger.error(f"Error sending data to peer {peer_id}: {e}")
                        import traceback

                        logger.error(traceback.format_exc())
                        self.remove_connection(peer_id)
                    break  # Exit loop on error
        except Exception as e:
            # Catch potential errors if connection is removed mid-operation
            if peer_id in self.connections:
                logger.error(
                    f"Unhandled error in outgoing traffic handler for {peer_id}: {e}"
                )
                import traceback

                logger.error(traceback.format_exc())
                self.remove_connection(peer_id)
            # else: Connection already removed, suppress error

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

        def decrypt_packet(encrypted_data):
            if len(encrypted_data) < 32:  # 16 bytes IV + 16 bytes tag
                raise ValueError("Encrypted data too short to contain IV and tag")
            iv = encrypted_data[:16]
            tag = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            decryptor = Cipher(
                algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
            ).decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

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

                    # Process complete packets from the buffer
                    while True:
                        if expected_length is None:
                            if len(buffer) >= 4:
                                expected_length = int.from_bytes(
                                    buffer[:4], byteorder="big"
                                )
                                buffer = buffer[4:]
                            else:
                                break  # Need more data for length

                        if len(buffer) >= expected_length:
                            encrypted_packet = buffer[:expected_length]
                            buffer = buffer[expected_length:]
                            expected_length = None

                            # Check connection status before decrypting/writing
                            if peer_id not in self.connections:
                                break

                            try:
                                packet = decrypt_packet(encrypted_packet)

                                # Check for keepalive packet (first byte is packet type)
                                if (
                                    len(packet) > 0
                                    and packet[0] == PACKET_TYPE_KEEPALIVE
                                ):
                                    logger.info(
                                        f"Received keepalive packet from peer {peer_id}"
                                    )
                                    continue  # Skip further processing for keepalives

                                logger.debug(
                                    f"Decrypted {len(packet)} bytes from peer {peer_id}"
                                )
                                self.tunnel.write(packet)
                            except ValueError as e:
                                logger.error(
                                    f"Decryption error for peer {peer_id}: {e}"
                                )
                                # Continue processing other packets
                            except OSError as e:
                                if peer_id in self.connections:
                                    if (
                                        e.errno == 9
                                    ):  # Bad file descriptor (tunnel closed?)
                                        logger.warning(
                                            f"Tunnel write error (errno 9) for peer {peer_id}."
                                        )
                                    else:
                                        logger.error(
                                            f"Tunnel write error for peer {peer_id}: {e}"
                                        )
                                    self.remove_connection(peer_id)
                                break
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
                except OSError as e:
                    if peer_id in self.connections:
                        if e.errno == 9:  # Bad file descriptor
                            logger.warning(
                                f"Socket for peer {peer_id} closed unexpectedly (errno 9)."
                            )
                        elif e.errno == 10038:  # Not a socket (Windows)
                            logger.warning(
                                f"Socket for peer {peer_id} closed unexpectedly (errno 10038)."
                            )
                        elif e.errno == 10053:  # Connection aborted (Windows)
                            logger.warning(
                                f"Connection aborted for peer {peer_id} (errno 10053)."
                            )
                        elif e.errno == 10054:  # Connection reset by peer (Windows)
                            logger.warning(
                                f"Connection reset by peer {peer_id} (errno 10054)."
                            )
                        else:
                            logger.error(
                                f"Error receiving data from peer {peer_id}: {e}"
                            )
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

            # Encrypt the keepalive packet
            iv = os.urandom(16)  # Generate a fresh IV
            encryptor = Cipher(
                algorithms.AES(key), modes.GCM(iv), backend=default_backend()
            ).encryptor()
            ciphertext = encryptor.update(keepalive_packet) + encryptor.finalize()
            encrypted_data = iv + encryptor.tag + ciphertext  # Prepend IV and tag

            # Send the packet with its length prefix
            packet_length = len(encrypted_data).to_bytes(4, byteorder="big")
            sock.sendall(packet_length + encrypted_data)

            # Update timestamps when sending keepalive
            current_time = time.time()
            connection["last_sent"] = (
                current_time  # Explicitly track when we sent keepalive
            )
            connection["last_seen"] = current_time

            logger.info(f"Sent keepalive packet to peer {peer_id}")
            return True
        except Exception as e:
            logger.error(f"Error sending keepalive to peer {peer_id}: {e}")
            self.remove_connection(peer_id)
            return False

    def check_and_send_keepalives(self):
        """Check all connections and send keepalives if needed"""
        current_time = time.time()

        # Only check every few seconds to avoid excessive processing
        if current_time - self.last_keepalive_check < 5:
            return

        self.last_keepalive_check = current_time

        for peer_id in list(self.connections.keys()):
            try:
                connection = self.connections.get(peer_id)
                if not connection:
                    continue

                # Send keepalive if no outgoing data sent for half the keepalive interval
                # regardless of whether we've received data
                if (
                    current_time - connection.get("last_sent", 0)
                    > self.config["keepalive_interval"] / 2
                ):
                    self.send_keepalive(peer_id)
            except Exception as e:
                logger.error(f"Error in keepalive check for peer {peer_id}: {e}")
                # Don't remove connection here, let the normal error handling handle it

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

                    # Reconnect if needed - use last_sent_or_received instead of last_seen
                    if (
                        time.time() - conn["last_received"]
                        > self.config["keepalive_interval"] * 3
                    ):
                        logger.info(f"Connection to peer {peer_id} timed out")
                        self.remove_connection(peer_id)
                        if peer_id in self.peers:
                            self.connect_to_peer(peer_id, self.peers[peer_id])

                # Check and send keepalives
                self.check_and_send_keepalives()

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
                self.tunnel.close()
                logger.info("Closed TUN device via Tunnel class.")
            except Exception as e:
                logger.error(f"Error closing TUN device via Tunnel class: {e}")

        logger.info("VPN client stopped")


if __name__ == "__main__":
    print_banner()
    client = MeshVPNClient(args.config)
    atexit.register(client.stop)
    client.start()
