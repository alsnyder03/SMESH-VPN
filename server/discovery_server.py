import socket
import json
import threading
import logging
import time
import os
import sys
import uuid
import base64

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Add the parent directory to the path so we can import the common module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.pqxdh import PQXDHServer
from common.aesgcm import encrypt_aes_gcm
from common.certificates import CertificateAuthority

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("discovery_server")


class DiscoveryServer:
    def __init__(self, host="0.0.0.0", port=8000, ca_dir="ca"):
        self.host = host
        self.port = port
        self.peers = {}  # Dictionary to store registered peers
        self.running = False
        self.lock = threading.Lock()  # For thread-safe peer list updates
        self.node_id = str(uuid.uuid4())  # Generate a unique ID for this server

        # Initialize certificate verification
        try:
            # Note: The discovery server only needs to verify certificates, not issue them
            self.ca = CertificateAuthority(ca_dir=ca_dir, create_if_missing=False)
            logger.info(
                f"Certificate verification system initialized with {len(self.ca.list_authorized_clients())} authorized clients"
            )
        except Exception as e:
            logger.error(f"Failed to initialize Certificate verification: {e}")
            raise

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
        """Handle a client connection with secure key exchange"""
        try:
            # Receive data from client using length-prefixed format
            try:
                # First read exactly 4 bytes for the length prefix
                length_prefix = client_socket.recv(4)
                if not length_prefix or len(length_prefix) < 4:
                    logger.warning(f"No valid length prefix received from {address}")
                    client_socket.close()
                    return

                # Parse the message length
                message_length = int.from_bytes(length_prefix, byteorder="big")

                # Sanity check on message size
                if message_length <= 0 or message_length > 1048576:  # Max 1MB
                    logger.error(
                        f"Invalid message length {message_length} from {address}"
                    )
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
                            f"Connection closed before complete message received from {address}"
                        )
                        client_socket.close()
                        return
                    data += chunk
                    remaining -= len(chunk)
            except Exception as e:
                logger.error(f"Error reading client data: {e}")
                client_socket.close()
                return

            if not data:
                logger.warning(f"Empty data received from {address}")
                client_socket.close()
                return

            # Parse registration data
            try:
                registration = json.loads(data.decode("utf-8"))
                logger.info(
                    f"Registration from {address}: {{'node_id': '{registration['node_id']}', 'ip_address': {registration['ip_address']}, 'listen_port': {registration['listen_port']}, 'classical_public': '{registration['classical_public'][:8]}', 'pq_public': '{registration['pq_public'][:8]}'}}"
                )
            except json.JSONDecodeError as e:
                logger.warning(
                    f"Invalid JSON received from {address} with size {len(data)}: {e}"
                )
                if hasattr(e, "doc") and e.doc:
                    # Log a portion of the problematic data for debugging
                    error_context = e.doc[
                        max(0, e.pos - 50) : min(len(e.doc), e.pos + 50)
                    ]
                    logger.error(f"Context around error: {repr(error_context)}")
                self._send_error(client_socket, "Invalid JSON data")
                client_socket.close()
                return

            # Verify client certificate - now required for all connections
            if "certificate" not in registration:
                logger.warning(f"Missing certificate from {address}")
                self._send_error(client_socket, "Certificate is required")
                client_socket.close()
                return

            # Verify required fields
            if (
                "node_id" not in registration
                or "listen_port" not in registration
                or "classical_public" not in registration
                or "pq_public" not in registration
                or "ip_address" not in registration
            ):
                logger.warning(
                    f"Invalid registration from {address} - missing required fields"
                )
                self._send_error(client_socket, "Missing required fields")
                client_socket.close()
                return

            try:
                client_cert = base64.b64decode(registration["certificate"])
                client_id = registration["node_id"]

                if not self.ca.verify_client_certificate(client_id, client_cert):
                    logger.warning(
                        f"Invalid or unauthorized certificate from {client_id}"
                    )
                    self._send_error(
                        client_socket, "Invalid or unauthorized certificate"
                    )
                    client_socket.close()
                    return

                # Verify signature if provided (new authentication step)
                if "signature" in registration and "signed_message" in registration:
                    try:
                        # Extract the public key from the client certificate
                        cert = CertificateAuthority.load_certificate_from_pem(
                            client_cert
                        )
                        public_key = cert.public_key()

                        # Get the signature and message
                        signature = base64.b64decode(registration["signature"])
                        message = base64.b64decode(registration["signed_message"])

                        # Verify the signature
                        try:
                            public_key.verify(
                                signature,
                                message,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH,
                                ),
                                hashes.SHA256(),
                            )
                            logger.info(f"Valid signature verified for {client_id}")
                        except InvalidSignature:
                            logger.warning(f"Invalid signature from {client_id}")
                            self._send_error(client_socket, "Invalid signature")
                            client_socket.close()
                            return
                    except Exception as e:
                        logger.error(f"Error verifying signature: {e}")
                        self._send_error(client_socket, "Signature verification error")
                        client_socket.close()
                        return
                else:
                    logger.warning(
                        f"Missing signature from {client_id} - authentication is incomplete"
                    )
                    # For backward compatibility, we'll allow connections without signatures
                    # but will log a warning. In a future version, this should be required.

                logger.info(f"Valid certificate verified for {client_id}")
            except Exception as e:
                import traceback

                logger.error(f"Error verifying client certificate: {e}")
                # traceback with e
                logger.error(f"traceback: {traceback.format_exc()}")
                self._send_error(client_socket, "Certificate verification error")
                client_socket.close()
                return

                # Perform PQXDH key exchange
            server = PQXDHServer()
            server_keys = server.generate_keys()

            try:
                client_classical_public = bytes.fromhex(
                    registration["classical_public"]
                )
                client_pq_public = bytes.fromhex(registration["pq_public"])

                # Generate ciphertext for the client
                ciphertext = server.exchange(client_classical_public, client_pq_public)

                # Create response with our public key and ciphertext
                secure_response = {
                    "classical_public": server_keys["classical_public"].hex(),
                    "ciphertext": ciphertext.hex(),
                    "status": "authorized",
                }

                # Send length-prefixed JSON response
                json_response = json.dumps(secure_response).encode()
                length_prefix = len(json_response).to_bytes(4, byteorder="big")
                client_socket.sendall(length_prefix + json_response)

                # Store the shared secret for future communications with this peer
                shared_secret = server.shared_secret

                # Add logging to confirm shared secret derivation
                logger.info(f"Derived shared secret with client: {shared_secret.hex()}")

                # Encrypt and send the peer list
                peer_list = []
                with self.lock:
                    for pid, pinfo in self.peers.items():
                        peer_list.append(pinfo)

                encrypted_peer_list = encrypt_aes_gcm(
                    shared_secret, json.dumps(peer_list).encode()
                )
                # Send with length prefix
                peer_list_length = len(encrypted_peer_list).to_bytes(4, byteorder="big")
                client_socket.sendall(peer_list_length + encrypted_peer_list)
                logger.info(
                    f"Sent peer list with {len(peer_list)} peers to {registration['node_id']}"
                )
                logger.debug(f"Sending peer list: {peer_list}")

            except Exception as e:
                logger.error(f"Error in secure key exchange: {e}")
                client_socket.close()
                return

            # Store peer information
            peer_id = registration["node_id"]
            peer_info = {
                "node_id": peer_id,
                "host": address[0],
                "ip_address": registration["ip_address"],
                "listen_port": registration["listen_port"],
                "last_seen": time.time(),
            }

            with self.lock:
                self.peers[peer_id] = peer_info
                logger.info(
                    f"Registered peer {peer_id} at {address[0]}:{registration['listen_port']} with VPN IP {registration['ip_address']}"
                )
                logger.debug(f"Registering peer: {peer_info}")

        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
            import traceback

            logger.error(traceback.format_exc())
        finally:
            client_socket.close()

    def _send_error(self, client_socket, error_message):
        """Send an error response to the client"""
        error_response = {"status": "error", "error": error_message}
        try:
            json_response = json.dumps(error_response).encode()
            length_prefix = len(json_response).to_bytes(4, byteorder="big")
            client_socket.sendall(length_prefix + json_response)
        except Exception as e:
            logger.error(f"Error sending error response: {e}")

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
    ca_dir = os.environ.get("CA_DIR", "ca")

    server = DiscoveryServer(host, port, ca_dir)

    # List authorized clients if requested
    if "--list-clients" in sys.argv:
        clients = server.ca.list_authorized_clients()
        print(f"Authorized clients ({len(clients)}):")
        for client_id, info in clients.items():
            print(
                f"- {info['common_name']} (ID: {client_id}, Expires: {info['expires_at']})"
            )
        sys.exit(0)

    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        server.stop()
