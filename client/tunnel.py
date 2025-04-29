import os
import sys
import logging
import platform
import subprocess
import threading
import time
import socket
import struct
from typing import Optional, Callable, Dict
from ipaddress import ip_address, IPv4Network, IPv4Address
import select  # Added for non-blocking read

logger = logging.getLogger(__name__)


class Tunnel:
    """
    A Linux TUN device abstraction.
    This class provides an interface for creating and managing tunnels.
    """

    def __init__(
        self,
        interface_name: str,
        local_ip: str,
        prefix_len: int = 24,
        packet_handler: Callable[[bytes, str], None] = None,
    ):
        """
        Initialize the tunnel device.

        Args:
            interface_name: Name of the virtual interface (e.g., "tun0")
            local_ip: IP address for the tunnel interface
            prefix_len: Network prefix length (default: 24)
            packet_handler: Callback function that receives packet data and destination IP
                           Function signature: callback(packet_data: bytes, destination_ip: str) -> None
        """
        self.interface_name = interface_name
        self.local_ip = local_ip
        self.prefix_len = prefix_len
        self.tun_fd = None  # File descriptor
        self.running = False
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.packet_handler = packet_handler
        self.reader_thread = None
        self.packet_callbacks: Dict[str, Callable[[bytes], None]] = {}
        self.subnet = IPv4Network(f"{local_ip}/{prefix_len}", strict=False)

    def __enter__(self):
        """Support context manager interface"""
        if not self.setup():
            raise RuntimeError("Failed to set up tunnel interface")
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up when used as context manager"""
        self.cleanup()

    def setup(self) -> bool:
        """Set up the tunnel interface for Linux"""
        logger.info("Setting up tunnel interface")
        try:
            return self._setup_linux()
        except Exception as e:
            logger.error(f"Error setting up tunnel: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return False

    def _setup_linux(self) -> bool:
        """Set up TUN device on Linux"""
        try:
            import fcntl  # Linux/Unix specific
            import time  # Import time for delays

            # Constants from Linux headers
            TUNSETIFF = 0x400454CA
            IFF_TUN = 0x0001
            IFF_NO_PI = 0x1000  # Don't provide packet information

            # Check if interface already exists
            try:
                # Use ip link show to check if interface exists
                result = subprocess.run(
                    ["ip", "link", "show", "dev", self.interface_name],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )

                if result.returncode == 0:
                    logger.info(
                        f"Interface {self.interface_name} already exists, cleaning up..."
                    )
                    # Interface exists, bring it down first
                    subprocess.run(
                        ["ip", "link", "set", "dev", self.interface_name, "down"],
                        check=False,
                        stderr=subprocess.DEVNULL,
                    )
                    # Delete the existing interface
                    subprocess.run(
                        [
                            "ip",
                            "tuntap",
                            "del",
                            "dev",
                            self.interface_name,
                            "mode",
                            "tun",
                        ],
                        check=False,
                        stderr=subprocess.DEVNULL,
                    )
                    # Wait a short time for kernel to clean up resources
                    logger.info("Waiting for interface cleanup...")
                    time.sleep(2)
            except Exception as e:
                logger.warning(f"Error checking for existing interface: {e}")

            # Open the TUN device file
            tun_fd = os.open("/dev/net/tun", os.O_RDWR)

            # Prepare interface request structure
            ifr = struct.pack(
                "16sH", self.interface_name.encode("ascii"), IFF_TUN | IFF_NO_PI
            )

            # Register the interface
            fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

            # Store file descriptor
            self.tun_fd = tun_fd

            # Configure IP address and bring interface up
            subprocess.run(
                [
                    "ip",
                    "addr",
                    "add",
                    f"{self.local_ip}/{self.prefix_len}",
                    "dev",
                    self.interface_name,
                ],
                check=True,
            )
            subprocess.run(
                ["ip", "link", "set", "dev", self.interface_name, "up"], check=True
            )

            # Add explicit route for the subnet through the tunnel interface
            try:
                # Extract subnet from the local IP and prefix length
                ip_obj = ip_address(self.local_ip)
                # Use IPv4Network to get the proper subnet, using strict=False to allow host bits
                subnet = str(IPv4Network(f"{ip_obj}/{self.prefix_len}", strict=False))

                # Delete any existing route first to avoid "file exists" errors
                subprocess.run(
                    ["ip", "route", "del", subnet],
                    check=False,  # Don't fail if route doesn't exist
                    stderr=subprocess.DEVNULL,
                )

                # Add the new route
                subprocess.run(
                    ["ip", "route", "add", subnet, "dev", self.interface_name],
                    check=False,  # Don't fail if route already exists
                )
                logger.info(f"Added route for {subnet} through {self.interface_name}")
            except Exception as e:
                logger.warning(f"Failed to add explicit route, but continuing: {e}")

            # Disable IPv6 autoconfiguration to prevent Router Solicitations
            try:
                subprocess.run(
                    ["sysctl", f"net.ipv6.conf.{self.interface_name}.autoconf=0"],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["sysctl", f"net.ipv6.conf.{self.interface_name}.accept_ra=0"],
                    check=True,
                    capture_output=True,
                )
            except Exception:
                pass  # Ignore IPv6 configuration errors

            # Set to non-blocking mode
            flags = fcntl.fcntl(self.tun_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            logger.info(
                f"Linux TUN device '{self.interface_name}' set up with IP {self.local_ip}/{self.prefix_len}"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to set up Linux TUN device: {e}")
            if self.tun_fd is not None:
                os.close(self.tun_fd)
                self.tun_fd = None
            return False

    def start(self):
        """Start processing packets from the tunnel."""
        if self.running:
            logger.warning("Tunnel handler already running.")
            return

        self.running = True

        # Start the packet reader thread
        self.reader_thread = threading.Thread(
            target=self._packet_reader_loop, daemon=True, name="TunnelPacketReader"
        )
        self.reader_thread.start()

        logger.info(f"Tunnel {self.interface_name} started with packet reader thread")

    def stop(self):
        """Stop the tunnel processing thread."""
        if not self.running:
            return

        logger.info("Stopping tunnel...")
        self.running = False

        if self.reader_thread and self.reader_thread.is_alive():
            logger.info("Stopping packet reader thread...")
            self.reader_thread.join(timeout=1)
            if self.reader_thread.is_alive():
                logger.warning("Tunnel packet reader thread did not stop gracefully.")
            self.reader_thread = None

        logger.info("Tunnel stopped")

    def cleanup(self):
        """Clean up resources (close file descriptor, remove interface)."""
        logger.info(f"Cleaning up tunnel interface '{self.interface_name}'...")
        self.stop()

        # Close the file descriptor
        if self.tun_fd is not None:
            try:
                os.close(self.tun_fd)
                self.tun_fd = None
                logger.info("Tunnel descriptor closed.")
            except Exception as e:
                logger.error(f"Error closing tunnel descriptor: {e}")

        # Clean up the interface configuration
        try:
            subprocess.run(
                ["ip", "link", "set", "dev", self.interface_name, "down"],
                check=False,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                ["ip", "tuntap", "del", "dev", self.interface_name, "mode", "tun"],
                check=False,
                stderr=subprocess.DEVNULL,
            )
            logger.info(f"Linux interface '{self.interface_name}' removed.")
        except Exception as e:
            logger.error(f"Error during interface cleanup commands: {e}")

        logger.info(f"Tunnel interface '{self.interface_name}' cleanup complete.")

    def register_packet_callback(
        self, destination_ip: str, callback: Callable[[bytes], None]
    ) -> None:
        """
        Register a callback function for a specific destination IP.
        The callback will be called when a packet destined for this IP is received.

        Args:
            destination_ip: The destination IP to match packets against
            callback: Function that receives packet data (bytes)
        """
        logger.info(f"Registering callback for destination IP: {destination_ip}")
        self.packet_callbacks[destination_ip] = callback

    def unregister_packet_callback(self, destination_ip: str) -> None:
        """
        Unregister a callback function for a specific destination IP.

        Args:
            destination_ip: The destination IP whose callback should be removed
        """
        if destination_ip in self.packet_callbacks:
            logger.info(f"Unregistering callback for destination IP: {destination_ip}")
            del self.packet_callbacks[destination_ip]

    def _packet_reader_loop(self):
        """
        Main packet reading loop that reads packets from the tunnel interface
        and calls appropriate callbacks based on the destination IP.
        """
        logger.info("Starting packet reader loop")
        logger.info(f"Registered callbacks: {list(self.packet_callbacks.keys())}")

        while self.running and self.tun_fd is not None:
            try:
                # Read a packet from the tunnel interface
                packet = self.read(max_size=4096)

                if not packet or len(packet) < 20:  # Minimum IPv4 header size
                    time.sleep(0.01)  # Avoid busy wait
                    continue

                # Extract destination IP from IPv4 packet header
                # IPv4 version (first 4 bits should be 4)
                version = packet[0] >> 4
                if version != 4:
                    # Not an IPv4 packet, skip
                    continue

                # Destination IP is at bytes 16-19
                dst_ip = socket.inet_ntoa(packet[16:20])
                src_ip = socket.inet_ntoa(packet[12:16])
                logger.info(f"Received packet from {src_ip} to {dst_ip}")

                # Check if this is a packet for our subnet
                if IPv4Address(dst_ip) in self.subnet:
                    # Call the general packet handler if registered
                    if self.packet_handler:
                        logger.debug(
                            f"Calling general packet handler for packet to {dst_ip}"
                        )
                        self.packet_handler(packet, dst_ip)

                    # Call the specific callback for this destination IP if registered
                    if dst_ip in self.packet_callbacks:
                        try:
                            logger.debug(f"Calling specific callback for {dst_ip}")
                            self.packet_callbacks[dst_ip](packet)
                        except Exception as e:
                            logger.error(f"Error in packet callback for {dst_ip}: {e}")
                            import traceback

                            logger.error(traceback.format_exc())
                    else:
                        logger.info(
                            f"No callback registered for destination IP: {dst_ip}, available callbacks: {list(self.packet_callbacks.keys())}"
                        )

            except Exception as e:
                logger.error(f"Error in packet reader loop: {e}")
                import traceback

                logger.error(traceback.format_exc())
                time.sleep(0.1)  # Add delay to avoid tight loop on continuous errors

        logger.info("Packet reader loop stopped")

    def read(self, max_size=4096) -> Optional[bytes]:
        """
        Read a packet from the tunnel (non-blocking).

        Args:
            max_size: Maximum packet size to read.

        Returns:
            bytes or None: Packet data if available, None otherwise.
        """
        if not self.tun_fd or not self.running:
            return None

        with self.read_lock:
            try:
                return os.read(self.tun_fd, max_size)
            except BlockingIOError:
                # This is expected when no data is available on non-blocking fd
                return None
            except OSError as e:
                # Check for Bad File Descriptor (errno 9)
                if e.errno == 9:
                    logger.error(
                        "Bad file descriptor during read. Tunnel may be closed."
                    )
                    self.tun_fd = None  # Mark as closed
                    self.stop()
                else:
                    # Log other OS errors
                    logger.error(f"OSError reading from tunnel: {e}")
                return None
            except Exception as e:
                # Catch any other unexpected errors during read
                logger.error(f"Unexpected error reading from tunnel: {e}")
                self.stop()
                return None

    def write(self, packet: bytes) -> bool:
        """
        Write a packet to the tunnel.

        Args:
            packet: Packet data to write.

        Returns:
            bool: True if write was successful, False otherwise.
        """
        if not self.tun_fd or not self.running:
            logger.warning("Tunnel not ready or not running for writing.")
            return False

        with self.write_lock:
            try:
                bytes_sent = os.write(self.tun_fd, packet)
                return bytes_sent == len(packet)
            except OSError as e:
                # Check for Bad File Descriptor (errno 9)
                if e.errno == 9:
                    logger.error(
                        "Bad file descriptor during write. Tunnel may be closed."
                    )
                    self.tun_fd = None  # Mark as closed
                    self.stop()
                else:
                    # Log other OS errors
                    logger.error(f"OSError writing to tunnel: {e}")
                return False
            except Exception as e:
                # Catch any other unexpected errors during write
                logger.error(f"Unexpected error writing to tunnel: {e}")
                self.stop()
                return False

    def close(self):
        """Clean up the TUN device."""
        if self.tun_fd is not None:
            try:
                os.close(self.tun_fd)
                self.tun_fd = None
                logger.info(f"Closed TUN device for {self.interface_name}")
            except OSError as e:
                logger.error(f"Error closing TUN device {self.interface_name}: {e}")

        # Teardown commands
        try:
            # Bring the interface down
            subprocess.run(
                ["ip", "link", "set", "dev", self.interface_name, "down"],
                check=False,
            )
            logger.info(f"Brought down interface {self.interface_name}")
        except Exception as e:
            logger.error(f"Unexpected error during interface teardown: {e}")

        self.tun_fd = None  # Ensure fd is marked as None even if close failed


# Example Usage (can be placed in if __name__ == "__main__")
def handle_packet_from_tunnel(packet: bytes):
    print(f"Received packet from tunnel: {len(packet)} bytes")
    print(packet.hex())  # Print packet in hex format for debugging
    # Process the packet (e.g., encrypt and send to peer)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )
    logger.info("Starting Tunnel example...")

    # Choose interface name and IP based on platform needs
    if_name = "tun_smesh0"
    ip_addr = "10.10.0.10"

    try:
        # Use context manager for automatic setup and cleanup
        with Tunnel(interface_name=if_name, local_ip=ip_addr) as tunnel:
            logger.info(f"Tunnel interface '{tunnel.interface_name}' is up.")

            # Register a callback
            tunnel.register_packet_callback("10.10.0.2", handle_packet_from_tunnel)

            logger.info("Tunnel running. Press Ctrl+C to stop.")

            # Simple example loop
            while tunnel.running:
                packet = tunnel.read()
                if packet:
                    handle_packet_from_tunnel(packet)
                else:
                    time.sleep(0.01)  # Prevent busy-waiting

    except KeyboardInterrupt:
        logger.info("Ctrl+C received, shutting down.")
    except RuntimeError as e:
        logger.error(f"Failed to initialize tunnel: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        import traceback

        logger.error(traceback.format_exc())

    logger.info("Tunnel example finished.")
