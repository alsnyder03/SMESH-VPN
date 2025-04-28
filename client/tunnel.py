import os
import sys
import logging
import platform
import subprocess
import threading
import time
import socket
import struct
from typing import Optional, Callable, Dict, Any
from ipaddress import ip_address, IPv4Network, IPv4Address
import select  # Added for non-blocking read

logger = logging.getLogger(__name__)


class Tunnel:
    """
    A cross-platform abstraction for TUN/TAP devices.
    This class provides a unified interface for creating and managing tunnels
    across different operating systems.
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
        self.tun_fd = None  # File descriptor or socket
        self.running = False
        self.os_name = platform.system().lower()
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.packet_handler = packet_handler
        self.tunnel_port = 0  # Used for Windows socket proxy
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
        """
        Set up the tunnel interface based on the current platform.

        Returns:
            bool: True if setup was successful, False otherwise
        """
        logger.info(f"Setting up tunnel for platform: {self.os_name}")
        try:
            if self.os_name == "linux":
                return self._setup_linux()
            elif self.os_name == "windows":
                return self._setup_windows()
            elif self.os_name == "darwin":  # macOS
                return self._setup_macos()
            else:
                logger.error(f"Unsupported platform: {self.os_name}")
                return False
        except Exception as e:
            logger.error(f"Error setting up tunnel: {e}")
            import traceback

            logger.error(traceback.format_exc())
            return False

    def _setup_linux(self) -> bool:
        """Set up TUN device on Linux"""
        try:
            import fcntl  # Linux/Unix specific
            import time   # Import time for delays

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
                    stderr=subprocess.PIPE
                )
                
                if result.returncode == 0:
                    logger.info(f"Interface {self.interface_name} already exists, cleaning up...")
                    # Interface exists, bring it down first
                    subprocess.run(
                        ["ip", "link", "set", "dev", self.interface_name, "down"],
                        check=False,
                        stderr=subprocess.DEVNULL,
                    )
                    # Delete the existing interface
                    subprocess.run(
                        ["ip", "tuntap", "del", "dev", self.interface_name, "mode", "tun"],
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
            # This ensures proper routing between VPN clients
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
                logger.info(
                    f"Disabled IPv6 autoconfiguration for {self.interface_name}"
                )
            except FileNotFoundError:
                logger.warning(
                    "'sysctl' command not found. Cannot disable IPv6 autoconf automatically."
                )
            except subprocess.CalledProcessError as e:
                # This might fail if IPv6 is disabled globally or the module isn't loaded
                logger.warning(
                    f"Could not disable IPv6 autoconf for {self.interface_name} (might be normal): {e.stderr.decode().strip()}"
                )
            except Exception as e_sysctl:
                logger.warning(
                    f"An unexpected error occurred disabling IPv6 autoconf: {e_sysctl}"
                )

            # Set to non-blocking mode
            flags = fcntl.fcntl(self.tun_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            logger.info(
                f"Linux TUN device '{self.interface_name}' set up with IP {self.local_ip}/{self.prefix_len}"
            )
            return True
        except ImportError:
            logger.error("'fcntl' module not found. Cannot set up TUN on this system.")
            return False
        except FileNotFoundError:
            logger.error(
                "'ip' command not found or /dev/net/tun does not exist. Is the 'tuntap' module loaded?"
            )
            return False
        except PermissionError:
            logger.error(
                "Permission denied. Run as root or with CAP_NET_ADMIN capability."
            )
            return False
        except Exception as e:
            logger.error(f"Failed to set up Linux TUN device: {e}")
            if self.tun_fd is not None:
                os.close(self.tun_fd)
                self.tun_fd = None
            return False

    def _setup_windows(self) -> bool:
        """Set up a socket-based proxy tunnel on Windows."""
        logger.info("Windows detected. Creating a socket-based proxy tunnel.")
        # Note: This doesn't create a real network interface visible to the OS.
        # It relies on the application routing packets correctly.
        # For a real interface, OpenVPN TAP or WinTUN drivers are needed.
        try:
            # Create a UDP socket to act as the tunnel endpoint
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.bind(("127.0.0.1", 0))  # Bind to localhost on an available port
            self.tunnel_port = server.getsockname()[1]
            server.setblocking(False)  # Set to non-blocking

            # Store the socket as our "file descriptor"
            self.tun_fd = server

            logger.info(
                f"Created proxy tunnel on Windows using UDP socket 127.0.0.1:{self.tunnel_port}"
            )
            logger.info(
                f"Application treats this as interface '{self.interface_name}' with IP {self.local_ip}/{self.prefix_len}"
            )
            logger.warning(
                "Windows proxy tunnel does not create a system-wide interface."
            )
            logger.warning(
                "Routing must be handled within the application or manually."
            )

            # Attempt to add a route (requires admin privileges)
            self._setup_windows_routing()

            return True
        except Exception as e:
            logger.error(f"Failed to set up Windows TUN proxy: {e}")
            if self.tun_fd is not None:
                self.tun_fd.close()
                self.tun_fd = None
            return False

    def _setup_windows_routing(self):
        """Attempt to set up routing on Windows (requires admin)."""
        # This is a best-effort attempt and might fail if not run as admin.
        # The subnet 10.10.0.0/24 is hardcoded here, should ideally be configurable.
        subnet_addr = "10.10.0.0"
        subnet_mask = "255.255.255.0"
        logger.info(
            f"Attempting to add route for {subnet_addr}/{subnet_mask} via {self.local_ip}"
        )
        try:
            # Delete existing route first, ignore errors
            subprocess.run(
                ["route", "delete", subnet_addr], check=False, capture_output=True
            )
            # Add the new route
            result = subprocess.run(
                ["route", "add", subnet_addr, "MASK", subnet_mask, self.local_ip],
                check=True,
                capture_output=True,
                text=True,
            )
            logger.info("Route added successfully (requires admin privileges).")
            logger.debug(f"Route command output: {result.stdout}")
        except FileNotFoundError:
            logger.warning(
                "'route' command not found. Cannot set up routing automatically."
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to add route (may require admin privileges): {e}")
            logger.warning(f"Route command error output: {e.stderr}")
        except Exception as e:
            logger.warning(
                f"An unexpected error occurred while setting up routing: {e}"
            )

    def _setup_macos(self) -> bool:
        """Set up TUN device on macOS"""
        logger.info("macOS detected. Setting up TUN interface.")
        # Requires TUN/TAP driver (e.g., tuntaposx) to be installed.
        try:
            # Check for TUN/TAP driver (simple check, might not be foolproof)
            if not any(f.startswith("utun") for f in os.listdir("/dev")):
                logger.warning(
                    "No /dev/utun* devices found. TUN/TAP driver might be missing."
                )
                # Attempt to load kext, might require user interaction or sudo
                try:
                    subprocess.run(
                        ["sudo", "kextload", "/Library/Extensions/tun.kext"],
                        check=True,
                        capture_output=True,
                    )
                    subprocess.run(
                        ["sudo", "kextload", "/Library/Extensions/tap.kext"],
                        check=True,
                        capture_output=True,
                    )
                    logger.info("Attempted to load tun/tap kexts.")
                except Exception as kext_e:
                    logger.warning(
                        f"Could not load kexts: {kext_e}. Please install TUN/TAP driver (e.g., tuntaposx). Manual loading might be needed."
                    )
                    # return False # Decide if you want to fail here or try anyway

            # Find an available utun device
            tun_device_path = None
            for i in range(256):  # Check utun0 to utun255
                path = f"/dev/utun{i}"
                try:
                    fd = os.open(path, os.O_RDWR)
                    # Successfully opened, this is our device
                    self.tun_fd = fd
                    # Get the actual interface name assigned by the kernel
                    # This requires more complex ioctl calls (SIOCGIFNAME) or parsing ifconfig output
                    # For simplicity, we'll assume the name matches utun{i} for configuration
                    # but this might not always be true if interfaces are renamed.
                    # A more robust method involves socket ioctls.
                    self.interface_name = (
                        f"utun{i}"  # Update interface name based on opened device
                    )
                    tun_device_path = path
                    logger.info(
                        f"Opened TUN device: {path} as interface {self.interface_name}"
                    )
                    break
                except OSError as e:
                    if e.errno == 16:  # Device busy
                        continue
                    elif (
                        e.errno == 2
                    ):  # No such file or directory (shouldn't happen if driver is loaded)
                        continue
                    else:
                        raise  # Re-raise other errors

            if self.tun_fd is None:
                logger.error("Could not find or open an available utun device.")
                return False

            # Configure the interface using ifconfig
            subprocess.run(
                ["ifconfig", self.interface_name, "inet", self.local_ip, self.local_ip],
                check=True,
            )
            subprocess.run(
                ["ifconfig", self.interface_name, "netmask", f"{self.prefix_len}"],
                check=True,
            )  # This might not be the correct way to set prefixlen on macOS
            subprocess.run(["ifconfig", self.interface_name, "up"], check=True)

            # Set non-blocking (less critical on macOS compared to Linux select/poll)
            # import fcntl
            # flags = fcntl.fcntl(self.tun_fd, fcntl.F_GETFL)
            # fcntl.fcntl(self.tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            logger.info(
                f"macOS TUN device '{self.interface_name}' set up with IP {self.local_ip}"
            )
            return True
        except FileNotFoundError:
            logger.error("'ifconfig' command not found. Cannot configure interface.")
            return False
        except PermissionError:
            logger.error(
                "Permission denied. Run as root or with appropriate permissions."
            )
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Error configuring macOS interface: {e}")
            logger.error(f"Command output: {e.stderr}")
            if self.tun_fd is not None:
                os.close(self.tun_fd)
                self.tun_fd = None
            return False
        except Exception as e:
            logger.error(f"Failed to set up macOS TUN device: {e}")
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
            # For socket proxy, we might need to send a dummy packet to unblock recvfrom
            if self.os_name == "windows" and self.tun_fd:
                try:
                    dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    dummy_socket.sendto(b"stop", ("127.0.0.1", self.tunnel_port))
                    dummy_socket.close()
                except Exception as e:
                    logger.warning(f"Could not send stop signal to Windows proxy: {e}")

            self.reader_thread.join(timeout=1)
            if self.reader_thread.is_alive():
                logger.warning("Tunnel packet reader thread did not stop gracefully.")
            self.reader_thread = None

        logger.info("Tunnel stopped")

    def cleanup(self):
        """Clean up resources (close file descriptor/socket, remove interface)."""
        logger.info(f"Cleaning up tunnel interface '{self.interface_name}'...")
        self.stop()

        # Close the file descriptor or socket
        if self.tun_fd is not None:
            try:
                if self.os_name == "windows":
                    self.tun_fd.close()
                else:
                    os.close(self.tun_fd)
                self.tun_fd = None
                logger.info("Tunnel descriptor/socket closed.")
            except Exception as e:
                logger.error(f"Error closing tunnel descriptor/socket: {e}")

        # Clean up the interface configuration
        try:
            if self.os_name == "linux":
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
            elif self.os_name == "darwin":
                # Interface might be automatically destroyed when fd is closed,
                # but explicitly bringing it down is good practice.
                subprocess.run(
                    ["ifconfig", self.interface_name, "down"],
                    check=False,
                    stderr=subprocess.DEVNULL,
                )
                # Deleting utun interfaces might not be standard practice or necessary
                # os.system(f"ifconfig {self.interface_name} destroy")
                logger.info(f"macOS interface '{self.interface_name}' brought down.")
            elif self.os_name == "windows":
                # Attempt to remove the route
                try:
                    subprocess.run(
                        ["route", "delete", "10.10.0.0"],
                        check=False,
                        capture_output=True,
                    )
                    logger.info(
                        "Attempted to remove route (requires admin privileges)."
                    )
                except Exception:
                    logger.warning("Could not automatically remove route.")
        except Exception as e:
            logger.error(f"Error during interface cleanup commands: {e}")

        logger.info(f"Tunnel interface '{self.interface_name}' cleanup complete.")

    def read_packet(self, max_size=4096) -> Optional[bytes]:
        """
        Read a packet from the tunnel (non-blocking).

        Args:
            max_size: Maximum packet size to read.

        Returns:
            bytes or None: Packet data if available, None otherwise.
        """
        if not self.tun_fd or not self.running:
            # logger.debug("Tunnel not ready or not running for reading.")
            return None

        with self.read_lock:
            try:
                if self.os_name == "windows":
                    # Read from the UDP socket (Windows proxy)
                    data, _ = self.tun_fd.recvfrom(max_size)
                    # Ignore dummy stop packet
                    if data == b"stop":
                        return None
                    return data
                else:
                    # Read from the TUN file descriptor (Linux/macOS)
                    return os.read(self.tun_fd, max_size)
            except BlockingIOError:
                # This is expected when no data is available on non-blocking fd/socket
                return None
            except ConnectionResetError:  # Can happen on Windows socket
                logger.warning(
                    "ConnectionResetError during read (Windows socket closed?)."
                )
                self.stop()
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

    def write_packet(self, packet: bytes) -> bool:
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
                if self.os_name == "windows":
                    # Write to the UDP socket (Windows proxy)
                    # Need a target address, send back to itself for the handler loop
                    bytes_sent = self.tun_fd.sendto(
                        packet, ("127.0.0.1", self.tunnel_port)
                    )
                else:
                    # Write to the TUN file descriptor (Linux/macOS)
                    bytes_sent = os.write(self.tun_fd, packet)
                return bytes_sent == len(packet)
            except BlockingIOError:
                # The write buffer might be full
                logger.warning("Write would block. Packet dropped.")
                return False
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

        while self.running and self.tun_fd is not None:
            try:
                # Read a packet from the tunnel interface
                packet = self.read_packet(max_size=4096)

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

                # Check if this is a packet from our subnet
                if IPv4Address(dst_ip) in self.subnet:
                    # Call the general packet handler if registered
                    if self.packet_handler:
                        self.packet_handler(packet, dst_ip)

                    # Call the specific callback for this destination IP if registered
                    if dst_ip in self.packet_callbacks:
                        try:
                            self.packet_callbacks[dst_ip](packet)
                        except Exception as e:
                            logger.error(f"Error in packet callback for {dst_ip}: {e}")
                    else:
                        logger.debug(
                            f"No callback registered for destination IP: {dst_ip}"
                        )

            except Exception as e:
                logger.error(f"Error in packet reader loop: {e}")
                import traceback

                logger.error(traceback.format_exc())
                time.sleep(0.1)  # Add delay to avoid tight loop on continuous errors

        logger.info("Packet reader loop stopped")

    def read(self, mtu: int = 4096) -> bytes | None:
        """Read a packet from the TUN device (non-blocking)."""
        if not self.tun_fd:
            logger.error("TUN device not initialized or closed.")
            return None

        try:
            # Check if the file descriptor is ready for reading
            ready_to_read, _, _ = select.select(
                [self.tun_fd], [], [], 0.01
            )  # Small timeout
            if self.tun_fd in ready_to_read:
                try:
                    return os.read(self.tun_fd, mtu)
                except BlockingIOError as e:
                    # This happens with non-blocking I/O when no data is available
                    # It's not an error, just return None to indicate no data
                    if e.errno == 11:  # Resource temporarily unavailable (EAGAIN/EWOULDBLOCK)
                        return None
                    else:
                        # For other BlockingIOError types, log but don't close the TUN
                        logger.warning(f"BlockingIOError in read() but not EAGAIN: {e}")
                        return None
            else:
                return None  # No data available
        except OSError as e:
            # Only close the TUN device for serious errors, not normal non-blocking behavior
            if e.errno == 9:  # Bad file descriptor
                logger.error(f"Bad file descriptor error reading from TUN device: {e}")
                self.close()  # Attempt to clean up
            else:
                logger.warning(f"OSError reading from TUN device: {e}, continuing operation")
            return None
        except Exception as e:
            logger.error(f"Unexpected error reading from TUN device: {e}")
            return None

    def write(self, packet: bytes) -> int | None:
        """Write a packet to the TUN device."""
        if not self.tun_fd:
            logger.error("TUN device not initialized or closed.")
            return None
        try:
            return os.write(self.tun_fd, packet)
        except OSError as e:
            logger.error(f"Error writing to TUN device: {e}")
            self.close()  # Attempt to clean up
            return None
        except Exception as e:
            logger.error(f"Unexpected error writing to TUN device: {e}")
            return None

    def close(self):
        """Clean up the TUN device."""
        if self.tun_fd is not None:
            try:
                os.close(self.tun_fd)
                self.tun_fd = None
                logger.info(f"Closed TUN device for {self.interface_name}")
            except OSError as e:
                logger.error(f"Error closing TUN device {self.interface_name}: {e}")

        # Teardown commands (consider platform specifics if needed)
        try:
            if sys.platform.startswith("linux"):
                # Bring the interface down
                subprocess.run(
                    ["ip", "link", "set", "dev", self.interface_name, "down"],
                    check=False,
                )
                # Optionally delete the interface (might require root)
                # subprocess.run(["ip", "tuntap", "del", "dev", self.interface_name, "mode", "tun"], check=False)
                logger.info(f"Brought down interface {self.interface_name}")
            elif sys.platform == "darwin":
                # On macOS, closing the FD usually suffices, but explicit down might be good
                subprocess.run(["ifconfig", self.interface_name, "down"], check=False)
                logger.info(f"Brought down interface {self.interface_name}")

        except FileNotFoundError:
            logger.warning(
                "Network configuration commands (ip/ifconfig) not found during cleanup."
            )
        except subprocess.CalledProcessError as e:
            logger.warning(
                f"Error during interface teardown for {self.interface_name}: {e}"
            )
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
    if platform.system().lower() == "windows":
        if_name = "LoopbackTunnel"  # Name is conceptual on Windows proxy
        ip_addr = "10.10.0.100"  # Example IP
    elif platform.system().lower() == "linux":
        if_name = "tun_smesh0"
        ip_addr = "10.10.0.10"
    elif platform.system().lower() == "darwin":
        if_name = "utun_smesh"  # Actual name will be utunX
        ip_addr = "10.10.0.10"
    else:
        logger.error("Unsupported platform for example.")
        sys.exit(1)

    try:
        # Use context manager for automatic setup and cleanup
        with Tunnel(interface_name=if_name, local_ip=ip_addr) as tunnel:
            logger.info(f"Tunnel interface '{tunnel.interface_name}' is up.")

            # Register a callback (especially useful for Windows)
            tunnel.register_packet_callback(handle_packet_from_tunnel)

            logger.info("Tunnel running. Press Ctrl+C to stop.")

            # Keep the main thread alive while the tunnel runs
            # On Linux/macOS, you might read packets here instead of using callbacks
            if tunnel.os_name != "windows":
                while tunnel.running:
                    packet = tunnel.read_packet()
                    if packet:
                        handle_packet_from_tunnel(packet)
                    else:
                        time.sleep(0.01)  # Prevent busy-waiting
            else:
                # On Windows, the handler thread runs the callbacks
                while tunnel.running:
                    time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Ctrl+C received, shutting down.")
    except RuntimeError as e:
        logger.error(f"Failed to initialize tunnel: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        import traceback

        logger.error(traceback.format_exc())

    logger.info("Tunnel example finished.")
