"""
Certificate management module for SMESH-VPN

This module provides a CertificateAuthority class that can be used to create and manage
certificates for the SMESH-VPN network.
"""

import os
import json
import logging
import datetime
from typing import Dict, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class CertificateAuthority:
    """
    A class for managing certificates for the SMESH-VPN network.
    """

    def __init__(self, ca_dir: str = "ca", create_if_missing: bool = False):
        """
        Initialize the Certificate Authority

        Args:
            ca_dir: Directory where CA files are stored
            create_if_missing: Create a new CA if one does not exist
        """
        self.ca_dir = ca_dir
        self.ca_key = None
        self.ca_cert = None
        self.clients_db_path = os.path.join(ca_dir, "clients.json") if ca_dir else None

        # Skip CA initialization if ca_dir is None
        if not ca_dir:
            logger.warning("No CA directory specified, skipping CA initialization")
            return

        # Create CA directory if it doesn't exist
        if not os.path.exists(ca_dir):
            if create_if_missing:
                os.makedirs(ca_dir, exist_ok=True)
                logger.info(f"Created CA directory: {ca_dir}")
            else:
                raise FileNotFoundError(f"CA directory {ca_dir} does not exist")

        # Check if we need to create a new CA or load an existing one
        ca_key_path = os.path.join(ca_dir, "ca_key.pem")
        ca_cert_path = os.path.join(ca_dir, "ca_cert.pem")

        if os.path.exists(ca_key_path) and os.path.exists(ca_cert_path):
            # Load existing CA
            self._load_ca(ca_key_path, ca_cert_path)
            logger.info("Loaded existing CA certificate and key")
        elif create_if_missing:
            # Create a new CA
            self._create_ca(ca_key_path, ca_cert_path)
            logger.info("Created new CA certificate and key")
        else:
            raise FileNotFoundError(
                f"CA files not found in {ca_dir} and create_if_missing is False"
            )

        # Initialize client database
        self._init_clients_db()

    def _load_ca(self, key_path: str, cert_path: str):
        """
        Load an existing CA certificate and private key

        Args:
            key_path: Path to CA private key file
            cert_path: Path to CA certificate file
        """
        with open(key_path, "rb") as key_file:
            self.ca_key = serialization.load_pem_private_key(
                key_file.read(), password=None, backend=default_backend()
            )

        with open(cert_path, "rb") as cert_file:
            self.ca_cert = x509.load_pem_x509_certificate(
                cert_file.read(), backend=default_backend()
            )

    def _create_ca(self, key_path: str, cert_path: str):
        """
        Create a new CA certificate and private key

        Args:
            key_path: Path where the CA private key will be saved
            cert_path: Path where the CA certificate will be saved
        """
        # Generate a private key for the CA
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072, backend=default_backend()
        )

        # Define CA subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SMESH-VPN"),
                x509.NameAttribute(NameOID.COMMON_NAME, "SMESH-VPN Root CA"),
            ]
        )

        # Get current time in UTC
        now = datetime.datetime.now(datetime.timezone.utc)

        # Create a CA certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(subject)  # Self-signed, so issuer == subject
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(
            now + datetime.timedelta(days=3650)
        )  # 10 years
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(self.ca_key.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Sign the CA certificate with its own private key
        self.ca_cert = builder.sign(
            private_key=self.ca_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        # Save the CA private key to file
        with open(key_path, "wb") as key_file:
            key_file.write(
                self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save the CA certificate to file
        with open(cert_path, "wb") as cert_file:
            cert_file.write(
                self.ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
            )

    def _init_clients_db(self):
        """Initialize or load the clients database"""
        if not self.clients_db_path:
            return

        if not os.path.exists(self.clients_db_path):
            # Create an empty database
            with open(self.clients_db_path, "w") as f:
                json.dump({}, f)

    def issue_client_certificate(
        self, client_id: str, common_name: str, valid_days: int = 365
    ) -> Tuple[bytes, bytes]:
        """
        Issue a new certificate for a client

        Args:
            client_id: Unique identifier for the client
            common_name: Common name for the certificate
            valid_days: Number of days the certificate will be valid

        Returns:
            Tuple containing the private key (PEM format) and certificate (PEM format)
        """
        # Generate a private key for the client
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Define client subject
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SMESH-VPN"),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

        # Get current time in UTC
        now = datetime.datetime.now(datetime.timezone.utc)

        # Create a certificate
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.not_valid_before(now)

        # Set expiration date
        expiration_date = now + datetime.timedelta(days=valid_days)
        builder = builder.not_valid_after(expiration_date)

        # Generate a unique serial number
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(private_key.public_key())

        # Add client ID as a subject alternative name extension
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(client_id)]), critical=False
        )

        # Set key usage for client certificates
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=False,  # Not a CA
                crl_sign=False,  # Not a CA
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Extended Key Usage - specify client authentication
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            ),
            critical=False,
        )

        # Basic Constraints - not a CA
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )

        # Sign the certificate with the CA private key
        certificate = builder.sign(
            private_key=self.ca_key,
            algorithm=hashes.SHA256(),
            backend=default_backend(),
        )

        # Convert to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        certificate_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)

        # Update the clients database
        self._add_client_to_db(client_id, common_name, expiration_date)

        return private_key_pem, certificate_pem

    def _add_client_to_db(
        self, client_id: str, common_name: str, expiration_date: datetime.datetime
    ):
        """Add a client to the client database"""
        if not self.clients_db_path:
            return

        try:
            with open(self.clients_db_path, "r") as f:
                clients = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            clients = {}

        clients[client_id] = {
            "common_name": common_name,
            "expires_at": expiration_date.isoformat(),
        }

        with open(self.clients_db_path, "w") as f:
            json.dump(clients, f, indent=2)

    def verify_client_certificate(self, client_id: str, cert_data: bytes) -> bool:
        """
        Verify a client certificate against the CA

        Args:
            client_id: Expected client ID
            cert_data: Certificate data in PEM or DER format

        Returns:
            True if certificate is valid, False otherwise
        """
        try:
            # Check if the client is in the database first (if we have a database)
            if self.clients_db_path:
                clients = self.list_authorized_clients()
                if client_id not in clients:
                    logger.warning(
                        f"Client ID {client_id} not found in authorized clients database"
                    )
                    return False

            # Try to load the certificate
            try:
                cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            except ValueError:
                # Try DER format if PEM fails
                cert = x509.load_der_x509_certificate(cert_data, default_backend())

            # Get current time in UTC
            now = datetime.datetime.now(datetime.timezone.utc)

            # Check if the certificate is expired
            if cert.not_valid_after_utc < now:
                logger.warning(f"Certificate for {client_id} has expired")
                return False

            if cert.not_valid_before_utc > now:
                logger.warning(f"Certificate for {client_id} is not yet valid")
                return False

            # If we have a CA certificate, verify against it
            if self.ca_cert:
                # Verify that the certificate was issued by our CA
                public_key = self.ca_cert.public_key()
                try:
                    public_key.verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                except Exception as e:
                    logger.warning(f"Certificate signature verification failed: {e}")
                    return False

            logger.info(f"Certificate validated successfully for client {client_id}")
            return True

        except Exception as e:
            logger.error(f"Error verifying certificate: {e}")
            return False

    def verify_server_certificate(
        self, server_id: str, cert_data: bytes, expected_cert_data: bytes = None
    ) -> bool:
        """
        Verify a server certificate

        Args:
            server_id: Expected server ID
            cert_data: Certificate data in PEM or DER format
            expected_cert_data: Expected certificate data for direct comparison (optional)

        Returns:
            True if certificate is valid, False otherwise
        """
        try:
            # If we have expected certificate data, do a direct comparison
            if expected_cert_data:
                # Load both certificates
                try:
                    received_cert = x509.load_pem_x509_certificate(
                        cert_data, default_backend()
                    )
                    expected_cert = x509.load_pem_x509_certificate(
                        expected_cert_data, default_backend()
                    )

                    # Compare public keys (more reliable than comparing the entire cert)
                    received_key = received_cert.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                    expected_key = expected_cert.public_key().public_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )

                    if received_key != expected_key:
                        logger.warning(
                            "Server certificate public key doesn't match expected certificate"
                        )
                        return False

                    logger.info(
                        f"Server certificate validated successfully against hardcoded certificate"
                    )
                    return True

                except Exception as e:
                    logger.error(f"Error comparing server certificates: {e}")
                    # Fall back to regular validation

            # Otherwise do regular validation
            return self.verify_client_certificate(server_id, cert_data)

        except Exception as e:
            logger.error(f"Error verifying server certificate: {e}")
            return False

    def revoke_client_certificate(self, client_id: str) -> bool:
        """
        Revoke a client certificate

        Args:
            client_id: ID of the client to revoke

        Returns:
            True if certificate was revoked, False if client_id not found
        """
        if not self.clients_db_path:
            logger.warning("No clients database available for revocation")
            return False

        try:
            with open(self.clients_db_path, "r") as f:
                clients = json.load(f)

            if client_id in clients:
                del clients[client_id]

                with open(self.clients_db_path, "w") as f:
                    json.dump(clients, f, indent=2)

                logger.info(f"Certificate for client {client_id} revoked successfully")
                return True
            else:
                logger.warning(f"No certificate found for client {client_id}")
                return False

        except Exception as e:
            logger.error(f"Error revoking certificate: {e}")
            return False

    def list_authorized_clients(self) -> Dict[str, Dict[str, str]]:
        """
        Get a list of all authorized clients

        Returns:
            Dictionary mapping client IDs to their information
        """
        if not self.clients_db_path:
            return {}

        try:
            with open(self.clients_db_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def get_ca_certificate_pem(self) -> bytes:
        """
        Get the CA certificate in PEM format

        Returns:
            CA certificate as PEM-encoded bytes
        """
        if not self.ca_cert:
            return None
        return self.ca_cert.public_bytes(encoding=serialization.Encoding.PEM)

    @staticmethod
    def load_certificate_from_pem(cert_data: bytes) -> x509.Certificate:
        """
        Load a certificate from PEM data

        Args:
            cert_data: Certificate data in PEM format

        Returns:
            Certificate object
        """
        return x509.load_pem_x509_certificate(cert_data, default_backend())
