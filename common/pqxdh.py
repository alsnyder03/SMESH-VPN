from kyber_py.ml_kem import ML_KEM_1024
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives import hashes


class PQXDHServer:
    """
    Post-Quantum Extended Diffie-Hellman (PQXDH) implementation.
    Combines classical X448 with a post-quantum KEM algorithm.
    """

    def __init__(self):
        """
        Initialize the PQXDH key exchange.
        """
        self.classical_private_key = None
        self.classical_public_key = None
        self.shared_secret = None

    def generate_keys(self):
        """Generate classical key pair"""
        self.classical_private_key = x448.X448PrivateKey.generate()
        self.classical_public_key = self.classical_private_key.public_key()

        return {
            "classical_public": self.classical_public_key.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
        }

    def exchange(
        self, client_classical_public: bytes, client_pq_public: bytes
    ) -> bytes:
        """
        Recieves public keys from client, computes classical shared secret,
        create and send pq ciphertext.
        This is the server's part of the key exchange.

        Args:
            client_classical_public (bytes): EC public key from client
            client_pq_public (bytes): PQ public key from client

            Returns:
                bytes: ciphertext to send to client
        """
        # Classical part - works like traditional Diffie-Hellman
        # Both parties can derive the same shared secret without sending anything else
        client_classical_key = x448.X448PublicKey.from_public_bytes(
            client_classical_public
        )
        classical_shared = self.classical_private_key.exchange(client_classical_key)

        # Post-quantum part - uses Key Encapsulation Mechanism
        # This creates:
        # 1. A random secret that we know
        # 2. A ciphertext that encapsulates this secret for the peer
        # We must send the ciphertext to the peer - NOT the secret itself
        pq_secret, ciphertext = ML_KEM_1024.encaps(client_pq_public)

        # create secret from classical shared secret and pq_secret
        self.shared_secret = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=None, info=b"PQXDH-Shared-Secret"
        ).derive(classical_shared + pq_secret)

        # Return the ciphertext - this must be sent to the peer
        # The secret itself is never transmitted
        return ciphertext


class PQXDHClient:
    """
    Post-Quantum Extended Diffie-Hellman (PQXDH) implementation.
    Combines classical X448 with a post-quantum KEM algorithm.
    """

    def __init__(self):
        """
        Initialize the PQXDH key exchange.

        Args:
            pq_algorithm (str): Post-quantum algorithm to use (default: ML-KEM-1024)
        """
        self.classical_private_key = None
        self.classical_public_key = None
        self.pq_client = None
        self.pq_public_key = None
        self.shared_secret = None
        self.classical_shared = None  # Store classical shared secret

    def generate_keys(self):
        """Generate both classical and post-quantum key pairs"""
        # Generate classical X25519 (elliptic curve) keys
        self.classical_private_key = x448.X448PrivateKey.generate()
        self.classical_public_key = self.classical_private_key.public_key()

        # Generate post-quantum keys
        # encapsulate the post quantum key with elliptic curve
        # in case the post quantum key has an unknown analytical flaw
        self.pq_public_key, self.pq_private_key = ML_KEM_1024.keygen()

        return {
            "classical_public": self.classical_public_key.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
            "pq_public": self.pq_public_key,
        }

    def exchange(self, server_classical_public: bytes, server_ciphertext: bytes):
        """
        Recieves public keys from server, computes classical shared secret
        This is the client's part of the key exchange.

        Args:
            server_classical_public (bytes): EC public key from server

        """
        # Classical part - works like traditional Diffie-Hellman
        # Both parties can derive the same shared secret without sending anything else
        server_classical_key = x448.X448PublicKey.from_public_bytes(
            server_classical_public
        )
        self.classical_shared = self.classical_private_key.exchange(
            server_classical_key
        )

        # Recover the peer's secret from their ciphertext
        # This is possible because we have the matching private key
        server_pq_secret = ML_KEM_1024.decaps(self.pq_private_key, server_ciphertext)

        # 1. Classical shared secret (traditional Diffie-Hellman)
        # 2. Post-quantum secret (KEM)
        # length is 32 bytes (256 bits) for the HKDF output
        # for use as AES key
        self.shared_secret = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=None, info=b"PQXDH-Shared-Secret"
        ).derive(self.classical_shared + server_pq_secret)

        return self.shared_secret

    def get_shared_secret(self):
        """Return the established shared secret"""
        if not self.shared_secret:
            raise ValueError(
                "Shared secret not yet established. Complete the key exchange first."
            )
        return self.shared_secret
