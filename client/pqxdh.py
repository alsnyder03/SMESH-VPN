import os
import liboqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


class PQXDH:
    """
    Post-Quantum Extended Diffie-Hellman (PQXDH) implementation.
    Combines classical X25519 with a post-quantum KEM algorithm.
    """

    def __init__(self, pq_algorithm="Kyber768"):
        """
        Initialize the PQXDH key exchange.

        Args:
            pq_algorithm (str): Post-quantum algorithm to use (default: Kyber768)
        """
        self.pq_algorithm = pq_algorithm
        self.classical_private_key = None
        self.classical_public_key = None
        self.pq_client = None
        self.pq_public_key = None
        self.pq_secret = None
        self.shared_secret = None

    def generate_keys(self):
        """Generate both classical and post-quantum key pairs"""
        # Generate classical X25519 keys
        self.classical_private_key = x25519.X25519PrivateKey.generate()
        self.classical_public_key = self.classical_private_key.public_key()

        # Generate post-quantum keys
        self.pq_client = liboqs.KeyEncapsulation(self.pq_algorithm)
        self.pq_public_key = self.pq_client.generate_keypair()

        return {
            "classical_public": self.classical_public_key.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
            "pq_public": self.pq_public_key,
        }

    def process_peer_keys(self, peer_classical_public, peer_pq_public):
        """
        Process the peer's public keys and generate shared secret.

        Args:
            peer_classical_public (bytes): Peer's classical public key
            peer_pq_public (bytes): Peer's post-quantum public key

        Returns:
            bytes: The shared secret
        """
        # Convert peer's classical public key bytes to a key object
        peer_classical_key = x25519.X25519PublicKey.from_public_bytes(
            peer_classical_public
        )

        # Perform classical key exchange
        classical_shared = self.classical_private_key.exchange(peer_classical_key)

        # Perform post-quantum key encapsulation
        ciphertext, pq_shared = liboqs.KeyEncapsulation(self.pq_algorithm).encap_secret(
            peer_pq_public
        )
        self.pq_secret = pq_shared

        # Combine both shared secrets using HKDF
        self.shared_secret = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"PQXDH-Shared-Secret"
        ).derive(classical_shared + pq_shared)

        return {"shared_secret": self.shared_secret, "ciphertext": ciphertext}

    def decapsulate(self, ciphertext):
        """
        Decapsulate the post-quantum shared secret.

        Args:
            ciphertext (bytes): The ciphertext from peer

        Returns:
            bytes: The shared secret
        """
        # Decapsulate post-quantum shared secret
        pq_shared = self.pq_client.decap_secret(ciphertext)

        # The classical shared secret should already be computed
        # Now combine with the post-quantum shared secret
        self.shared_secret = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"PQXDH-Shared-Secret"
        ).derive(self.shared_secret + pq_shared)

        return self.shared_secret

    def get_shared_secret(self):
        """Return the established shared secret"""
        return self.shared_secret
