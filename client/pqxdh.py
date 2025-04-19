import oqs
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives import hashes


class PQXDH:
    """
    Post-Quantum Extended Diffie-Hellman (PQXDH) implementation.
    Combines classical X448 with a post-quantum KEM algorithm.
    """

    def __init__(self, pq_algorithm="ML-KEM-1024"):
        """
        Initialize the PQXDH key exchange.

        Args:
            pq_algorithm (str): Post-quantum algorithm to use (default: ML-KEM-1024)
        """
        self.pq_algorithm = pq_algorithm
        self.classical_private_key = None
        self.classical_public_key = None
        self.pq_client = None
        self.pq_public_key = None
        self.pq_secret = None
        self.shared_secret = None
        self.classical_shared = None  # Store classical shared secret
        self.peer_ciphertext = None  # Store peer's ciphertext

    def generate_keys(self):
        """Generate both classical and post-quantum key pairs"""
        # Generate classical X25519 (elliptic curve) keys
        self.classical_private_key = x448.X448PrivateKey.generate()
        self.classical_public_key = self.classical_private_key.public_key()

        # Generate post-quantum keys
        # encapsulate the post quantum key with elliptic curve
        # in case the post quantum key has an unknown analytical flaw
        self.pq_client = oqs.KeyEncapsulation(self.pq_algorithm)
        self.pq_public_key = self.pq_client.generate_keypair()

        return {
            "classical_public": self.classical_public_key.public_bytes(
                Encoding.Raw, PublicFormat.Raw
            ),
            "pq_public": self.pq_public_key,
        }

    def process_peer_keys(self, peer_classical_public, peer_pq_public):
        """
        Process the peer's public keys.

        For the classical part (ECDH):
        - We compute a shared secret using our private key and peer's public key
        - No information needs to be sent back

        For the post-quantum part (KEM):
        - We generate a random secret and encapsulate it against peer's public key
        - We get a ciphertext that only the peer can decrypt
        - We must send this ciphertext to the peer

        Args:
            peer_classical_public (bytes): Peer's classical public key
            peer_pq_public (bytes): Peer's post-quantum public key

        Returns:
            bytes: Contains ciphertext to send to peer
        """
        # Classical part - works like traditional Diffie-Hellman
        # Both parties can derive the same shared secret without sending anything else
        peer_classical_key = x448.X448PublicKey.from_public_bytes(peer_classical_public)
        self.classical_shared = self.classical_private_key.exchange(peer_classical_key)

        # Post-quantum part - uses Key Encapsulation Mechanism
        # This creates:
        # 1. A random secret that we know
        # 2. A ciphertext that encapsulates this secret for the peer
        # We must send the ciphertext to the peer - NOT the secret itself
        ciphertext, self.pq_secret = oqs.KeyEncapsulation(
            self.pq_algorithm
        ).encap_secret(peer_pq_public)

        # Return the ciphertext - this must be sent to the peer
        # The secret itself is never transmitted
        return ciphertext

    def decapsulate(self, peer_ciphertext):
        """
        Decapsulate the peer's ciphertext to get the shared secret.

        The peer has created a random secret and encapsulated it for us.
        We use our private key to recover that same secret from the ciphertext.

        At this point:
        - We know our classical shared secret (ECDH)
        - We know our random PQ secret that we generated for the peer
        - We know the peer's random PQ secret that they generated for us

        We combine all three to create the final shared secret.

        Args:
            peer_ciphertext (bytes): The ciphertext from peer (NOT the secret itself)

        Returns:
            bytes: The final combined shared secret
        """
        if not self.classical_shared:
            raise ValueError("Must call process_peer_keys before decapsulate")

        # Recover the peer's secret from their ciphertext
        # This is possible because we have the matching private key
        peer_pq_secret = self.pq_client.decap_secret(peer_ciphertext)

        # order matters for the key derivation, sort to make it consistent
        # without sorting, the clients would have different shared secrets
        # because their pq_secrets would be flipped (peer vs self)
        # technically only 1 pq_secret is needed, but we use both to maintain
        # the same process for both parties
        # This is not a security concern, but a consistency one
        pq_secrets = sorted([self.pq_secret, peer_pq_secret])

        # 1. Classical shared secret (traditional Diffie-Hellman)
        # 2 & 3. The two PQ secrets in sorted order
        # length is 32 bytes (256 bits) for the HKDF output
        # for use as AES key
        self.shared_secret = HKDF(
            algorithm=hashes.SHA512(), length=32, salt=None, info=b"PQXDH-Shared-Secret"
        ).derive(self.classical_shared + pq_secrets[0] + pq_secrets[1])

        return self.shared_secret

    def get_shared_secret(self):
        """Return the established shared secret"""
        if not self.shared_secret:
            raise ValueError(
                "Shared secret not yet established. Complete the key exchange first."
            )
        return self.shared_secret
