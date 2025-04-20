import unittest
import logging
import os
import sys

# Add the parent directory to the path so we can import the module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from client.pqxdh import PQXDHServer, PQXDHClient


class TestPQXDH(unittest.TestCase):
    """Test cases for the Post-Quantum Extended Diffie-Hellman (PQXDH) implementation."""

    def setUp(self):
        """Set up test fixtures before each test method."""
        # Configure logging
        logging.basicConfig(level=logging.DEBUG)
        self.logger = logging.getLogger(__name__)

        # Create instances for testing
        self.server = PQXDHServer()
        self.client = PQXDHClient()

    def tearDown(self):
        """Clean up after each test method."""
        self.server = None
        self.client = None

    def test_key_generation(self):
        """Test that keys are properly generated."""
        # Generate key pairs
        server_keys = self.server.generate_keys()
        client_keys = self.client.generate_keys()

        # Verify keys exist and have the correct format
        self.assertIn("classical_public", server_keys)
        self.assertIn("classical_public", client_keys)
        self.assertIn("pq_public", client_keys)

        # Check that the keys are not empty
        self.assertTrue(len(server_keys["classical_public"]) > 0)
        self.assertTrue(len(client_keys["classical_public"]) > 0)
        self.assertTrue(len(client_keys["pq_public"]) > 0)

    def test_key_exchange(self):
        """Test the complete key exchange process."""
        # Step 1: Generate key pairs for both parties
        self.logger.info("Generating key pairs...")
        server_keys = self.server.generate_keys()
        client_keys = self.client.generate_keys()

        # Step 2: Server encapsulates a secret for the client
        self.logger.info("Server encapsulating secret...")
        ciphertext = self.server.exchange(
            client_keys["classical_public"],
            client_keys["pq_public"],
        )

        # Step 3: Client processes the server's public key and ciphertext
        self.logger.info("Client processing keys and ciphertext...")
        client_secret = self.client.exchange(
            server_keys["classical_public"], ciphertext
        )

        # Step 4: Verify that both parties derived the same shared secret
        self.logger.info(f"Server secret: {self.server.shared_secret.hex()}")
        self.logger.info(f"Client secret: {self.client.shared_secret.hex()}")

        self.assertEqual(
            self.server.shared_secret,
            self.client.shared_secret,
            "Shared secrets do not match",
        )

        # Verify the shared secret is of expected length (32 bytes for AES-256)
        self.assertEqual(
            len(self.server.shared_secret),
            32,
            "Shared secret should be 32 bytes (256 bits)",
        )

    def test_multiple_exchanges(self):
        """Test that multiple key exchanges with the same instances work correctly."""
        # First exchange
        server_keys1 = self.server.generate_keys()
        client_keys1 = self.client.generate_keys()
        ciphertext1 = self.server.exchange(
            client_keys1["classical_public"], client_keys1["pq_public"]
        )
        self.client.exchange(server_keys1["classical_public"], ciphertext1)
        shared_secret1 = self.client.shared_secret

        # Store the result
        first_server_secret = self.server.shared_secret
        first_client_secret = self.client.shared_secret

        # Second exchange (should generate different keys)
        server_keys2 = self.server.generate_keys()
        client_keys2 = self.client.generate_keys()
        ciphertext2 = self.server.exchange(
            client_keys2["classical_public"], client_keys2["pq_public"]
        )
        self.client.exchange(server_keys2["classical_public"], ciphertext2)

        # Verify each exchange works
        self.assertEqual(
            first_server_secret,
            first_client_secret,
            "First exchange: shared secrets do not match",
        )
        self.assertEqual(
            self.server.shared_secret,
            self.client.shared_secret,
            "Second exchange: shared secrets do not match",
        )

        # Verify the two exchanges produced different secrets
        self.assertNotEqual(
            first_server_secret,
            self.server.shared_secret,
            "Multiple exchanges should produce different secrets",
        )


if __name__ == "__main__":
    unittest.main()
