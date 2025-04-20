import logging
from pqxdh import PQXDHServer, PQXDHClient

# Setup logging to debug the key exchange
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create two PQXDH instances to simulate key exchange between two parties
server = PQXDHServer()
client = PQXDHClient()

# Step 1: Generate key pairs for both parties
print("Generating key pairs...")
keys1 = server.generate_keys()
keys2 = client.generate_keys()

ciphertext = server.exchange(
    keys2["classical_public"],
    keys2["pq_public"],
)

client.exchange(keys1["classical_public"], ciphertext)
# Step 3: Exchange ciphertexts for post quantum secret and complete the key exchange


# Step 4: Verify that both parties derived the same shared secret
print(f"Party 1 Shared Secret: {server.shared_secret.hex()}")
print(f"Party 2 Shared Secret: {client.shared_secret.hex()}")
print(
    f"Shared secrets match: {server.shared_secret.hex() == client.shared_secret.hex()}"
)
