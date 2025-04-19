import logging
from pqxdh import PQXDH

# Setup logging to debug the key exchange
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create two PQXDH instances to simulate key exchange between two parties
key_exchange1 = PQXDH()
key_exchange2 = PQXDH()

# Step 1: Generate key pairs for both parties
print("Generating key pairs...")
keys1 = key_exchange1.generate_keys()
keys2 = key_exchange2.generate_keys()

# Party 1 processes Party 2's keys and creates ciphertext1
ciphertext1 = key_exchange1.process_peer_keys(
    keys2["classical_public"],
    keys2["pq_public"],
)

# Party 2 processes Party 1's keys and creates ciphertext2
ciphertext2 = key_exchange2.process_peer_keys(
    keys1["classical_public"],
    keys1["pq_public"],
)

# Step 3: Exchange ciphertexts for post quantum secret and complete the key exchange
# Party 1 decapsulates ciphertext2 from Party 2
key_exchange1.decapsulate(ciphertext2)

# Party 2 decapsulates ciphertext1 from Party 1
key_exchange2.decapsulate(ciphertext1)

# Step 4: Verify that both parties derived the same shared secret
print(f"Party 1 Shared Secret: {key_exchange1.shared_secret.hex()}")
print(f"Party 2 Shared Secret: {key_exchange2.shared_secret.hex()}")
print(
    f"Shared secrets match: {key_exchange1.shared_secret.hex() == key_exchange2.shared_secret.hex()}"
)
