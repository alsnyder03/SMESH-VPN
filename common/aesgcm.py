from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_aes_gcm(shared_secret, plaintext):
    """
    Encrypts data using AES-GCM.

    Args:
        shared_secret (bytes): The shared secret used as the AES key.
        plaintext (bytes): The plaintext data to encrypt.

    Returns:
        bytes: The encrypted data containing IV, tag, and ciphertext.
    """
    iv = os.urandom(12)  # Generate a random 12-byte IV
    encryptor = Cipher(
        algorithms.AES(shared_secret),
        modes.GCM(iv),
        backend=default_backend(),
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext

def decrypt_aes_gcm(shared_secret, encrypted_data):
    """
    Decrypts data using AES-GCM.

    Args:
        shared_secret (bytes): The shared secret used as the AES key.
        encrypted_data (bytes): The encrypted data containing IV, tag, and ciphertext.

    Returns:
        bytes: The decrypted plaintext.

    Raises:
        ValueError: If the encrypted data is invalid or decryption fails.
    """
    if len(encrypted_data) < 28:
        raise ValueError("Invalid encrypted data. Must contain at least IV and tag.")

    iv = encrypted_data[:12]  # First 12 bytes are the IV
    if len(iv) != 12:
        raise ValueError("Invalid IV size. IV must be exactly 12 bytes.")

    tag = encrypted_data[12:28]  # Next 16 bytes are the GCM tag
    ciphertext = encrypted_data[28:]  # Rest is the ciphertext

    decryptor = Cipher(
        algorithms.AES(shared_secret),
        modes.GCM(iv, tag),
        backend=default_backend(),
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()