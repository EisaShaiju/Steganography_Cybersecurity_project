from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

# Function to derive a 32-byte AES key from a passphrase
def derive_key(passphrase: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(16)  # Generate a random 16-byte salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(passphrase.encode())  # Derive key from passphrase
    return key, salt

# Function to encrypt a message using AES
def encrypt_message(message: str, passphrase: str):
    key, salt = derive_key(passphrase)
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad message to be a multiple of 16 bytes
    padded_msg = message + ' ' * (16 - len(message) % 16)
    encrypted_bytes = encryptor.update(padded_msg.encode()) + encryptor.finalize()

    # Encode as base64 for easy embedding in images
    encrypted_data = base64.b64encode(salt + iv + encrypted_bytes).decode()
    return encrypted_data

# Function to decrypt a message using AES
def decrypt_message(encrypted_data: str, passphrase: str):
    try:
        data = base64.b64decode(encrypted_data)
        salt, iv, encrypted_bytes = data[:16], data[16:32], data[32:]

        key, _ = derive_key(passphrase, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        decrypted_msg = decryptor.update(encrypted_bytes) + decryptor.finalize()
        return decrypted_msg.decode().strip()  # Remove padding
    except Exception:
        return "Incorrect passkey or corrupted data!"

# Testing
if __name__ == "__main__":
    msg = "Secret message!"
    key = "mysecurepassword"

    encrypted = encrypt_message(msg, key)
    print("Encrypted:", encrypted)

    decrypted = decrypt_message(encrypted, key)
    print("Decrypted:", decrypted)
