"""
SafeKeyGuard - Main Module

"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
import os

class SafeKeyGuard:
    def __init__(self):
        class SafeKeyGuard:
        self.encryption_key = None
        self.load_key()

    def load_key(self):
        import os
import json

class SafeKeyGuard:
    def __init__(self):
        
        self.encryption_key = None
        self.load_key()

    def load_key(self):
        
        key_file_path = "encryption_key.json"

        if os.path.exists(key_file_path):
            # Key file exists, load the key from the file
            with open(key_file_path, "r") as key_file:
                key_data = json.load(key_file)
                self.encryption_key = bytes.fromhex(key_data["key"])
        else:
           
            self.encryption_key = self.generate_key()
            with open(key_file_path, "w") as key_file:
                json.dump({"key": self.encryption_key.hex()}, key_file)

    def generate_key(self):
       
        return os.urandom(32)

if __name__ == "__main__":
    # Example usage
    skg = SafeKeyGuard()
    print("Encryption key loaded:", skg.encryption_key.hex())
        pass
if __name__ == "__main__":
    skg = SafeKeyGuard()
    print("SafeKeyGuard application initialized")
        pass
    def generate_key(self) -> bytes:
        key = os.urandom(32)
        return key
if __name__ == "__main__":
    skg = SafeKeyGuard()
    key = skg.generate_key()
    print("New encryption key generated:", key.hex())
