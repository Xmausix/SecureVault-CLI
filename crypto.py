import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    key_bytes = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key_bytes)


def generate_salt() -> bytes:
    return os.urandom(32)


def encrypt(plaintext: str, key: bytes) -> str:
    fernet = Fernet(key)
    encrypted_bytes = fernet.encrypt(plaintext.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt(ciphertext: str, key: bytes) -> str:
    fernet = Fernet(key)
    decrypted_bytes = fernet.decrypt(ciphertext.encode("utf-8"))
    return decrypted_bytes.decode("utf-8")


def hash_master_password(master_password: str, salt: bytes) -> str:
    salted = master_password.encode("utf-8") + salt
    return hashlib.sha256(salted).hexdigest()