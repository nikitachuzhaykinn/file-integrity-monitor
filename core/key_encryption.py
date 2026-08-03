import os
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger(__name__)


def generate_master_key() -> bytes:
    return Fernet.generate_key()


def encrypt_private_key(private_key_pem: bytes, master_key: bytes) -> bytes:
    f = Fernet(master_key)
    return f.encrypt(private_key_pem)


def decrypt_private_key(encrypted_data: bytes, master_key: bytes) -> bytes:
    f = Fernet(master_key)
    return f.decrypt(encrypted_data)


def save_encrypted_private_key(private_key_pem: bytes, master_key: bytes, file_path: str):
    encrypted = encrypt_private_key(private_key_pem, master_key)
    with open(file_path, 'wb') as f:
        f.write(encrypted)
    logger.info("Зашифрованный приватный ключ сохранён в %s", file_path)


def load_encrypted_private_key(file_path: str, master_key: bytes) -> bytes:
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    return decrypt_private_key(encrypted, master_key)