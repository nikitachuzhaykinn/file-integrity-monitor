import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64


def generate_master_key() -> bytes:
    """Генерирует новый мастер-ключ (32 байта) для Fernet."""
    return Fernet.generate_key()


def encrypt_private_key(private_key_pem: bytes, master_key: bytes) -> bytes:
    """
    Шифрует PEM-данные приватного ключа с помощью мастер-ключа.
    Возвращает зашифрованные данные.
    """
    f = Fernet(master_key)
    return f.encrypt(private_key_pem)


def decrypt_private_key(encrypted_data: bytes, master_key: bytes) -> bytes:
    """
    Расшифровывает зашифрованный приватный ключ.
    Возвращает PEM-данные.
    """
    f = Fernet(master_key)
    return f.decrypt(encrypted_data)


def save_encrypted_private_key(private_key_pem: bytes, master_key: bytes, file_path: str):
    """Шифрует приватный ключ и сохраняет в файл."""
    encrypted = encrypt_private_key(private_key_pem, master_key)
    with open(file_path, 'wb') as f:
        f.write(encrypted)
    print(f"[+] Зашифрованный приватный ключ сохранён в {file_path}")


def load_encrypted_private_key(file_path: str, master_key: bytes) -> bytes:
    """Загружает зашифрованный приватный ключ из файла и расшифровывает."""
    with open(file_path, 'rb') as f:
        encrypted = f.read()
    return decrypt_private_key(encrypted, master_key)