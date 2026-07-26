import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import config


def generate_key_pair():
    """
    Генерирует пару ключей RSA.

    Возвращает:
        tuple: (private_key, public_key)
    """
    print(f"[*] Генерация пары ключей RSA ({config.RSA_KEY_SIZE} бит)...")

    # Генерируем приватный ключ
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.RSA_KEY_SIZE,
        backend=default_backend()
    )

    # Получаем публичный ключ из приватного
    public_key = private_key.public_key()

    print("[+] Пара ключей успешно сгенерирована")
    return private_key, public_key


def save_private_key(private_key, file_path):
    """Сохраняет приватный ключ в файл."""
    # Создаём папку для ключей, если нет
    key_dir = os.path.dirname(file_path)
    if key_dir and not os.path.exists(key_dir):
        os.makedirs(key_dir, mode=0o700)  # Только владелец имеет доступ

    # Сериализуем и сохраняем приватный ключ
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Можно добавить пароль
    )

    with open(file_path, 'wb') as f:
        f.write(pem)

    # Устанавливаем права доступа (только чтение для владельца)
    os.chmod(file_path, 0o600)
    print(f"[+] Приватный ключ сохранён: {file_path}")


def save_public_key(public_key, file_path):
    """Сохраняет публичный ключ в файл."""
    # Сериализуем и сохраняем публичный ключ
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(file_path, 'wb') as f:
        f.write(pem)

    print(f"[+] Публичный ключ сохранён: {file_path}")


def load_private_key(file_path):
    """Загружает приватный ключ из файла."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Приватный ключ не найден: {file_path}")

    with open(file_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

    return private_key


def load_public_key(file_path):
    """Загружает публичный ключ из файла."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Публичный ключ не найден: {file_path}")

    with open(file_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    return public_key


def sign_file(file_path, private_key, signature_path):
    """
    Подписывает файл приватным ключом.

    Аргументы:
        file_path (str): Путь к файлу для подписи
        private_key: Приватный ключ RSA
        signature_path (str): Путь для сохранения подписи
    """
    # Читаем файл
    with open(file_path, 'rb') as f:
        data = f.read()

    # Создаём подпись
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Сохраняем подпись
    with open(signature_path, 'wb') as f:
        f.write(signature)

    print(f"[+] Файл подписан: {signature_path}")


def verify_file_signature(file_path, public_key, signature_path):
    """
    Проверяет подпись файла.

    Аргументы:
        file_path (str): Путь к файлу
        public_key: Публичный ключ RSA
        signature_path (str): Путь к файлу подписи

    Возвращает:
        bool: True если подпись верна, False если нет

    Исключения:
        InvalidSignature: если подпись невалидна
    """
    # Читаем файл и подпись
    with open(file_path, 'rb') as f:
        data = f.read()

    with open(signature_path, 'rb') as f:
        signature = f.read()

    # Проверяем подпись
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("[+] Подпись верна ✓")
        return True
    except InvalidSignature:
        print("[!] ПОДПИСЬ НЕВЕРНА! Файл мог быть изменён! ✗")
        return False