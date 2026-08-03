import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import getpass
from core.config_loader import config
from core.keyring_storage import (
    save_key_to_storage,
    load_key_from_storage,
    key_exists_in_storage,
    is_storage_available,
    get_available_backend,
    save_master_key_to_storage,
    load_master_key_from_storage,
    master_key_exists_in_storage
)
import logging

logger = logging.getLogger(__name__)


def generate_key_pair():
    logger.info("Генерация пары ключей RSA (%d бит)...", config.RSA_KEY_SIZE)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.RSA_KEY_SIZE,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    logger.info("Пара ключей успешно сгенерирована")
    return private_key, public_key


def save_private_key(private_key, file_path, password=None):
    key_dir = os.path.dirname(file_path)
    if key_dir and not os.path.exists(key_dir):
        os.makedirs(key_dir, mode=0o700)

    encryption_algorithm = serialization.NoEncryption()
    if password is not None:
        encryption_algorithm = serialization.BestAvailableEncryption(password)
        logger.info("Приватный ключ будет зашифрован паролем")

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

    with open(file_path, 'wb') as f:
        f.write(pem)

    os.chmod(file_path, 0o600)
    logger.info("Приватный ключ сохранён: %s", file_path)


def load_private_key(file_path, password=None):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Приватный ключ не найден: {file_path}")

    with open(file_path, 'rb') as f:
        key_data = f.read()

    try:
        private_key = serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=default_backend()
        )
        return private_key
    except ValueError as e:
        if "incorrect password" in str(e).lower() or "could not deserialize" in str(e).lower():
            raise ValueError("Неверный пароль или ключ повреждён") from e
        raise


def save_public_key(public_key, file_path):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(file_path, 'wb') as f:
        f.write(pem)

    logger.info("Публичный ключ сохранён: %s", file_path)


def load_public_key(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Публичный ключ не найден: {file_path}")

    with open(file_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    return public_key


def sign_file(file_path, private_key, signature_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    with open(signature_path, 'wb') as f:
        f.write(signature)

    logger.info("Файл подписан: %s", signature_path)


def verify_file_signature(file_path, public_key, signature_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    with open(signature_path, 'rb') as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        logger.info("Подпись верна ✓")
        return True
    except InvalidSignature:
        logger.error("ПОДПИСЬ НЕВЕРНА! Файл мог быть изменён! ✗")
        return False


def save_private_key_to_storage(private_key, password=None, username="default"):
    if not is_storage_available():
        logger.warning("Системное хранилище недоступно")
        return False

    encryption_algorithm = serialization.NoEncryption()
    if password is not None:
        encryption_algorithm = serialization.BestAvailableEncryption(password)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

    return save_key_to_storage('private_key', pem, username)


def load_private_key_from_storage(password=None, username="default"):
    if not is_storage_available():
        logger.warning("Системное хранилище недоступно")
        return None

    key_data = load_key_from_storage('private_key', username)
    if key_data is None:
        logger.warning("Приватный ключ не найден в хранилище")
        return None

    try:
        private_key = serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=default_backend()
        )
        return private_key
    except ValueError as e:
        if "incorrect password" in str(e).lower() or "could not deserialize" in str(e).lower():
            logger.error("Неверный пароль для приватного ключа")
        else:
            logger.error("Ошибка загрузки ключа: %s", e)
        return None


def save_public_key_to_storage(public_key, username="default"):
    if not is_storage_available():
        logger.warning("Системное хранилище недоступно")
        return False

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return save_key_to_storage('public_key', pem, username)


def load_public_key_from_storage(username="default"):
    if not is_storage_available():
        logger.warning("Системное хранилище недоступно")
        return None

    key_data = load_key_from_storage('public_key', username)
    if key_data is None:
        logger.warning("Публичный ключ не найден в хранилище")
        return None

    try:
        public_key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
        return public_key
    except Exception as e:
        logger.error("Ошибка загрузки публичного ключа: %s", e)
        return None


def check_storage_status():
    available = is_storage_available()
    backend = get_available_backend() if available else "Недоступен"

    status = {
        'available': available,
        'backend': backend,
        'private_key_exists': key_exists_in_storage('private_key') if available else False,
        'public_key_exists': key_exists_in_storage('public_key') if available else False
    }
    return status


def prompt_for_storage_choice():
    if not is_storage_available():
        logger.warning("Системное хранилище недоступно. Будет использован файловый метод.")
        return False

    logger.info("Доступно системное хранилище: %s", get_available_backend())
    response = input("Использовать системное хранилище для ключей? (Y/n): ").strip().lower()
    return response != 'n'


def prompt_for_password(prompt="Введите пароль для приватного ключа: "):
    password = getpass.getpass(prompt)
    if password:
        return password.encode('utf-8')
    return None


def prompt_for_password_confirmation():
    while True:
        password1 = getpass.getpass("Введите пароль для защиты ключа (или оставьте пустым): ")
        if not password1:
            return None

        password2 = getpass.getpass("Повторите пароль: ")
        if password1 == password2:
            return password1.encode('utf-8')
        else:
            logger.warning("Пароли не совпадают. Попробуйте снова.")