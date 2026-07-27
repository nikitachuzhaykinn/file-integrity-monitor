import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import config
import getpass


def generate_key_pair():
    """Генерирует пару ключей RSA."""
    print(f"[*] Генерация пары ключей RSA ({config.RSA_KEY_SIZE} бит)...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=config.RSA_KEY_SIZE,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    print("[+] Пара ключей успешно сгенерирована")
    return private_key, public_key


def save_private_key(private_key, file_path, password=None):
    """
    Сохраняет приватный ключ в файл с опциональным шифрованием паролем.

    Аргументы:
        private_key: Приватный ключ RSA
        file_path (str): Путь для сохранения
        password (bytes или None): Пароль для шифрования ключа
    """
    # Создаём папку для ключей, если нет
    key_dir = os.path.dirname(file_path)
    if key_dir and not os.path.exists(key_dir):
        os.makedirs(key_dir, mode=0o700)

    # Определяем алгоритм шифрования
    encryption_algorithm = serialization.NoEncryption()
    if password is not None:
        # Используем PBKDF2 для защиты от перебора
        encryption_algorithm = serialization.BestAvailableEncryption(password)
        print("[*] Приватный ключ будет зашифрован паролем")

    # Сериализуем и сохраняем приватный ключ
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

    with open(file_path, 'wb') as f:
        f.write(pem)

    # Устанавливаем права доступа (только владелец)
    os.chmod(file_path, 0o600)
    print(f"[+] Приватный ключ сохранён: {file_path}")


def load_private_key(file_path, password=None):
    """
    Загружает приватный ключ из файла с опциональным паролем.

    Аргументы:
        file_path (str): Путь к файлу ключа
        password (bytes или None): Пароль для расшифровки

    Возвращает:
        PrivateKey: Загруженный приватный ключ

    Исключения:
        FileNotFoundError: Если файл не найден
        ValueError: Неверный пароль или повреждённый ключ
    """
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
    """Сохраняет публичный ключ в файл."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(file_path, 'wb') as f:
        f.write(pem)

    print(f"[+] Публичный ключ сохранён: {file_path}")


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
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    with open(signature_path, 'wb') as f:
        f.write(signature)

    print(f"[+] Файл подписан: {signature_path}")


def verify_file_signature(file_path, public_key, signature_path):
    """
    Проверяет подпись файла.
    """
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
        print("[+] Подпись верна ✓")
        return True
    except InvalidSignature:
        print("[!] ПОДПИСЬ НЕВЕРНА! Файл мог быть изменён! ✗")
        return False


def prompt_for_password(prompt="Введите пароль для приватного ключа: "):
    """
    Безопасно запрашивает пароль у пользователя.

    Возвращает:
        bytes: Пароль в байтах или None, если пароль не введён
    """
    password = getpass.getpass(prompt)
    if password:
        return password.encode('utf-8')
    return None


def prompt_for_password_confirmation():
    """
    Запрашивает пароль с подтверждением.

    Возвращает:
        bytes: Пароль в байтах или None, если пароль не введён
    """
    while True:
        password1 = getpass.getpass("Введите пароль для защиты ключа (или оставьте пустым): ")
        if not password1:
            return None

        password2 = getpass.getpass("Повторите пароль: ")
        if password1 == password2:
            return password1.encode('utf-8')
        else:
            print("[!] Пароли не совпадают. Попробуйте снова.")