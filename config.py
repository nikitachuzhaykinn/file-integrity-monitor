# Папка, которую будем мониторить
TARGET_DIRECTORY = './test_folder'

# Файл для хранения базовой линии (хешей)
BASELINE_FILE = 'baseline.json'

# Файл подписи базовой линии
BASELINE_SIGNATURE_FILE = 'baseline.json.sig'

# Алгоритм хеширования
HASH_ALGORITHM = 'sha256'

# Размер блока для чтения файла (в байтах)
CHUNK_SIZE = 4096

# Кодировка для работы с файлами
ENCODING = 'utf-8'

# Пути к криптографическим ключам (для файлового метода)
PRIVATE_KEY_FILE = 'keys/private_key.pem'
PUBLIC_KEY_FILE = 'keys/public_key.pem'

# Имя пользователя для системного хранилища
KEYRING_USERNAME = 'fim_user'

# Использовать системное хранилище (True) или файлы (False)
USE_KEYRING = True  # None = спрашивать при первом запуске

# Размер RSA ключа (2048 или 4096 бит)
RSA_KEY_SIZE = 2048

# Путь к зашифрованному приватному ключу (используется с мастер-ключом)
ENCRYPTED_PRIVATE_KEY_FILE = 'keys/private_key.enc'