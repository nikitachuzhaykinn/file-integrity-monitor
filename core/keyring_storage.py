import keyring
import config
import base64
import logging

logger = logging.getLogger(__name__)

SERVICE_NAME = "fim_project"


def _get_winvault_backend():
    try:
        backends = keyring.backend.get_all_keyring()
        for backend in backends:
            if 'WinVaultKeyring' in str(backend):
                return backend
        return None
    except Exception as e:
        logger.debug("Ошибка получения WinVaultKeyring: %s", e)
        return None


def is_storage_available():
    try:
        backend = _get_winvault_backend()
        if backend is None:
            return False
        test_key = "_fim_test_key"
        test_value = "test"
        backend.set_password(SERVICE_NAME, test_key, test_value)
        result = backend.get_password(SERVICE_NAME, test_key)
        backend.delete_password(SERVICE_NAME, test_key)
        return result == test_value
    except Exception as e:
        logger.debug("Хранилище недоступно: %s", e)
        return False


def get_available_backend():
    backend = _get_winvault_backend()
    if backend:
        return "WinVaultKeyring"
    return "Недоступен"


def save_key_to_storage(key_name, key_data, username="default"):
    try:
        backend = _get_winvault_backend()
        if backend is None:
            keyring.set_password(SERVICE_NAME, f"{key_name}_{username}", key_data.decode('utf-8'))
        else:
            backend.set_password(SERVICE_NAME, f"{key_name}_{username}", key_data.decode('utf-8'))
        logger.info("Ключ '%s' сохранён в системном хранилище", key_name)
        return True
    except Exception as e:
        logger.error("Ошибка сохранения ключа в хранилище: %s", e)
        return False


def load_key_from_storage(key_name, username="default"):
    try:
        backend = _get_winvault_backend()
        if backend is None:
            key_data = keyring.get_password(SERVICE_NAME, f"{key_name}_{username}")
        else:
            key_data = backend.get_password(SERVICE_NAME, f"{key_name}_{username}")
        if key_data:
            logger.info("Ключ '%s' загружен из системного хранилища", key_name)
            return key_data.encode('utf-8')
        return None
    except Exception as e:
        logger.error("Ошибка загрузки ключа из хранилища: %s", e)
        return None


def delete_key_from_storage(key_name, username="default"):
    try:
        keyring.delete_password(SERVICE_NAME, f"{key_name}_{username}")
        logger.info("Ключ '%s' удалён из системного хранилища", key_name)
        return True
    except keyring.errors.PasswordDeleteError:
        logger.warning("Ключ '%s' не найден в хранилище", key_name)
        return False
    except Exception as e:
        logger.error("Ошибка удаления ключа: %s", e)
        return False


def key_exists_in_storage(key_name, username="default"):
    try:
        key_data = keyring.get_password(SERVICE_NAME, f"{key_name}_{username}")
        return key_data is not None
    except Exception as e:
        logger.debug("Ошибка проверки существования ключа: %s", e)
        return False


def save_master_key_to_storage(master_key: bytes, username="default"):
    try:
        key_b64 = base64.b64encode(master_key).decode('ascii')
        backend = _get_winvault_backend()
        if backend is None:
            keyring.set_password(SERVICE_NAME, f"master_key_{username}", key_b64)
        else:
            backend.set_password(SERVICE_NAME, f"master_key_{username}", key_b64)
        logger.info("Мастер-ключ сохранён в системном хранилище")
        return True
    except Exception as e:
        logger.error("Ошибка сохранения мастер-ключа: %s", e)
        return False


def load_master_key_from_storage(username="default") -> bytes | None:
    try:
        backend = _get_winvault_backend()
        if backend is None:
            key_b64 = keyring.get_password(SERVICE_NAME, f"master_key_{username}")
        else:
            key_b64 = backend.get_password(SERVICE_NAME, f"master_key_{username}")
        if key_b64:
            return base64.b64decode(key_b64)
        return None
    except Exception as e:
        logger.error("Ошибка загрузки мастер-ключа: %s", e)
        return None


def master_key_exists_in_storage(username="default") -> bool:
    try:
        key_data = keyring.get_password(SERVICE_NAME, f"master_key_{username}")
        return key_data is not None
    except Exception as e:
        logger.debug("Ошибка проверки мастер-ключа: %s", e)
        return False