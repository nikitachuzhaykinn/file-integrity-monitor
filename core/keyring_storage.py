"""
Модуль для безопасного хранения криптографических ключей
в системном хранилище (Windows Credential Manager, macOS Keychain, Linux Secret Service)
"""

import keyring
import config
import base64

SERVICE_NAME = "fim_project"


def _get_winvault_backend():
    """Возвращает экземпляр WinVaultKeyring, если доступен."""
    try:
        backends = keyring.backend.get_all_keyring()
        for backend in backends:
            if 'WinVaultKeyring' in str(backend):
                return backend
        return None
    except Exception:
        return None


def is_storage_available():
    """Проверяет доступность системного хранилища через тестовую запись."""
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
    except Exception:
        return False


def get_available_backend():
    """Возвращает имя доступного бэкенда."""
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
        print(f"[+] Ключ '{key_name}' сохранён в системном хранилище")
        return True
    except Exception as e:
        print(f"[!] Ошибка сохранения ключа в хранилище: {e}")
        return False


def load_key_from_storage(key_name, username="default"):
    try:
        backend = _get_winvault_backend()
        if backend is None:
            key_data = keyring.get_password(SERVICE_NAME, f"{key_name}_{username}")
        else:
            key_data = backend.get_password(SERVICE_NAME, f"{key_name}_{username}")
        if key_data:
            print(f"[+] Ключ '{key_name}' загружен из системного хранилища")
            return key_data.encode('utf-8')
        return None
    except Exception as e:
        print(f"[!] Ошибка загрузки ключа из хранилища: {e}")
        return None


def delete_key_from_storage(key_name, username="default"):
    try:
        keyring.delete_password(SERVICE_NAME, f"{key_name}_{username}")
        print(f"[+] Ключ '{key_name}' удалён из системного хранилища")
        return True
    except keyring.errors.PasswordDeleteError:
        print(f"[!] Ключ '{key_name}' не найден в хранилище")
        return False
    except Exception as e:
        print(f"[!] Ошибка удаления ключа: {e}")
        return False


def key_exists_in_storage(key_name, username="default"):
    try:
        key_data = keyring.get_password(SERVICE_NAME, f"{key_name}_{username}")
        return key_data is not None
    except Exception:
        return False


# ---------- Функции для мастер-ключа (для обхода ограничения размера) ----------

def save_master_key_to_storage(master_key: bytes, username="default"):
    """Сохраняет мастер-ключ в системное хранилище, кодируя в base64."""
    try:
        # Кодируем в base64 для безопасного хранения как строки
        key_b64 = base64.b64encode(master_key).decode('ascii')
        backend = _get_winvault_backend()
        if backend is None:
            keyring.set_password(SERVICE_NAME, f"master_key_{username}", key_b64)
        else:
            backend.set_password(SERVICE_NAME, f"master_key_{username}", key_b64)
        print("[+] Мастер-ключ сохранён в системном хранилище")
        return True
    except Exception as e:
        print(f"[!] Ошибка сохранения мастер-ключа: {e}")
        return False


def load_master_key_from_storage(username="default") -> bytes | None:
    """Загружает мастер-ключ из системного хранилища, декодируя из base64."""
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
        print(f"[!] Ошибка загрузки мастер-ключа: {e}")
        return None


def master_key_exists_in_storage(username="default") -> bool:
    """Проверяет, существует ли мастер-ключ в хранилище."""
    try:
        key_data = keyring.get_password(SERVICE_NAME, f"master_key_{username}")
        return key_data is not None
    except Exception:
        return False