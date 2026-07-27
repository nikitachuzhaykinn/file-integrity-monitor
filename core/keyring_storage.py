"""
Модуль для безопасного хранения криптографических ключей
в системном хранилище (Windows Credential Manager, macOS Keychain, Linux Secret Service)
"""

import keyring
import config

SERVICE_NAME = "fim_project"


def save_key_to_storage(key_name, key_data, username="default"):
    try:
        if not keyring.backend.get_keyring():
            print("[!] Предупреждение: Системное хранилище недоступно")
            return False
        keyring.set_password(SERVICE_NAME, f"{key_name}_{username}", key_data.decode('utf-8'))
        print(f"[+] Ключ '{key_name}' сохранён в системном хранилище")
        return True
    except Exception as e:
        print(f"[!] Ошибка сохранения ключа в хранилище: {e}")
        return False


def load_key_from_storage(key_name, username="default"):
    try:
        key_data = keyring.get_password(SERVICE_NAME, f"{key_name}_{username}")
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


def get_available_backend():
    try:
        backend = keyring.backend.get_keyring()
        if backend:
            return str(backend).split('.')[-1].replace("'>", "")
        return "Недоступен"
    except Exception:
        return "Недоступен"


def is_storage_available():
    try:
        backend = keyring.backend.get_keyring()
        return backend is not None
    except Exception:
        return False