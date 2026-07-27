import json
import os
import config
from core.signature import (
    sign_file,
    verify_file_signature,
    load_private_key,
    load_public_key,
    load_private_key_from_storage,
    load_public_key_from_storage,
    check_storage_status
)


def get_private_key(password=None):
    if config.USE_KEYRING and check_storage_status()['available']:
        private_key = load_private_key_from_storage(password, config.KEYRING_USERNAME)
        if private_key:
            return private_key

    if os.path.exists(config.PRIVATE_KEY_FILE):
        try:
            return load_private_key(config.PRIVATE_KEY_FILE, password)
        except Exception as e:
            print(f"[!] Ошибка загрузки ключа из файла: {e}")
            return None

    return None


def get_public_key():
    if config.USE_KEYRING and check_storage_status()['available']:
        public_key = load_public_key_from_storage(config.KEYRING_USERNAME)
        if public_key:
            return public_key

    if os.path.exists(config.PUBLIC_KEY_FILE):
        try:
            return load_public_key(config.PUBLIC_KEY_FILE)
        except Exception as e:
            print(f"[!] Ошибка загрузки ключа из файла: {e}")
            return None

    return None


def save_baseline(baseline_data, password=None):
    with open(config.BASELINE_FILE, 'w', encoding=config.ENCODING) as f:
        json.dump(baseline_data, f, indent=4, ensure_ascii=False)

    print(f"[+] Базовая линия сохранена в {config.BASELINE_FILE}")

    private_key = get_private_key(password)

    if private_key:
        try:
            sign_file(config.BASELINE_FILE, private_key, config.BASELINE_SIGNATURE_FILE)
        except Exception as e:
            print(f"[!] Ошибка подписи: {e}")
    else:
        print("[!] Warning: Приватный ключ не найден. Baseline не подписан.")
        print("[!] Запустите: python keygen.py")


def load_baseline():
    if not os.path.exists(config.BASELINE_FILE):
        return None

    public_key = get_public_key()

    if (public_key is not None and
        os.path.exists(config.BASELINE_SIGNATURE_FILE)):

        print("[*] Проверка цифровой подписи baseline.json...")
        try:
            is_valid = verify_file_signature(
                config.BASELINE_FILE,
                public_key,
                config.BASELINE_SIGNATURE_FILE
            )

            if not is_valid:
                print("[!] КРИТИЧЕСКАЯ ОШИБКА: Подпись невалидна!")
                print("[!] Возможно, baseline.json был скомпрометирован!")
                return None

        except Exception as e:
            print(f"[!] Ошибка проверки подписи: {e}")
            return None
    else:
        print("[!] Warning: Подпись не проверяется (нет ключей)")

    with open(config.BASELINE_FILE, 'r', encoding=config.ENCODING) as f:
        return json.load(f)


def baseline_exists():
    return os.path.exists(config.BASELINE_FILE)