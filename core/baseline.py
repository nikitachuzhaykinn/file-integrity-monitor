import json
import os
import config
from core.signature import sign_file, verify_file_signature, load_private_key, load_public_key


def save_baseline(baseline_data):
    """Сохраняет базовую линию в JSON файл и подписывает её."""
    # Сохраняем baseline
    with open(config.BASELINE_FILE, 'w', encoding=config.ENCODING) as f:
        json.dump(baseline_data, f, indent=4, ensure_ascii=False)

    print(f"[+] Базовая линия сохранена в {config.BASELINE_FILE}")

    # Подписываем файл, если есть приватный ключ
    if os.path.exists(config.PRIVATE_KEY_FILE):
        try:
            private_key = load_private_key(config.PRIVATE_KEY_FILE)
            sign_file(config.BASELINE_FILE, private_key, config.BASELINE_SIGNATURE_FILE)
        except Exception as e:
            print(f"[!] Warning: Не удалось подписать baseline: {e}")
    else:
        print("[!] Warning: Приватный ключ не найден. Baseline не подписан.")
        print("[!] Создайте ключи: python keygen.py")


def load_baseline():
    """
    Загружает базовую линию из JSON файла с проверкой подписи.

    Возвращает:
        dict: Данные базовой линии или None при ошибке
    """
    if not os.path.exists(config.BASELINE_FILE):
        return None

    # Проверяем подпись, если есть публичный ключ и файл подписи
    if (os.path.exists(config.PUBLIC_KEY_FILE) and
            os.path.exists(config.BASELINE_SIGNATURE_FILE)):

        print("[*] Проверка цифровой подписи baseline.json...")
        try:
            public_key = load_public_key(config.PUBLIC_KEY_FILE)
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

    # Загружаем данные
    with open(config.BASELINE_FILE, 'r', encoding=config.ENCODING) as f:
        return json.load(f)


def baseline_exists():
    """Проверяет существование файла базовой линии."""
    return os.path.exists(config.BASELINE_FILE)