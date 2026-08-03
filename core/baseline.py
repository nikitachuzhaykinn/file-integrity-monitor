import json
import os
import logging
from core.config_loader import config
from core.signature import (
    sign_file,
    verify_file_signature,
    load_private_key,
    load_public_key,
    load_public_key_from_storage,
    check_storage_status
)
from core.keyring_storage import load_master_key_from_storage, master_key_exists_in_storage
from core.key_encryption import load_encrypted_private_key

logger = logging.getLogger(__name__)


def get_private_key(password=None):
    if config.USE_KEYRING and check_storage_status()['available']:
        master_key = load_master_key_from_storage(config.KEYRING_USERNAME)
        if master_key is not None:
            try:
                private_pem = load_encrypted_private_key(config.ENCRYPTED_PRIVATE_KEY_FILE, master_key)
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.backends import default_backend
                private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=password,
                    backend=default_backend()
                )
                logger.info("Приватный ключ загружен через мастер-ключ")
                return private_key
            except Exception as e:
                logger.error("Ошибка загрузки приватного ключа через мастер-ключ: %s", e)

    if os.path.exists(config.PRIVATE_KEY_FILE):
        try:
            return load_private_key(config.PRIVATE_KEY_FILE, password)
        except Exception as e:
            logger.error("Ошибка загрузки ключа из файла: %s", e)
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
            logger.error("Ошибка загрузки публичного ключа: %s", e)
            return None

    return None


def save_baseline(baseline_data, password=None):
    with open(config.BASELINE_FILE, 'w', encoding=config.ENCODING) as f:
        json.dump(baseline_data, f, indent=4, ensure_ascii=False)

    logger.info("Базовая линия сохранена в %s", config.BASELINE_FILE)

    private_key = get_private_key(password)

    if private_key:
        try:
            sign_file(config.BASELINE_FILE, private_key, config.BASELINE_SIGNATURE_FILE)
        except Exception as e:
            logger.error("Ошибка подписи: %s", e)
    else:
        logger.warning("Приватный ключ не найден. Baseline не подписан.")
        logger.warning("Запустите: python keygen.py")


def load_baseline():
    if not os.path.exists(config.BASELINE_FILE):
        return None

    public_key = get_public_key()

    if (public_key is not None and
            os.path.exists(config.BASELINE_SIGNATURE_FILE)):

        logger.info("Проверка цифровой подписи baseline.json...")
        try:
            is_valid = verify_file_signature(
                config.BASELINE_FILE,
                public_key,
                config.BASELINE_SIGNATURE_FILE
            )

            if not is_valid:
                logger.critical("КРИТИЧЕСКАЯ ОШИБКА: Подпись невалидна! Возможно, baseline.json был скомпрометирован!")
                return None

        except Exception as e:
            logger.error("Ошибка проверки подписи: %s", e)
            return None
    else:
        logger.warning("Подпись не проверяется (нет ключей)")

    with open(config.BASELINE_FILE, 'r', encoding=config.ENCODING) as f:
        return json.load(f)


def baseline_exists():
    return os.path.exists(config.BASELINE_FILE)