import os
from core.signature import (
    generate_key_pair,
    save_private_key,
    save_public_key,
    save_private_key_to_storage,
    save_public_key_to_storage,
    prompt_for_password_confirmation,
    prompt_for_storage_choice,
    check_storage_status
)
from core.keyring_storage import (
    save_master_key_to_storage,
    load_master_key_from_storage,
    master_key_exists_in_storage
)
from core.key_encryption import (
    generate_master_key,
    save_encrypted_private_key
)
from core.logger import setup_logging
from core.config_loader import config
import logging

setup_logging()
logger = logging.getLogger(__name__)


def save_keys_to_files(private_key, public_key, password):
    logger.info("Сохранение ключей в файлы...")
    save_private_key(private_key, config.PRIVATE_KEY_FILE, password)
    save_public_key(public_key, config.PUBLIC_KEY_FILE)


def save_keys_with_master_key(private_key, public_key, password, username="default"):
    master_key = load_master_key_from_storage(username)
    if master_key is None:
        logger.info("Мастер-ключ не найден, генерируем новый...")
        master_key = generate_master_key()
        if not save_master_key_to_storage(master_key, username):
            logger.error("Не удалось сохранить мастер-ключ, прерываем.")
            return False
    else:
        logger.info("Мастер-ключ загружен из хранилища.")

    from cryptography.hazmat.primitives import serialization
    encryption_alg = serialization.NoEncryption()
    if password is not None:
        encryption_alg = serialization.BestAvailableEncryption(password)
        logger.info("Приватный ключ будет зашифрован паролем пользователя")

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg
    )

    save_encrypted_private_key(private_pem, master_key, config.ENCRYPTED_PRIVATE_KEY_FILE)

    if config.USE_KEYRING and check_storage_status()['available']:
        save_public_key_to_storage(public_key, username)
    else:
        save_public_key(public_key, config.PUBLIC_KEY_FILE)

    logger.info("Приватный ключ сохранён с использованием мастер-ключа.")
    return True


def main():
    print("=" * 60)
    print("Генерация криптографических ключей для FIM")
    print("=" * 60)

    storage_status = check_storage_status()
    logger.info("Статус системного хранилища: %s", 'Доступно' if storage_status['available'] else 'Недоступно')
    if storage_status['available']:
        logger.info("Бэкенд: %s", storage_status['backend'])

    keys_exist = False
    if os.path.exists(config.ENCRYPTED_PRIVATE_KEY_FILE):
        logger.warning("Зашифрованный приватный ключ уже существует: %s", config.ENCRYPTED_PRIVATE_KEY_FILE)
        keys_exist = True
    elif storage_status['available'] and master_key_exists_in_storage(config.KEYRING_USERNAME):
        logger.warning("Мастер-ключ уже существует в хранилище")
        keys_exist = True

    if keys_exist:
        response = input("Перезаписать существующие ключи? (y/N): ").strip().lower()
        if response != 'y':
            logger.info("Отменено.")
            return

    private_key, public_key = generate_key_pair()

    if not storage_status['available']:
        logger.warning("Системное хранилище недоступно. Будет использован файловый метод.")
        password = prompt_for_password_confirmation()
        save_keys_to_files(private_key, public_key, password)
        logger.info("Ключи сохранены в файлы.")
        return

    logger.info("Будет использовано двухуровневое хранение:")
    logger.info("    - мастер-ключ (AES) в системном хранилище")
    logger.info("    - зашифрованный приватный ключ в файле")
    logger.info("    - публичный ключ в системном хранилище (или файле)")

    print("[!] Вы можете дополнительно защитить приватный ключ паролем.")
    print("[!] Это необязательно, но рекомендуется.")
    password = prompt_for_password_confirmation()
    if password:
        logger.info("Приватный ключ будет дополнительно зашифрован паролем")
    else:
        logger.warning("Предупреждение: приватный ключ не будет защищён паролем (только мастер-ключом)")

    success = save_keys_with_master_key(private_key, public_key, password, config.KEYRING_USERNAME)

    if success:
        print("\n" + "=" * 60)
        print("[+] Ключи успешно сгенерированы!")
        print("=" * 60)
        print(f"Метод хранения: мастер-ключ в системном хранилище + файл {config.ENCRYPTED_PRIVATE_KEY_FILE}")
        if password:
            print("[✓] Приватный ключ дополнительно защищён паролем")
        else:
            print("[!] Приватный ключ защищён только мастер-ключом (без пароля)")
        print("\n[!] ВАЖНО: Храните мастер-ключ (в системном хранилище) и пароль в безопасности!")
        logger.info("Генерация ключей завершена успешно.")
    else:
        logger.error("Ошибка при сохранении ключей.")


if __name__ == '__main__':
    main()