import sys
import os
import argparse
from core.scanner import create_baseline, check_integrity
from core.code_hasher import save_code_baseline, check_code_integrity
from core.signature import prompt_for_password, check_storage_status
from core.logger import setup_logging
from core.config_loader import config
import logging

setup_logging()
logger = logging.getLogger(__name__)


def print_usage():
    print("File Integrity Monitor (FIM) с цифровой подписью")
    print("-" * 50)
    print("Использование:")
    print("  python main.py init         - Создать базовую линию для файлов")
    print("  python main.py check        - Проверить целостность файлов")
    print("  python main.py code-init    - Создать базовую линию для кода (.py)")
    print("  python main.py code-check   - Проверить целостность кода (.py)")
    print("  python keygen.py            - Сгенерировать ключи")
    print("-" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor (FIM) - система контроля целостности файлов"
    )
    parser.add_argument(
        'command',
        nargs='?',
        default=None,
        choices=['init', 'check', 'code-init', 'code-check'],
        help='Команда: init, check, code-init, code-check'
    )
    parser.add_argument(
        '--dir',
        default=config.TARGET_DIRECTORY,
        help=f'Целевая директория для мониторинга (по умолчанию: {config.TARGET_DIRECTORY})'
    )

    args = parser.parse_args()

    if args.command is None:
        print_usage()
        return

    target_dir = os.path.normpath(args.dir)
    command = args.command.lower()

    if command == 'init':
        if not os.path.exists(target_dir):
            logger.error("Папка '%s' не найдена.", target_dir)
            logger.error("Укажите существующую директорию через --dir или создайте её.")
            return

        storage_status = check_storage_status()
        if storage_status['available']:
            logger.info("Системное хранилище доступно (бэкенд: %s)", storage_status['backend'])

        private_key_exists = False
        password = None

        if config.USE_KEYRING and storage_status['available']:
            from core.keyring_storage import master_key_exists_in_storage
            if master_key_exists_in_storage(config.KEYRING_USERNAME):
                if os.path.exists(config.ENCRYPTED_PRIVATE_KEY_FILE):
                    private_key_exists = True
                    logger.info("Приватный ключ найден (мастер-ключ + зашифрованный файл)")
                else:
                    logger.warning("Мастер-ключ есть, но файл private_key.enc отсутствует")

        if not private_key_exists and os.path.exists(config.PRIVATE_KEY_FILE):
            private_key_exists = True
            logger.info("Приватный ключ найден: %s", config.PRIVATE_KEY_FILE)

        if not private_key_exists:
            logger.warning("Приватный ключ не найден!")
            logger.warning("Для подписи baseline рекомендуется запустить: python keygen.py")
            response = input("Продолжить без подписи? (y/N): ").strip().lower()
            if response != 'y':
                logger.info("Отменено.")
                return
        else:
            logger.info("Для подписи baseline требуется приватный ключ.")
            password = prompt_for_password("Введите пароль от приватного ключа: ")
            if password is None:
                logger.warning("Пароль не введён. Попытка загрузить ключ без пароля...")
            else:
                logger.info("Пароль принят")

        logger.info("Создание базовой линии для: %s", target_dir)
        from core.scanner import scan_directory
        from core.baseline import save_baseline

        data = scan_directory(target_dir)
        save_baseline(data, password)

    elif command == 'check':
        if not os.path.exists(target_dir):
            logger.error("Папка '%s' не найдена.", target_dir)
            return
        logger.info("Проверка целостности для: %s", target_dir)
        check_integrity(target_dir)

    elif command == 'code-init':
        logger.info("Создание кодовой базовой линии...")
        password = None
        # Проверяем наличие ключа (как в init)
        storage_status = check_storage_status()
        private_key_exists = False
        if config.USE_KEYRING and storage_status['available']:
            from core.keyring_storage import master_key_exists_in_storage
            if master_key_exists_in_storage(config.KEYRING_USERNAME):
                if os.path.exists(config.ENCRYPTED_PRIVATE_KEY_FILE):
                    private_key_exists = True
        if not private_key_exists and os.path.exists(config.PRIVATE_KEY_FILE):
            private_key_exists = True

        if private_key_exists:
            password = prompt_for_password("Введите пароль от приватного ключа: ")
            if password is None:
                logger.warning("Пароль не введён. Попытка загрузить ключ без пароля...")
        else:
            logger.warning("Приватный ключ не найден. Кодовая базовая линия будет без подписи.")

        save_code_baseline(password)
        logger.info("Кодовая базовая линия создана.")

    elif command == 'code-check':
        logger.info("Проверка целостности кода...")
        check_code_integrity()

    else:
        logger.error("Неизвестная команда: %s", command)
        print_usage()


if __name__ == '__main__':
    main()