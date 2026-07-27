import sys
import os
import config
import argparse
from core.scanner import create_baseline, check_integrity
from core.signature import prompt_for_password, check_storage_status


def print_usage():
    print("File Integrity Monitor (FIM) с цифровой подписью")
    print("-" * 50)
    print("Использование:")
    print("  python main.py init    - Создать базовую линию")
    print("  python main.py check   - Проверить целостность")
    print("  python keygen.py       - Сгенерировать ключи")
    print("-" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor (FIM) - система контроля целостности файлов"
    )
    parser.add_argument(
        'command',
        nargs='?',
        default=None,
        choices=['init', 'check'],
        help='Команда: init (создать baseline) или check (проверить целостность)'
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

    if not os.path.exists(target_dir):
        print(f"[!] Ошибка: Папка '{target_dir}' не найдена.")
        print("[!] Укажите существующую директорию через --dir или создайте её.")
        return

    command = args.command.lower()

    if command == 'init':
        storage_status = check_storage_status()
        if storage_status['available']:
            print(f"[*] Системное хранилище доступно (бэкенд: {storage_status['backend']})")

        private_key_exists = False

        if storage_status['available'] and storage_status['private_key_exists']:
            private_key_exists = True
            print("[*] Приватный ключ найден в системном хранилище")

        if not private_key_exists and os.path.exists(config.PRIVATE_KEY_FILE):
            private_key_exists = True
            print(f"[*] Приватный ключ найден: {config.PRIVATE_KEY_FILE}")

        if not private_key_exists:
            print("[!] Warning: Приватный ключ не найден!")
            print("[!] Для подписи baseline рекомендуется запустить: python keygen.py")
            response = input("Продолжить без подписи? (y/N): ").strip().lower()
            if response != 'y':
                print("[*] Отменено.")
                return
            password = None
        else:
            print("\n[*] Для подписи baseline требуется приватный ключ.")
            password = prompt_for_password("Введите пароль от приватного ключа: ")
            if password is None:
                print("[!] Пароль не введён. Попытка загрузить ключ без пароля...")
            else:
                print("[*] Пароль принят")

        print(f"\n[*] Создание базовой линии для: {target_dir}")
        from core.scanner import scan_directory
        from core.baseline import save_baseline

        data = scan_directory(target_dir)
        save_baseline(data, password)

    elif command == 'check':
        print(f"\n[*] Проверка целостности для: {target_dir}")
        check_integrity(target_dir)

    else:
        print(f"[!] Неизвестная команда: {command}")
        print_usage()


if __name__ == '__main__':
    main()