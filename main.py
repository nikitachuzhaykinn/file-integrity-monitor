import sys
import os
import config
import argparse
from core.scanner import create_baseline, check_integrity
from core.signature import prompt_for_password


def print_usage():
    """Выводит справку по использованию."""
    print("File Integrity Monitor (FIM) с цифровой подписью")
    print("-" * 50)
    print("Использование:")
    print("  python main.py init    - Создать базовую линию")
    print("  python main.py check   - Проверить целостность")
    print("  python keygen.py       - Сгенерировать ключи")
    print("-" * 50)


def main():
    """Главная функция программы."""
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
        # Проверяем наличие приватного ключа
        if not os.path.exists(config.PRIVATE_KEY_FILE):
            print("[!] Warning: Приватный ключ не найден!")
            print("[!] Для подписи baseline рекомендуется запустить: python keygen.py")
            response = input("Продолжить без подписи? (y/N): ").strip().lower()
            if response != 'y':
                print("[*] Отменено.")
                return
            password = None
        else:
            # Запрашиваем пароль для приватного ключа
            print("\n[*] Для подписи baseline требуется приватный ключ.")
            password = prompt_for_password("Введите пароль от приватного ключа: ")
            if password is None:
                print("[!] Пароль не введён. Попытка загрузить ключ без пароля...")
                password = None
            else:
                print("[*] Пароль принят")

        print(f"\n[*] Создание базовой линии для: {target_dir}")
        # Модифицируем create_baseline для передачи пароля
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