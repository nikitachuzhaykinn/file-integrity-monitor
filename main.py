import sys
import os
import config
import argparse
from core.scanner import create_baseline, check_integrity


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
    # Настраиваем парсер аргументов
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor (FIM) - система контроля целостности файлов"
    )
    parser.add_argument(
        'command',
        nargs='?',  # <-- Делает аргумент НЕОБЯЗАТЕЛЬНЫМ
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

    # Если команда не указана — выводим справку и выходим
    if args.command is None:
        print_usage()
        return

    # Нормализуем путь для кроссплатформенности (Windows/Linux)
    target_dir = os.path.normpath(args.dir)

    # Проверяем существование целевой директории
    if not os.path.exists(target_dir):
        print(f"[!] Ошибка: Папка '{target_dir}' не найдена.")
        print("[!] Укажите существующую директорию через --dir или создайте её.")
        return

    command = args.command.lower()

    if command == 'init':
        # Проверяем наличие приватного ключа перед созданием baseline
        if not os.path.exists(config.PRIVATE_KEY_FILE):
            print("[!] Warning: Приватный ключ не найден!")
            print("[!] Для подписи baseline рекомендуется запустить: python keygen.py")
            response = input("Продолжить без подписи? (y/N): ").strip().lower()
            if response != 'y':
                print("[*] Отменено.")
                return

        print(f"\n[*] Создание базовой линии для: {target_dir}")
        create_baseline(target_dir)

    elif command == 'check':
        print(f"\n[*] Проверка целостности для: {target_dir}")
        check_integrity(target_dir)

    else:
        print(f"[!] Неизвестная команда: {command}")
        print_usage()


if __name__ == '__main__':
    main()