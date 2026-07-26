import sys
import os
import config
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
    print("Пример:")
    print("  1. python keygen.py          # Генерация ключей")
    print("  2. python main.py init       # Создание baseline")
    print("  3. python main.py check      # Проверка")


def main():
    """Главная функция программы."""
    # Проверка целевой директории
    if not os.path.exists(config.TARGET_DIRECTORY):
        print(f"[!] Ошибка: Папка '{config.TARGET_DIRECTORY}' не найдена.")
        print("[!] Создайте её перед запуском.")
        return

    # Проверка аргументов
    if len(sys.argv) < 2:
        print_usage()
        return

    command = sys.argv[1].lower()

    if command == 'init':
        # Проверяем наличие ключей
        if not os.path.exists(config.PRIVATE_KEY_FILE):
            print("[!] Warning: Приватный ключ не найден!")
            print("[!] Для подписи baseline запустите: python keygen.py")
            response = input("Продолжить без подписи? (y/N): ").strip().lower()
            if response != 'y':
                return

        create_baseline(config.TARGET_DIRECTORY)

    elif command == 'check':
        check_integrity(config.TARGET_DIRECTORY)

    else:
        print(f"[!] Неизвестная команда: {command}")
        print_usage()


if __name__ == '__main__':
    main()