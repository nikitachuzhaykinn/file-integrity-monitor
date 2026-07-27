import os
from datetime import datetime
from core.hasher import calculate_file_hash
from core.baseline import save_baseline, load_baseline, baseline_exists


def scan_directory(directory):
    """Сканирует директорию и возвращает словарь {путь: хеш}."""
    file_hashes = {}
    print(f"[*] Сканирование: {directory}")

    for root, dirs, files in os.walk(directory):
        for file_name in files:
            full_path = os.path.join(root, file_name)
            file_hash = calculate_file_hash(full_path)

            if file_hash:
                file_hashes[full_path] = {
                    'hash': file_hash,
                    'timestamp': datetime.now().isoformat()
                }

    print(f"[+] Найдено файлов: {len(file_hashes)}")
    return file_hashes


def create_baseline(directory, password=None):
    """
    Создает новую базовую линию с опциональным паролем для подписи.
    """
    data = scan_directory(directory)
    save_baseline(data, password)


def check_integrity(directory):
    """Проверяет целостность файлов."""
    if not baseline_exists():
        print("[!] Ошибка: Базовая линия не найдена. Запустите 'init'.")
        return

    baseline_data = load_baseline()

    if baseline_data is None:
        print("[!] КРИТИЧЕСКАЯ ОШИБКА: Не удалось загрузить baseline.json")
        print("[!] Проверка целостности НЕ МОЖЕТ быть выполнена!")
        print("[!] Возможные причины:")
        print("[!]   1. Подпись невалидна (файл изменён)")
        print("[!]   2. Отсутствуют ключи проверки")
        print("[!]   3. Файл повреждён")
        print("\n[!] РЕКОМЕНДАЦИЯ: Пересоздайте baseline командой 'init'")
        return

    current_files = set()
    violations = []

    print(f"[*] Проверка целостности...")

    for root, dirs, files in os.walk(directory):
        for file_name in files:
            full_path = os.path.join(root, file_name)
            current_files.add(full_path)

            current_hash = calculate_file_hash(full_path)

            if full_path not in baseline_data:
                violations.append(f"[НОВЫЙ] {full_path}")
            elif current_hash != baseline_data[full_path]['hash']:
                violations.append(f"[ИЗМЕНЕН] {full_path}")

    for stored_path in baseline_data:
        if stored_path not in current_files:
            violations.append(f"[УДАЛЕН] {stored_path}")

    print("-" * 50)
    if violations:
        print(f"[!] НАЙДЕНО НАРУШЕНИЙ: {len(violations)}")
        for v in violations:
            print(v)
    else:
        print("[+] Нарушений не обнаружено. Система чиста.")
    print("-" * 50)