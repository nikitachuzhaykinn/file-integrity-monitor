import os
import hmac
import time
from datetime import datetime
from core.hasher import calculate_multiple_hashes
from core.baseline import save_baseline, load_baseline, baseline_exists
import logging
from core.config_loader import config
import fnmatch
from core.metrics import inc_files_scanned, inc_violations, set_duration, print_metrics, reset_metrics

logger = logging.getLogger(__name__)


def is_ignored(path: str, patterns: list) -> bool:
    base = os.path.basename(path)
    for pattern in patterns:
        if fnmatch.fnmatch(base, pattern):
            return True
    return False


def scan_directory(directory):
    file_hashes = {}
    logger.info("Сканирование: %s", directory)

    base_dir = os.path.abspath(directory)
    ignore_patterns = getattr(config, 'IGNORE_PATTERNS', [])

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d), ignore_patterns)]

        for file_name in files:
            full_path = os.path.join(root, file_name)
            if is_ignored(full_path, ignore_patterns):
                logger.debug("Игнорируем файл: %s", full_path)
                continue

            hashes = calculate_multiple_hashes(full_path)
            if hashes:
                rel_path = os.path.relpath(full_path, base_dir)
                file_hashes[rel_path] = {
                    'hashes': hashes,
                    'timestamp': datetime.now().isoformat()
                }
                inc_files_scanned()

    logger.info("Найдено файлов: %d", len(file_hashes))
    return file_hashes


def create_baseline(directory, password=None):
    data = scan_directory(directory)
    save_baseline(data, password)


def check_integrity(directory):
    reset_metrics('file')
    start_time = time.time()

    if not baseline_exists():
        logger.error("Базовая линия не найдена. Запустите 'init'.")
        return

    baseline_data = load_baseline()
    if baseline_data is None:
        logger.critical("КРИТИЧЕСКАЯ ОШИБКА: Не удалось загрузить baseline.json")
        logger.critical("Проверка целостности НЕ МОЖЕТ быть выполнена!")
        logger.critical("Возможные причины:")
        logger.critical("  1. Подпись невалидна (файл изменён)")
        logger.critical("  2. Отсутствуют ключи проверки")
        logger.critical("  3. Файл повреждён")
        logger.critical("\nРЕКОМЕНДАЦИЯ: Пересоздайте baseline командой 'init'")
        return

    base_dir = os.path.abspath(directory)
    current_files = {}
    violations_list = []
    ignore_patterns = getattr(config, 'IGNORE_PATTERNS', [])

    logger.info("Проверка целостности...")

    for root, dirs, files in os.walk(base_dir):
        dirs[:] = [d for d in dirs if not is_ignored(os.path.join(root, d), ignore_patterns)]

        for file_name in files:
            full_path = os.path.join(root, file_name)
            if is_ignored(full_path, ignore_patterns):
                continue

            rel_path = os.path.relpath(full_path, base_dir)
            hashes = calculate_multiple_hashes(full_path)
            if hashes:
                current_files[rel_path] = hashes
                inc_files_scanned()

    # Проверяем новые и изменённые файлы
    for rel_path, current_hashes in current_files.items():
        if rel_path not in baseline_data:
            violations_list.append(f"[НОВЫЙ] {rel_path}")
            inc_violations()
        else:
            stored_hashes = baseline_data[rel_path]['hashes']
            for alg, current_hash in current_hashes.items():
                if alg not in stored_hashes:
                    violations_list.append(f"[ИЗМЕНЕН] {rel_path} (новый алгоритм {alg})")
                    inc_violations()
                    break
                if not hmac.compare_digest(
                    current_hash.encode('utf-8'),
                    stored_hashes[alg].encode('utf-8')
                ):
                    violations_list.append(f"[ИЗМЕНЕН] {rel_path} (не совпадает {alg})")
                    inc_violations()
                    break

    # Проверяем удалённые файлы
    for rel_path in baseline_data:
        if rel_path not in current_files:
            if not is_ignored(rel_path, ignore_patterns):
                violations_list.append(f"[УДАЛЕН] {rel_path}")
                inc_violations()

    # Длительность сканирования
    duration = time.time() - start_time
    set_duration(duration)

    logger.info("-" * 50)
    if violations_list:
        logger.warning("НАЙДЕНО НАРУШЕНИЙ: %d", len(violations_list))
        for v in violations_list:
            logger.warning(v)
    else:
        logger.info("Нарушений не обнаружено. Система чиста.")
    logger.info("-" * 50)

    # Вывод статистики
    print_metrics()