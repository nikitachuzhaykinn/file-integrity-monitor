import os
import json
import fnmatch
import logging
from datetime import datetime
from core.hasher import calculate_file_hash
from core.baseline import save_baseline, load_baseline, get_private_key, get_public_key
from core.config_loader import config
from core.signature import sign_file, verify_file_signature

logger = logging.getLogger(__name__)


def is_ignored_code(path, patterns):
    """Проверяет, должен ли файл/папка быть проигнорирован при сканировании кода."""
    base = os.path.basename(path)
    for pattern in patterns:
        if fnmatch.fnmatch(base, pattern):
            return True
    return False


def scan_py_files(directory, ignore_patterns):
    """Сканирует все .py файлы в директории (рекурсивно) и возвращает словарь {путь: хеш}."""
    py_files = {}
    logger.info("Сканирование .py файлов в %s", directory)

    for root, dirs, files in os.walk(directory):
        # Исключаем игнорируемые папки
        dirs[:] = [d for d in dirs if not is_ignored_code(os.path.join(root, d), ignore_patterns)]

        for file_name in files:
            if not file_name.endswith('.py'):
                continue
            full_path = os.path.join(root, file_name)
            if is_ignored_code(full_path, ignore_patterns):
                logger.debug("Игнорируем код: %s", full_path)
                continue

            file_hash = calculate_file_hash(full_path)
            if file_hash:
                py_files[full_path] = file_hash

    logger.info("Найдено .py файлов: %d", len(py_files))
    return py_files


def save_code_baseline(password=None):
    """Создаёт baseline для кода и подписывает его."""
    ignore_patterns = getattr(config, 'CODE_IGNORE_PATTERNS', [])
    # Также добавим стандартные игнорируемые паттерны из основного конфига, если они есть
    # Но для кода они могут быть специфическими, поэтому используем только CODE_IGNORE_PATTERNS.

    # Определяем корень проекта (где находится main.py) – можно взять текущую директорию.
    project_root = os.getcwd()
    baseline_data = scan_py_files(project_root, ignore_patterns)

    # Добавляем временную метку
    baseline_data['_meta'] = {
        'timestamp': datetime.now().isoformat(),
        'type': 'code_baseline'
    }

    # Сохраняем в файл
    with open(config.CODE_BASELINE_FILE, 'w', encoding='utf-8') as f:
        json.dump(baseline_data, f, indent=4, ensure_ascii=False)

    logger.info("Кодовая базовая линия сохранена в %s", config.CODE_BASELINE_FILE)

    # Подписываем
    private_key = get_private_key(password)
    if private_key:
        try:
            sign_file(config.CODE_BASELINE_FILE, private_key, config.CODE_BASELINE_SIGNATURE_FILE)
        except Exception as e:
            logger.error("Ошибка подписи кодовой базовой линии: %s", e)
    else:
        logger.warning("Приватный ключ не найден. Кодовая базовая линия не подписана.")


def load_code_baseline():
    """Загружает baseline кода с проверкой подписи."""
    if not os.path.exists(config.CODE_BASELINE_FILE):
        return None

    public_key = get_public_key()
    if public_key and os.path.exists(config.CODE_BASELINE_SIGNATURE_FILE):
        logger.info("Проверка подписи кодовой базовой линии...")
        try:
            is_valid = verify_file_signature(
                config.CODE_BASELINE_FILE,
                public_key,
                config.CODE_BASELINE_SIGNATURE_FILE
            )
            if not is_valid:
                logger.critical("Подпись кодовой базовой линии НЕВЕРНА! Код может быть скомпрометирован!")
                return None
        except Exception as e:
            logger.error("Ошибка проверки подписи кода: %s", e)
            return None
    else:
        logger.warning("Подпись кода не проверяется (нет ключей или файла подписи).")

    with open(config.CODE_BASELINE_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def check_code_integrity():
    """Проверяет целостность текущих .py файлов."""
    baseline_data = load_code_baseline()
    if baseline_data is None:
        logger.error("Кодовая базовая линия не найдена. Запустите 'code-init'.")
        return

    # Удаляем мета-данные
    baseline_meta = baseline_data.pop('_meta', {})

    ignore_patterns = getattr(config, 'CODE_IGNORE_PATTERNS', [])
    project_root = os.getcwd()
    current_files = scan_py_files(project_root, ignore_patterns)

    violations = []
    # Проверяем новые и изменённые файлы
    for path, hash_value in current_files.items():
        if path not in baseline_data:
            violations.append(f"[НОВЫЙ] {path}")
        elif hash_value != baseline_data[path]:
            violations.append(f"[ИЗМЕНЕН] {path}")

    # Проверяем удалённые файлы
    for path in baseline_data:
        if path not in current_files:
            violations.append(f"[УДАЛЕН] {path}")

    logger.info("-" * 50)
    if violations:
        logger.warning("НАЙДЕНО НАРУШЕНИЙ ЦЕЛОСТНОСТИ КОДА: %d", len(violations))
        for v in violations:
            logger.warning(v)
    else:
        logger.info("Код не изменён. Целостность подтверждена.")
    logger.info("-" * 50)

    return violations