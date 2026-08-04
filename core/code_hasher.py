import os
import json
import hmac
import fnmatch
import logging
from datetime import datetime
from core.hasher import calculate_multiple_hashes
from core.baseline import get_private_key, get_public_key
from core.config_loader import config
from core.signature import sign_file, verify_file_signature

logger = logging.getLogger(__name__)


def is_ignored_code(path, patterns):
    base = os.path.basename(path)
    for pattern in patterns:
        if fnmatch.fnmatch(base, pattern):
            return True
    return False


def scan_py_files(directory, ignore_patterns):
    py_files = {}
    logger.info("Сканирование .py файлов в %s", directory)

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not is_ignored_code(os.path.join(root, d), ignore_patterns)]

        for file_name in files:
            if not file_name.endswith('.py'):
                continue
            full_path = os.path.join(root, file_name)
            if is_ignored_code(full_path, ignore_patterns):
                logger.debug("Игнорируем код: %s", full_path)
                continue

            hashes = calculate_multiple_hashes(full_path)
            if hashes:
                py_files[full_path] = hashes

    logger.info("Найдено .py файлов: %d", len(py_files))
    return py_files


def save_code_baseline(password=None):
    ignore_patterns = getattr(config, 'CODE_IGNORE_PATTERNS', [])
    project_root = os.getcwd()
    baseline_data = scan_py_files(project_root, ignore_patterns)

    baseline_data['_meta'] = {
        'timestamp': datetime.now().isoformat(),
        'type': 'code_baseline'
    }

    with open(config.CODE_BASELINE_FILE, 'w', encoding='utf-8') as f:
        json.dump(baseline_data, f, indent=4, ensure_ascii=False)

    logger.info("Кодовая базовая линия сохранена в %s", config.CODE_BASELINE_FILE)

    private_key = get_private_key(password)
    if private_key:
        try:
            sign_file(config.CODE_BASELINE_FILE, private_key, config.CODE_BASELINE_SIGNATURE_FILE)
        except Exception as e:
            logger.error("Ошибка подписи кодовой базовой линии: %s", e)
    else:
        logger.warning("Приватный ключ не найден. Кодовая базовая линия не подписана.")


def load_code_baseline():
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
    baseline_data = load_code_baseline()
    if baseline_data is None:
        logger.error("Кодовая базовая линия не найдена. Запустите 'code-init'.")
        return

    baseline_meta = baseline_data.pop('_meta', {})

    ignore_patterns = getattr(config, 'CODE_IGNORE_PATTERNS', [])
    project_root = os.getcwd()
    current_files = scan_py_files(project_root, ignore_patterns)

    violations = []
    for path, current_hashes in current_files.items():
        if path not in baseline_data:
            violations.append(f"[НОВЫЙ] {path}")
        else:
            stored_hashes = baseline_data[path]
            for alg, current_hash in current_hashes.items():
                if alg not in stored_hashes:
                    violations.append(f"[ИЗМЕНЕН] {path} (новый алгоритм {alg})")
                    break
                if not hmac.compare_digest(
                    current_hash.encode('utf-8'),
                    stored_hashes[alg].encode('utf-8')
                ):
                    violations.append(f"[ИЗМЕНЕН] {path} (не совпадает {alg})")
                    break

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