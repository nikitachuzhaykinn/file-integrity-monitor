import hashlib
import logging
from core.config_loader import config
from core.hash_cache import get_cached_hash, set_cached_hash

logger = logging.getLogger(__name__)


def calculate_file_hash(file_path, algorithm=None):
    """
    Вычисляет хеш файла по указанному алгоритму.
    Если algorithm не задан, использует первый алгоритм из списка в конфиге.
    """
    if algorithm is None:
        algorithms = getattr(config, 'HASH_ALGORITHMS', ['sha256'])
        algorithm = algorithms[0] if algorithms else 'sha256'

    # Кэш: ключ = путь + алгоритм
    cache_key = f"{file_path}:{algorithm}"
    cached = get_cached_hash(cache_key)
    if cached is not None:
        logger.debug("Используем кэшированный хеш для %s (%s)", file_path, algorithm)
        return cached

    hasher = hashlib.new(algorithm)
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(config.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        hash_value = hasher.hexdigest()
        set_cached_hash(cache_key, hash_value)
        return hash_value
    except PermissionError:
        logger.warning("Нет прав на чтение файла: %s", file_path)
        return None
    except Exception as e:
        logger.error("Ошибка чтения %s: %s", file_path, e)
        return None


def calculate_multiple_hashes(file_path):
    """
    Вычисляет хеши для всех алгоритмов, указанных в конфиге.
    Возвращает словарь {algorithm: hash_value} или None при ошибке.
    """
    algorithms = getattr(config, 'HASH_ALGORITHMS', ['sha256'])
    result = {}
    for alg in algorithms:
        h = calculate_file_hash(file_path, alg)
        if h is None:
            logger.error("Не удалось вычислить хеш по алгоритму %s для %s", alg, file_path)
            return None
        result[alg] = h
    return result