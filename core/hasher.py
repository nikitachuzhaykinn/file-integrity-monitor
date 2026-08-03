import hashlib
import logging
from core.config_loader import config
from core.hash_cache import get_cached_hash, set_cached_hash

logger = logging.getLogger(__name__)


def calculate_file_hash(file_path):
    """
    Вычисляет хеш-сумму файла с использованием кэша.
    Если хеш уже вычислен, возвращает его из кэша.
    """
    # Проверяем кэш
    cached = get_cached_hash(file_path)
    if cached is not None:
        logger.debug("Используем кэшированный хеш для %s", file_path)
        return cached

    # Вычисляем хеш
    hasher = hashlib.new(config.HASH_ALGORITHM)

    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(config.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)

        hash_value = hasher.hexdigest()
        set_cached_hash(file_path, hash_value)
        return hash_value

    except PermissionError:
        logger.warning("Нет прав на чтение файла: %s", file_path)
        return None
    except Exception as error:
        logger.error("Ошибка чтения %s: %s", file_path, error)
        return None