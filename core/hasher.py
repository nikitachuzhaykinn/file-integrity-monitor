import hashlib
import logging
from core.config_loader import config

logger = logging.getLogger(__name__)


def calculate_file_hash(file_path):
    hasher = hashlib.new(config.HASH_ALGORITHM)

    try:
        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(config.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)

        return hasher.hexdigest()

    except PermissionError:
        logger.warning("Нет прав на чтение файла: %s", file_path)
        return None
    except Exception as error:
        logger.error("Ошибка чтения %s: %s", file_path, error)
        return None