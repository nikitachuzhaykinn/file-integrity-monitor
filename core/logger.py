import logging
import logging.handlers
import os
from config import LOG_FILE, LOG_MAX_BYTES, LOG_BACKUP_COUNT, LOG_LEVEL

def setup_logging():
    """Настраивает корневой логгер с ротацией по размеру."""
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o755, exist_ok=True)

    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)

    logger = logging.getLogger()
    logger.setLevel(level)

    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    logger.info("Логирование настроено (файл: %s, уровень: %s)", LOG_FILE, LOG_LEVEL)
    return logger

logger = logging.getLogger(__name__)