import logging
import logging.handlers
import os
import json
from datetime import datetime
from core.config_loader import config

# ---- JSON-форматтер ----
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "message": record.getMessage(),
            "filename": record.filename,
            "lineno": record.lineno,
        }
        # Добавляем исключение, если есть
        if record.exc_info:
            log_record["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_record, ensure_ascii=False)


def setup_logging():
    """Настраивает логирование с текстовым и JSON-форматами."""
    # --- Создаём директорию для логов ---
    log_dir = os.path.dirname(config.LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o755, exist_ok=True)

    # --- Уровень логирования ---
    level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)

    # --- Корневой логгер ---
    logger = logging.getLogger()
    logger.setLevel(level)

    # Удаляем старые обработчики (чтобы не дублировать)
    if logger.hasHandlers():
        logger.handlers.clear()

    # --- Общий текстовый форматтер ---
    text_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # --- 1. Текстовый лог в файл (с ротацией) ---
    text_file_handler = logging.handlers.RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT,
        encoding='utf-8'
    )
    text_file_handler.setLevel(level)
    text_file_handler.setFormatter(text_formatter)
    logger.addHandler(text_file_handler)

    # --- 2. Консольный вывод (текстовый) ---
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(text_formatter)
    logger.addHandler(console_handler)

    # --- 3. JSON-логи (если включены) ---
    if getattr(config, 'LOG_JSON_ENABLED', False):
        json_log_file = getattr(config, 'LOG_JSON_FILE', 'logs/fim.json')
        json_max_bytes = getattr(config, 'LOG_JSON_MAX_BYTES', 5 * 1024 * 1024)
        json_backup_count = getattr(config, 'LOG_JSON_BACKUP_COUNT', 3)

        json_dir = os.path.dirname(json_log_file)
        if json_dir and not os.path.exists(json_dir):
            os.makedirs(json_dir, mode=0o755, exist_ok=True)

        json_file_handler = logging.handlers.RotatingFileHandler(
            json_log_file,
            maxBytes=json_max_bytes,
            backupCount=json_backup_count,
            encoding='utf-8'
        )
        json_file_handler.setLevel(level)
        json_file_handler.setFormatter(JsonFormatter())
        logger.addHandler(json_file_handler)

        logger.info("JSON-логи включены, файл: %s", json_log_file)

    logger.info("Логирование настроено (уровень: %s)", config.LOG_LEVEL)
    return logger


logger = logging.getLogger(__name__)