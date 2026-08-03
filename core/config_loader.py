import os
import yaml
from types import SimpleNamespace
import logging

logger = logging.getLogger(__name__)

CONFIG_FILE = 'fim.yaml'
ENV_PROFILE = 'FIM_PROFILE'
DEFAULT_PROFILE = 'default'


def load_config():
    """Загружает конфигурацию из YAML-файла с учётом профиля."""
    profile = os.getenv(ENV_PROFILE, DEFAULT_PROFILE)

    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(
            f"Файл конфигурации {CONFIG_FILE} не найден. "
            f"Создайте его на основе fim.yaml.example"
        )

    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        full_config = yaml.safe_load(f)

    if profile not in full_config:
        raise KeyError(
            f"Профиль '{profile}' не найден в {CONFIG_FILE}. "
            f"Доступные профили: {', '.join(full_config.keys())}"
        )

    config_dict = full_config[profile]
    logger.info("Загружен профиль '%s' из %s", profile, CONFIG_FILE)

    # Преобразуем ключи в верхний регистр для совместимости со старым кодом
    upper_dict = {k.upper(): v for k, v in config_dict.items()}

    return SimpleNamespace(**upper_dict)


config = load_config()