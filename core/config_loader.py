import os
import yaml
from types import SimpleNamespace
import logging

logger = logging.getLogger(__name__)

CONFIG_FILE = 'fim.yaml'
ENV_PROFILE = 'FIM_PROFILE'
DEFAULT_PROFILE = 'default'


def load_config():
    profile = os.getenv(ENV_PROFILE, DEFAULT_PROFILE)
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(...)
    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
        full_config = yaml.safe_load(f)
    if profile not in full_config:
        raise KeyError(...)
    config_dict = full_config[profile]
    upper_dict = {k.upper(): v for k, v in config_dict.items()}
    return SimpleNamespace(**upper_dict)


config = load_config()