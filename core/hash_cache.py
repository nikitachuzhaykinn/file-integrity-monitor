"""
Модуль для кэширования хешей файлов в памяти.
"""

_cache = {}


def get_cached_hash(file_path):
    """Возвращает хеш из кэша, если есть, иначе None."""
    return _cache.get(file_path)


def set_cached_hash(file_path, hash_value):
    """Сохраняет хеш в кэш."""
    _cache[file_path] = hash_value


def clear_cache():
    """Очищает кэш (может пригодиться при тестировании)."""
    _cache.clear()


def is_cached(file_path):
    """Проверяет, есть ли файл в кэше."""
    return file_path in _cache