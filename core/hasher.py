import hashlib
import config


def calculate_file_hash(file_path):
    """
    Вычисляет хеш-сумму файла.

    Аргументы:
        file_path (str): Путь к файлу.

    Возвращает:
        str: Хеш-сумма в hex или None при ошибке.
    """
    # Создаем объект хеш-функции (динамически из конфига)
    hasher = hashlib.new(config.HASH_ALGORITHM)

    try:
        with open(file_path, "rb") as file:
            while True:
                # Читаем файл частями
                chunk = file.read(config.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)

        return hasher.hexdigest()

    except PermissionError:
        return None
    except Exception as error:
        print(f"[!] Ошибка чтения {file_path}: {error}")
        return None