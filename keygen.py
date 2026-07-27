import os
from core.signature import (
    generate_key_pair,
    save_private_key,
    save_public_key,
    save_private_key_to_storage,
    save_public_key_to_storage,
    prompt_for_password_confirmation,
    prompt_for_storage_choice,
    check_storage_status
)
import config


def save_keys_to_files(private_key, public_key, password):
    print("\n[*] Сохранение ключей в файлы...")
    save_private_key(private_key, config.PRIVATE_KEY_FILE, password)
    save_public_key(public_key, config.PUBLIC_KEY_FILE)


def save_keys_to_storage(private_key, public_key, password):
    print(f"\n[*] Сохранение ключей в системное хранилище...")
    print(f"[*] Бэкенд: {check_storage_status()['backend']}")

    if save_private_key_to_storage(private_key, password, config.KEYRING_USERNAME):
        print("[✓] Приватный ключ сохранён в хранилище")
    else:
        print("[!] Не удалось сохранить приватный ключ в хранилище")

    if save_public_key_to_storage(public_key, config.KEYRING_USERNAME):
        print("[✓] Публичный ключ сохранён в хранилище")
    else:
        print("[!] Не удалось сохранить публичный ключ в хранилище")


def main():
    print("=" * 60)
    print("Генерация криптографических ключей для FIM")
    print("=" * 60)

    storage_status = check_storage_status()
    print(f"\n[*] Статус системного хранилища: {'Доступно' if storage_status['available'] else 'Недоступно'}")
    if storage_status['available']:
        print(f"[*] Бэкенд: {storage_status['backend']}")

    keys_exist = False
    if storage_status['available'] and storage_status['private_key_exists']:
        print(f"\n[!] Ключи уже существуют в системном хранилище")
        keys_exist = True
    elif os.path.exists(config.PRIVATE_KEY_FILE):
        print(f"\n[!] Ключи уже существуют: {config.PRIVATE_KEY_FILE}")
        keys_exist = True

    if keys_exist:
        response = input("Перезаписать существующие ключи? (y/N): ").strip().lower()
        if response != 'y':
            print("[*] Отменено.")
            return

    private_key, public_key = generate_key_pair()

    use_storage = prompt_for_storage_choice()
    config.USE_KEYRING = use_storage

    print("\n[!] Важно: Приватный ключ будет защищён паролем.")
    print("[!] Без этого пароля подпись baseline будет невозможна.")
    print("[!] Храните пароль в надёжном месте!\n")

    password = prompt_for_password_confirmation()
    if password:
        print("[+] Приватный ключ будет зашифрован")
    else:
        print("[!] Предупреждение: Ключ сохранён без пароля (менее безопасно)")

    if use_storage and storage_status['available']:
        save_keys_to_storage(private_key, public_key, password)
    else:
        save_keys_to_files(private_key, public_key, password)

    print("\n" + "=" * 60)
    print("[+] Ключи успешно сгенерированы!")
    print("=" * 60)

    if use_storage and storage_status['available']:
        print(f"Метод хранения: Системное хранилище ({storage_status['backend']})")
        print(f"Пользователь: {config.KEYRING_USERNAME}")
    else:
        print(f"Метод хранения: Файлы")
        print(f"Приватный ключ: {config.PRIVATE_KEY_FILE}")
        print(f"Публичный ключ:  {config.PUBLIC_KEY_FILE}")

    if password:
        print("[✓] Приватный ключ защищён паролем")
    else:
        print("[!] Приватный ключ НЕ ЗАЩИЩЁН паролем")

    print("\n[!] ВАЖНО: Храните приватный ключ и пароль в безопасности!")
    print("[!] Никогда не передавайте их третьим лицам!")
    print("=" * 60)


if __name__ == '__main__':
    main()