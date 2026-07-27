import os
from core.signature import (
    generate_key_pair,
    save_private_key,
    save_public_key,
    prompt_for_password_confirmation
)
import config


def main():
    """Генерирует пару ключей и сохраняет их."""
    print("=" * 60)
    print("Генерация криптографических ключей для FIM")
    print("=" * 60)

    # Проверяем, существуют ли уже ключи
    if os.path.exists(config.PRIVATE_KEY_FILE):
        print(f"[!] Warning: Приватный ключ уже существует: {config.PRIVATE_KEY_FILE}")
        response = input("Перезаписать? (y/N): ").strip().lower()
        if response != 'y':
            print("[*] Отменено.")
            return

    # Генерируем ключи
    private_key, public_key = generate_key_pair()

    # Запрашиваем пароль для защиты приватного ключа
    print("\n[!] Важно: Приватный ключ будет защищён паролем.")
    print("[!] Без этого пароля подпись baseline будет невозможна.")
    print("[!] Храните пароль в надёжном месте!\n")

    password = prompt_for_password_confirmation()
    if password:
        print("[+] Приватный ключ будет зашифрован")
    else:
        print("[!] Предупреждение: Ключ сохранён без пароля (менее безопасно)")

    # Сохраняем ключи
    save_private_key(private_key, config.PRIVATE_KEY_FILE, password)
    save_public_key(public_key, config.PUBLIC_KEY_FILE)

    print("\n" + "=" * 60)
    print("[+] Ключи успешно сгенерированы!")
    print("=" * 60)
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