import os
from core.signature import generate_key_pair, save_private_key, save_public_key
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

    # Сохраняем ключи
    save_private_key(private_key, config.PRIVATE_KEY_FILE)
    save_public_key(public_key, config.PUBLIC_KEY_FILE)

    print("\n" + "=" * 60)
    print("[+] Ключи успешно сгенерированы!")
    print("=" * 60)
    print(f"Приватный ключ: {config.PRIVATE_KEY_FILE}")
    print(f"Публичный ключ:  {config.PUBLIC_KEY_FILE}")
    print("\n[!] ВАЖНО: Храните приватный ключ в безопасности!")
    print("[!] Никогда не передавайте его третьим лицам!")
    print("=" * 60)


if __name__ == '__main__':
    main()