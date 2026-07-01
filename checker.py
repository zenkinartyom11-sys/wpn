import requests
from urllib.parse import urlparse, parse_qs

# Имя текстового файла, который мы создадим в репозитории для подписки телефона
FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

def main():
    print("1. Скачиваем свежие ключи от igareck...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    chosen_link = None
    # Бежим по списку и ищем первый идеальный TCP-сервер (без grpc и без ws)
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            # Пропускаем проблемные для ТСПУ форматы grpc и ws
            if "type=grpc" in line or "type=ws" in line:
                continue
            
            # Нашли чистый TCP Reality сервер
            chosen_link = line.strip()
            break

    if not chosen_link:
        print("❌ В списке не найдено подходящих TCP VLESS ссылок.")
        return

    print(f"-> Успешно выбран рабочий TCP сервер!")

    # 2. Сохраняем эту чистую ссылку в локальный файл
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(chosen_link)
    print(f"✅ Ссылка успешно записана в файл {FILE_PATH}.")

if __name__ == "__main__":
    main()
