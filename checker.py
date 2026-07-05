import random
import socket
import requests
import time
import os
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# Полный путь к файлу в текущей папке скрипта
FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "subscription.txt")
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

RUSSIAN_IP_PREFIXES = [
    "84.201.", "51.250.", "178.154.", "91.242.", "185.12.", "185.129.", "185.22.", "188.225.", 
    "193.124.", "194.58.", "194.67.", "195.19.", "195.208.", "195.242.", "212.193.", "213.180.", 
    "217.114.", "217.23.", "217.73.", "31.31.", "37.140.", "45.86.", "77.220.", "77.222.", 
    "79.137.", "80.78.", "80.93.", "81.177.", "82.146.", "83.219.", "85.113.", 
    "85.119.", "87.251.", "89.108.", "89.111.", "89.169.", "89.223.", "91.210.", "91.213.", 
    "92.53.", "93.180.", "94.198.", "94.250.", "95.163.", "95.213.", "185.178.", "185.204.", "194.54."
]

def is_russian_ip(ip):
    if not ip:
        return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    return ip.endswith((".ru", ".su", ".by"))

def get_server_ping(link):
    """Измеряет чистую скорость TCP-подключения к серверу (Пинг)"""
    try:
        parsed = urlparse(link)
        ip = parsed.hostname
        port = parsed.port
        if not ip or not port:
            return None
            
        start_time = time.time()
        # Проверяем доступность порта напрямую
        with socket.create_connection((ip, int(port)), timeout=1.5) as sock:
            rtt = (time.time() - start_time) * 1000
            return rtt
    except Exception:
        return None

def main():
    print("1. Скачиваем базу серверов...")
    try:
        res_keys = requests.get(KEYS_LIST_URL, timeout=10)
    except Exception as e:
        print(f"Ошибка сети при скачивании базы: {e}")
        return

    if res_keys.status_code != 200:
        print(f"Сервер базы вернул ошибку {res_keys.status_code}")
        return

    all_valid_candidates = []
    used_uuids = set()

    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                if not parsed.hostname or not parsed.port or not parsed.username:
                    continue
                if parsed.username in used_uuids or is_russian_ip(parsed.hostname):
                    continue

                query_params = parse_qs(parsed.query)
                sni = query_params.get("sni", ["blank"])[0].lower()
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue

                used_uuids.add(parsed.username)
                all_valid_candidates.append(clean_line)
            except Exception:
                continue

    print(f"Найдено {len(all_valid_candidates)} серверов для проверки...")
    if not all_valid_candidates:
        return

    # Шаг 1: Быстрый многопоточный пинг всех найденных серверов
    print("2. Измеряем скорость отклика серверов в 30 потоков...")
    alive_servers = []
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_link = {executor.submit(get_server_ping, link): link for link in all_valid_candidates}
        for future in as_completed(future_to_link):
            link = future_to_link[future]
            rtt = future.result()
            if rtt is not None:
                alive_servers.append({"link": link, "rtt": rtt})

    # Сортируем: на самом верху будут серверы с минимальным пингом (самые быстрые для Telegram)
    alive_servers.sort(key=lambda x: x["rtt"])
    print(f"Успешно ответили {len(alive_servers)} серверов.")

    # Если кто-то ответил, берем топ-5 лучших по пингу, иначе берем 5 случайных
    if alive_servers:
        print("\nТоп-5 самых быстрых серверов:")
        for item in alive_servers[:5]:
            parsed = urlparse(item["link"])
            print(f"-> IP: {parsed.hostname} | Пинг: {item['rtt']:.1f} мс")
        result_links = [item["link"] for item in alive_servers[:5]]
    else:
        print("Внимание: Ни один сервер не ответил на пинг. Берем резервные 5.")
        random.shuffle(all_valid_candidates)
        result_links = all_valid_candidates[:5]

    # Шаг 2: Принудительная очистка и запись в файл
    try:
        subscription_content = "\n".join(result_links)
        with open(FILE_PATH, "w", encoding="utf-8") as f:
            f.write(subscription_content)
        
        print("\n=========================================")
        print(f"УСПЕХ! Данные обновлены.")
        print(f"Файл сохранен по пути: {FILE_PATH}")
        print("=========================================")
    except Exception as e:
        print(f"Ошибка при сохранении файла: {e}")

if __name__ == "__main__":
    main()
