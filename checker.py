import json
import random
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

def is_server_alive(ip, port, timeout=2):
    """Проверяет, отвечает ли порт сервера (TCP-пинг)"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    all_valid_candidates = []
    
    # Собираем абсолютно ВСЕ TCP Reality-серверы из базы
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            if "type=grpc" in line or "type=ws" in line:
                continue
            
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                
                if not ip or not port:
                    continue
                
                # Защита от подделок Яндекса
                if ip.startswith("84.201.") or ip.startswith("51.250.") or ip.startswith("178.154."):
                    continue
                
                query_params = parse_qs(parsed.query)
                sni = query_params.get("sni", [""]).lower()
                
                # Просто убираем очевидный ру-сегмент
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                all_valid_candidates.append(clean_line)
            except:
                continue

    if not all_valid_candidates:
        print("❌ Не удалось найти подходящие серверы в базе.")
        return

    # Перемешиваем, чтобы при каждом запуске список был уникальным
    random.shuffle(all_valid_candidates)
    
    working_links = []
    print(f"2. Ищем 5 живых серверов из {len(all_valid_candidates)} кандидатов...")
    
    for link in all_valid_candidates:
        if len(working_links) >= 5:
            break
            
        try:
            parsed = urlparse(link)
            ip = parsed.hostname
            port = parsed.port
            
            print(f"🔎 Тестируем IP: {ip}...")
            if is_server_alive(ip, port):
                print("   🚀 Отлично! Добавляем в подписку.")
                working_links.append(link)
        except:
            continue

    if not working_links:
        print("❌ Все выбранные серверы оказались недоступны по пингу.")
        return

    # Записываем 5 серверов через перенос строки
    subscription_content = "\n".join(working_links)

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ УСПЕХ! В файл {FILE_PATH} сохранено ровно {len(working_links)} случайных живых серверов.")

if __name__ == "__main__":
    main()
