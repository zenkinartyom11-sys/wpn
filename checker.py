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

def check_hosting_provider(ip):
    """Проверяет страну сервера через API"""
    try:
        response = requests.get(f"https://ipapi.co{ip}/json/", timeout=2)
        if response.status_code == 200:
            data = response.json()
            return data.get("country_code", "UNKNOWN")
    except:
        pass
    return "UNKNOWN"

def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    # Собираем все подходящие VLESS-ссылки в один список
    all_valid_candidates = []
    
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
                
                # Жёсткий бан русских подсетей
                if ip.startswith("84.201.") or ip.startswith("51.250.") or ip.startswith("178.154."):
                    continue
                
                query_params = parse_qs(parsed.query)
                sni = query_params.get("sni", [""]).lower()
                
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                all_valid_candidates.append((clean_line, ip, port))
            except:
                continue

    if not all_valid_candidates:
        print("❌ Не удалось найти подходящие серверы в базе.")
        return

    # Перемешиваем список, чтобы серверы были случайными при каждом запуске
    random.shuffle(all_valid_candidates)
    
    working_links = []
    print(f"2. Ищем 5 живых серверов из {len(all_valid_candidates)} кандидатов...")
    
    for link, ip, port in all_valid_candidates:
        # ИСПРАВЛЕНИЕ: Останавливаемся ровно на 5 серверах
        if len(working_links) >= 5:
            break
            
        print(f"🔎 Тестируем IP: {ip}...")
        
        if not is_server_alive(ip, port):
            continue
        
        country = check_hosting_provider(ip)
        if country == "RU":
            continue
            
        print(f"   🚩 Добавлен рабочий сервер! Страна: {country}")
        working_links.append(link)

    if not working_links:
        print("❌ Не удалось найти ни одного живого заграничного сервера.")
        return

    # Собираем 5 ссылок через перенос строки
    subscription_content = "\n".join(working_links)

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ Успешно! В файл {FILE_PATH} сохранено {len(working_links)} рабочих серверов.")

if __name__ == "__main__":
    main()
