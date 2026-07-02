import json
import random
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

# БАЗА ЖЕСТКОГО БАНА РОССИЙСКИХ ХОСТИНГОВ ПО ПЕРВЫМ ЦИФРАМ IP
# Сюда входят все пулы Yandex, Selectel, MskHost, Timeweb, RuVDS, VDSina, Beget и др.
RUSSIAN_IP_PREFIXES = [
    "84.201.", "51.250.", "178.154.", "91.242.", "185.12.", "185.129.", "185.22.", 
    "188.225.", "193.124.", "194.58.", "194.67.", "195.19.", "195.208.", "195.242.",
    "212.193.", "213.180.", "217.114.", "217.23.", "217.73.", "31.31.", "37.140.",
    "45.86.", "77.220.", "77.222.", "79.137.", "80.78.", "80.93.", "81.177.", 
    "82.146.", "82.202.", "83.219.", "85.113.", "85.119.", "87.251.", "89.108.",
    "89.111.", "89.169.", "89.223.", "91.210.", "91.213.", "92.53.", "93.180.",
    "94.198.", "94.250.", "95.163.", "95.213.", "185.178.", "185.204.", "194.54."
]

def is_server_alive(ip, port, timeout=1):
    """Проверяет, отвечает ли порт сервера (TCP-пинг)"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def is_russian_ip(ip):
    """Проверяет, принадлежит ли IP-адрес российскому хостингу"""
    # 1. Проверяем по нашей базе префиксов
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
            
    # 2. Быстрая проверка по СНГ доменной структуре, если вместо IP указан домен
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"):
        return True
        
    return False

def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    all_valid_candidates = []
    
    # Сбор кандидатов
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                
                if not ip or not port:
                    continue
                
                # ШАГ 1: КРИТИЧЕСКИЙ БАН ВСЕХ РОССИЙСКИХ СЕРВЕРОВ
                if is_russian_ip(ip):
                    continue
                
                # ШАГ 2: Фильтр по маскировочному домену (SNI)
                query_params = parse_qs(parsed.query)
                sni = query_params.get("sni", ["blank"]).lower()[0]
                
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                all_valid_candidates.append(clean_line)
            except:
                continue

    print(f"ℹ️ Всего найдено чистых заграничных кандидатов: {len(all_valid_candidates)}")

    if not all_valid_candidates:
        print("❌ Чистые заграничные серверы не найдены. Аварийный режим...")
        all_valid_candidates = [line.strip() for line in res_keys.text.splitlines() if line.startswith("vless://")]

    # Перемешиваем заграничные сервера
    random.shuffle(all_valid_candidates)
    
    working_links = []
    print(f"2. Тестируем и отбираем 5 живых заграничных серверов...")
    
    for link in all_valid_candidates:
        if len(working_links) >= 5:
            break
            
        try:
            parsed = urlparse(link)
            ip = parsed.hostname
            port = parsed.port
            
            # Проверяем живой ли порт
            if is_server_alive(ip, port):
                working_links.append(link)
                print(f"   🚀 Нашли рабочий зарубежный IP: {ip}:{port}. Добавлено ({len(working_links)}/5)")
        except:
            continue

    if not working_links:
        print("⚠️ Живые порты не ответили. Записываем 5 случайных заграничных серверов без проверки...")
        working_links = all_valid_candidates[:5]

    # Записываем итоговый файл подписки
    subscription_content = "\n".join(working_links)

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ УСПЕХ! В файл {FILE_PATH} сохранено ровно {len(working_links)} чистых заграничных серверов.")

if __name__ == "__main__":
    main()
