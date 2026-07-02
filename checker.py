import json
import random
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

# База жесткого бана российских хостингов по первым цифрам IP
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
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix): return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"): return True
    return False

def main():
    print("1. Скачиваем свежую базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print(f"❌ Ошибка скачивания базы ключей. Код: {res_keys.status_code}")
        return

    tcp_candidates = []
    other_candidates = []
    
    # Сортируем базу: отделяем TCP от остальных транспортов (WS, gRPC)
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                
                if not ip or not port or is_russian_ip(ip):
                    continue
                
                query_params = parse_qs(parsed.query)
                sni = query_params.get("sni", ["blank"]).lower()
                net_type = query_params.get("type", ["tcp"]).lower()
                security = query_params.get("security", ["none"]).lower()
                
                # Фильтруем русский SNI
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                # Нам нужны только Reality конфигурации
                if security == "reality":
                    if net_type == "tcp":
                        tcp_candidates.append(clean_line)
                    else:
                        other_candidates.append(clean_line)
            except:
                continue

    print(f"ℹ️ Найдено кандидатов: Чистый TCP: {len(tcp_candidates)} | Другие (WS/gRPC): {len(other_candidates)}")

    # Перемешиваем списки для случайного выбора при каждом запуске
    random.shuffle(tcp_candidates)
    random.shuffle(other_candidates)
    
    final_servers = []

    # ШАГ 1: ОБЯЗАТЕЛЬНО ИЩЕМ ХОТЯ БЫ ОДИН ЖИВОЙ TCP СЕРВЕР
    print("2. Ищем обязательный живой TCP сервер...")
    for link in tcp_candidates:
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                print(f"   🏆 Обязательный TCP сервер найден и добавлен: {parsed.hostname}")
                tcp_candidates.remove(link) # Убираем из кандидатов, чтобы не дублировать
                break
        except: continue

    # ШАГ 2: НАБИРАЕМ ОСТАВШИЕСЯ МЕСТА (Добиваем до 5 штук любыми живыми серверами)
    print("3. Добираем остальные 4 сервера из всех доступных транспортов...")
    # Объединяем остатки TCP и другие транспорты в один общий котел для добора
    combined_pool = tcp_candidates + other_candidates
    random.shuffle(combined_pool)

    for link in combined_pool:
        if len(final_servers) >= 5: 
            break
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                print(f"   ✅ Добавлен сервер [{len(final_servers)}/5]: {parsed.hostname} ({parse_qs(parsed.query).get('type', ['tcp'])[0]})")
        except: continue

    # Аварийный режим "вслепую": если по пингу никто не ответил, добираем из остатков без проверки
    if len(final_servers) < 5:
        print("⚠️ Не все порты ответили по пингу. Добираем сервера вслепую до 5 штук...")
        for link in combined_pool:
            if len(final_servers) >= 5: break
            if link not in final_servers:
                final_servers.append(link)

    # Записываем результат (ровно 5 ссылок через перенос строки)
    subscription_content = "\n".join(final_servers[:5])

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ УСПЕХ! В файл {FILE_PATH} успешно записано ровно {len(final_servers[:5])} серверов (Минимум 1 TCP на первом месте).")

if __name__ == "__main__":
    main()
