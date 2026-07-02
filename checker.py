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

def is_server_alive(ip, port, timeout=1): # Выставили жесткий таймаут 1 сек для отбора лучших
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
    print("1. Скачиваем проверенную базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    # Три раздельные корзины под каждый тип транспорта
    tcp_candidates = []
    ws_candidates = []
    grpc_candidates = []
    
    # Сортируем всю базу по типам сетей
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
                sni = query_params.get("sni", ["blank"])[0].lower()
                net_type = query_params.get("type", ["tcp"])[0].lower()
                security = query_params.get("security", ["none"])[0].lower()
                
                # Фильтруем очевидный русский SNI
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                # Раскладываем по корзинам (нам нужны только Reality конфигурации)
                if security == "reality":
                    if net_type == "tcp":
                        tcp_candidates.append(clean_line)
                    elif net_type == "ws":
                        ws_candidates.append(clean_line)
                    elif net_type == "grpc":
                        grpc_candidates.append(clean_line)
            except:
                continue

    print(f"ℹ️ Найдено заграничных кандидатов: TCP: {len(tcp_candidates)} | WS: {len(ws_candidates)} | gRPC: {len(grpc_candidates)}")

    # Перемешиваем каждую корзину отдельно для случайного выбора
    random.shuffle(tcp_candidates)
    random.shuffle(ws_candidates)
    random.shuffle(grpc_candidates)
    
    final_servers = []

    # 1. ОТБИРАЕМ 3 РАБОЧИХ TCP СЕРВЕРА
    print("-> Тестируем TCP серверы...")
    for link in tcp_candidates:
        if len(final_servers) >= 3: break
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                print(f"   ✅ Добавлен TCP [{len(final_servers)}/3]: {parsed.hostname}")
        except: continue

    # 2. ОТБИРАЕМ 1 РАБОЧИЙ WS СЕРВЕР
    print("-> Тестируем WS серверы...")
    ws_count = 0
    for link in ws_candidates:
        if ws_count >= 1: break
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                ws_count += 1
                print(f"   ✅ Добавлен WS [1/1]: {parsed.hostname}")
        except: continue

    # 3. ОТБИРАЕМ 1 РАБОЧИЙ gRPC СЕРВЕР
    print("-> Тестируем gRPC серверы...")
    grpc_count = 0
    for link in grpc_candidates:
        if grpc_count >= 1: break
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                grpc_count += 1
                print(f"   ✅ Добавлен gRPC [1/1]: {parsed.hostname}")
        except: continue

    # Аварийный режим "вслепую": если по пингу кто-то не ответил, добираем из списков без проверки
    if len(final_servers) < 5:
        print("⚠️ Не все типы сетей ответили по пингу. Добираем вслепую для сохранения структуры...")
        while len(final_servers) < 3 and tcp_candidates:
            final_servers.append(tcp_candidates.pop(0))
        if ws_count == 0 and ws_candidates:
            final_servers.append(ws_candidates[0])
        if grpc_count == 0 and grpc_candidates:
            final_servers.append(grpc_candidates[0])

    # Записываем ровно 5 серверов в файл подписки
    # Срез [:5] гарантирует, что серверов на выходе будет строго 5
    subscription_content = "\n".join(final_servers[:5])

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ УСПЕХ! Сформирована комбинированная подписка в {FILE_PATH}.")

if __name__ == "__main__":
    main()
