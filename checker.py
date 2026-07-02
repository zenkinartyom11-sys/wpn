import json
import random
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
# ИСПРАВЛЕНО: Новый актуальный путь к базе Reality-серверов barry-far
KEYS_LIST_URL = "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt"

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
        print(f"❌ Ошибка скачивания базы ключей. Код ответа: {res_keys.status_code}")
        return

    tcp_candidates = []
    ws_candidates = []
    grpc_candidates = []
    backup_pool = [] # Сюда складываем вообще все рабочие заграничные Reality
    
    # Сортируем базу по типам сетей
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
                
                # Фильтруем русский SNI
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                # Нам нужны только Reality конфигурации
                if security == "reality":
                    backup_pool.append(clean_line)
                    if net_type == "tcp":
                        tcp_candidates.append(clean_line)
                    elif net_type == "ws":
                        ws_candidates.append(clean_line)
                    elif net_type == "grpc":
                        grpc_candidates.append(clean_line)
            except:
                continue

    print(f"ℹ️ Сортировка завершена. TCP: {len(tcp_candidates)} | WS: {len(ws_candidates)} | gRPC: {len(grpc_candidates)}")

    # Перемешиваем все списки для случайного выбора
    random.shuffle(tcp_candidates)
    random.shuffle(ws_candidates)
    random.shuffle(grpc_candidates)
    random.shuffle(backup_pool)
    
    final_servers = []

    # План А: Пытаемся набрать идеальную структуру (3 TCP + 1 WS + 1 gRPC)
    print("2. Отбираем серверы по категориям...")
    
    # Набираем 3 TCP
    for link in tcp_candidates:
        if len(final_servers) >= 3: break
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
        except: continue
    print(f"   Успешно добавлено TCP: {len(final_servers)}/3")

    # Набираем 1 WS
    ws_added = 0
    for link in ws_candidates:
        if ws_added >= 1: break
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                ws_added += 1
        except: continue
    print(f"   Успешно добавлено WS: {ws_added}/1")

    # Набираем 1 gRPC
    grpc_added = 0
    for link in grpc_candidates:
        if grpc_added >= 1: break
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                grpc_added += 1
        except: continue
    print(f"   Успешно добавлено gRPC: {grpc_added}/1")

    # ПЛАН Б (Динамический добор): Если идеальная схема не набралась, 
    # забиваем оставшиеся места ЛЮБЫМИ живыми серверами из общего пула, пока не станет ровно 5
    if len(final_servers) < 5:
        print(f"⚠️ Собрано всего {len(final_servers)} серверов. Запускаем динамический добор до 5 штук...")
        for link in backup_pool:
            if len(final_servers) >= 5: break
            if link in final_servers: continue # Пропускаем, если уже добавили
            
            try:
                parsed = urlparse(link)
                if is_server_alive(parsed.hostname, parsed.port):
                    final_servers.append(link)
                    print(f"   ➕ Добор: добавлен сервер {parsed.hostname}")
            except: continue

    # ПЛАН В (Аварийный режим "вслепую"): Если гитхаб лежит по пингу, берем 5 любых заграничных без проверки
    if len(final_servers) < 5:
        print("⚠️ Живые порты не ответили. Добираем сервера вслепую...")
        for link in backup_pool:
            if len(final_servers) >= 5: break
            if link not in final_servers:
                final_servers.append(link)

    # Записываем результат (ровно 5 ссылок)
    subscription_content = "\n".join(final_servers[:5])

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ ВСЁ ГОТОВО! В файл {FILE_PATH} успешно записано ровно {len(final_servers[:5])} серверов.")

if __name__ == "__main__":
    main()
