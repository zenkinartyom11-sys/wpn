import json
import random
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  

# ТРИ РАЗНЫХ НЕЗАВИСИМЫХ ИСТОЧНИКА КОНФИГУРАЦИЙ VLESS REALITY
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
]

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

def download_and_parse_sources():
    """Последовательно скачивает данные из 3 ссылок и сортирует кандидатов"""
    tcp_candidates = []
    other_candidates = []
    
    print("1. Начинаем каскадное скачивание баз...")
    for idx, url in enumerate(SOURCES, 1):
        try:
            print(f"   📥 Скачиваем Источник №{idx}...")
            res = requests.get(url, timeout=5)
            if res.status_code != 200:
                print(f"   ⚠️ Ошибка скачивания источника №{idx} (Код: {res.status_code}). Переходим к следующему.")
                continue
                
            # Парсим строки из текущего источника
            for line in res.text.splitlines():
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
                        
                        # Фильтр русского цензурного SNI
                        if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                            continue
                        
                        # Собираем только Reality-конфигурации
                        if security == "reality":
                            if net_type == "tcp" and clean_line not in tcp_candidates:
                                tcp_candidates.append(clean_line)
                            elif net_type != "tcp" and clean_line not in other_candidates:
                                other_candidates.append(clean_line)
                    except:
                        continue
        except Exception as e:
            print(f"   ⚠️ Ошибка при обработке источника №{idx}: {e}")
            continue
            
    return tcp_candidates, other_candidates

def main():
    # Получаем объединенный список кандидатов изо всех 3 ссылок
    tcp_candidates, other_candidates = download_and_parse_sources()

    print(f"\nℹ️ Всего успешно собрано: Чистый TCP: {len(tcp_candidates)} | Другие (WS/gRPC): {len(other_candidates)}")

    if not tcp_candidates and not other_candidates:
        print("❌ Во всех 3 базах вообще не нашлось подходящих ссылок.")
        return

    # Перемешиваем массивы для случайного выбора
    random.shuffle(tcp_candidates)
    random.shuffle(other_candidates)
    
    final_servers = []

    # ШАГ 1: ОБЯЗАТЕЛЬНО ИЩЕМ ХОТЯ БЫ ОДИН ЖИВОЙ TCP СЕРВЕР
    print("\n2. Ищем обязательный живой заграничный TCP сервер...")
    for link in tcp_candidates:
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                print(f"   🏆 Обязательный TCP сервер закреплен на 1 месте: {parsed.hostname}")
                tcp_candidates.remove(link)
                break
        except: continue

    # ШАГ 2: НАБИРАЕМ ОСТАВШИЕСЯ МЕСТА (Добиваем до 5 штук любыми живыми серверами из общего котла)
    print("\n3. Набираем остальные 4 сервера из объединенного пула всех 3 источников...")
    combined_pool = tcp_candidates + other_candidates
    random.shuffle(combined_pool)

    for link in combined_pool:
        if len(final_servers) >= 5: 
            break
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                net_type_label = parse_qs(parsed.query).get('type', ['tcp'])[0]
                print(f"   ✅ Добавлен сервер [{len(final_servers)}/5]: {parsed.hostname} ({net_type_label})")
        except: continue

    # Аварийный режим "вслепую"
    if len(final_servers) < 5:
        print("\n⚠️ Не все порты ответили по пингу. Добираем сервера вслепую до 5 штук...")
        for link in combined_pool:
            if len(final_servers) >= 5: break
            if link not in final_servers:
                final_servers.append(link)

    # Записываем ровно 5 лучших ссылок
    subscription_content = "\n".join(final_servers[:5])

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"\n✅ КОМБИНИРОВАНИЕ ЗАВЕРШЕНО! В файл {FILE_PATH} успешно записано ровно {len(final_servers[:5])} серверов.")

if __name__ == "__main__":
    main()
