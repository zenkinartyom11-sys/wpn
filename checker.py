import json
import random
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
# Актуальная заграничная база без Яндекса
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

def is_server_alive(ip, port, timeout=2):
    """Проверяет, отвечает ли порт сервера (TCP-пинг)"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def is_russian_ip(ip):
    """Проверяет, принадлежит ли IP-адрес российскому хостингу"""
    if not ip:
        return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"):
        return True
    return False

def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    tcp_candidates = []
    other_candidates = []
    used_uuids = set()  # Защита от дубликатов на этапе первичного сбора
    
    # Сбор и сортировка кандидатов
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                uuid = parsed.username  # Извлекаем UUID
                
                if not ip or not port or not uuid:
                    continue
                
                # 1. Защита от дубликатов UUID
                if uuid in used_uuids:
                    continue
                
                # 2. КРИТИЧЕСКИЙ БАН ВСЕХ РОССИЙСКИХ СЕРВЕРОВ
                if is_russian_ip(ip):
                    continue
                
                # 3. Фильтр по маскировочному домену (SNI)
                query_params = parse_qs(parsed.query)
                sni_list = query_params.get("sni", ["blank"])
                sni = sni_list.lower() if sni_list else "blank"
                net_type = query_params.get("type", ["tcp"]).lower()
                security = query_params.get("security", ["none"]).lower()
                
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                # Отбираем только заграничный Reality
                if security == "reality":
                    if net_type == "tcp":
                        tcp_candidates.append((clean_line, uuid))
                    else:
                        other_candidates.append((clean_line, uuid))
                    used_uuids.add(uuid)
            except:
                continue

    print(f"ℹ️ Собрано уникальных кандидатов: Чистый TCP: {len(tcp_candidates)} | Другие транспорты: {len(other_candidates)}")

    if not tcp_candidates and not other_candidates:
        print("❌ Заграничные уникальные серверы не найдены.")
        return

    # Перемешиваем оба списка для случайного выбора
    random.shuffle(tcp_candidates)
    random.shuffle(other_candidates)
    
    final_servers = []
    final_uuids = set()

    # ШАГ 1: ОБЯЗАТЕЛЬНО ИЩЕМ ХОТЯ БЫ ОДИН ЖИВОЙ TCP СЕРВЕР НА ПЕРВОЕ МЕСТО
    print("2. Ищем обязательный живой TCP сервер на 1-е место...")
    for link, uuid in tcp_candidates:
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                final_uuids.add(uuid)
                print(f"   🏆 Обязательный живой TCP найден и закреплен: {parsed.hostname}")
                break
        except:
            continue

    # ШАГ 2: НАБИРАЕМ ОСТАВШИЕСЯ МЕСТА (Добиваем до 5 штук любыми живыми серверами)
    print("3. Добираем остальные 4 сервера из общего котла...")
    combined_pool = tcp_candidates + other_candidates
    random.shuffle(combined_pool)

    for link, uuid in combined_pool:
        if len(final_servers) >= 5:
            break
            
        # БЕЗОПАСНАЯ ПРОВЕРКА: Пропускаем, если этот UUID уже задействован (включая первый закрепленный TCP)
        if uuid in final_uuids:
            continue
            
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                final_servers.append(link)
                final_uuids.add(uuid)
                print(f"   ✅ Добавлен сервер [{len(final_servers)}/5]: {parsed.hostname}")
        except:
            continue

    # Аварийный режим "вслепую" (если Гитхаб забанен по пингу, добираем без проверки)
    if len(final_servers) < 5:
        print("⚠️ Часть портов не ответили по пингу. Добираем уникальные сервера вслепую...")
        for link, uuid in combined_pool:
            if len(final_servers) >= 5:
                break
            if uuid not in final_uuids:
                final_servers.append(link)
                final_uuids.add(uuid)

    # Записываем итоговый файл подписки (ровно 5 строк)
    subscription_content = "\n".join(final_servers[:5])

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ УСПЕХ! В файл {FILE_PATH} сохранено ровно {len(final_servers[:5])} уникальных серверов.")

if __name__ == "__main__":
    main()
