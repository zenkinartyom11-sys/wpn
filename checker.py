import random
import socket
import time
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

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
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def is_russian_ip(ip):
    if not ip: return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix): return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"): return True
    return False

def main():
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200: return

    all_servers = []
    used_uuids = set()
    
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                uuid = parsed.username
                
                if not ip or not port or not uuid or uuid in used_uuids or is_russian_ip(ip):
                    continue
                
                query_params = parse_qs(parsed.query)
                sni = str(query_params.get("sni", ["blank"])).lower()
                net_type = str(query_params.get("type", ["tcp"])).lower()
                security = str(query_params.get("security", ["none"])).lower()
                
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                if security == "reality":
                    all_servers.append({
                        "link": clean_line, "ip": ip, "port": port, "type": net_type, "uuid": uuid
                    })
                    used_uuids.add(uuid)
            except:
                continue

    if not all_servers: return

    random.shuffle(all_servers)
    final_servers = []

    # Ищем TCP
    for server in all_servers:
        if server["type"] == "tcp":
            if is_server_alive(server["ip"], server["port"]):
                final_servers.append(server["link"])
                all_servers.remove(server)
                break

    # Добираем остальные 4
    for server in all_servers:
        if len(final_servers) >= 5: break
        if is_server_alive(server["ip"], server["port"]):
            final_servers.append(server["link"])

    # Аварийный добор
    if len(final_servers) < 5:
        for server in all_servers:
            if len(final_servers) >= 5: break
            if server["link"] not in final_servers:
                final_servers.append(server["link"])

    # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: Добавляем в конец файла невидимый комментарий с точным временем.
    # Для Git файл ТЕПЕРЬ ВСЕГДА НОВЫЙ! Коммит сработает на 100%.
    subscription_content = "\n".join(final_servers[:5]) + f"\n# updated_at: {int(time.time())}"

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print("✅ Файл изменен.")

if __name__ == "__main__":
    main()
