import ssl
import json
import random
import socket
import requests
import time
import subprocess
import os
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

FILE_PATH = "subscription.txt" 
XRAY_PATH = "./xray"

# Сюда вставь свои 7 источников
URL_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt"
]

RUSSIAN_IP_PREFIXES = [
    "84.201.", "51.250.", "178.154.", "91.242.", "185.12.", "185.129.", "185.22.", "188.225.", 
    "193.124.", "194.58.", "194.67.", "195.19.", "195.208.", "195.242.", "212.193.", "213.180.", 
    "217.114.", "217.23.", "217.73.", "31.31.", "37.140.", "45.86.", "77.220.", "77.222.", 
    "79.137.", "80.78.", "80.93.", "81.177.", "82.146.", "82.202.", "83.219.", "85.113.", 
    "85.119.", "87.251.", "89.108.", "89.111.", "89.169.", "89.223.", "91.210.", "91.213.", 
    "92.53.", "93.180.", "94.198.", "94.250.", "95.163.", "95.213.", "185.178.", "185.204.", "194.54."
]

def is_russian_ip(ip):
    if not ip:
        return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"):
        return True
    return False

def check_geoip_api(ip):
    try:
        response = requests.get(f"http://ip-api.com{ip}", timeout=3).json()
        if response.get("countryCode") == "RU":
            return False
        return True
    except Exception:
        return True

def get_server_rtt(link, timeout=3):
    try:
        parsed = urlparse(link)
        ip = parsed.hostname
        port = parsed.port
        if not ip or not port:
            return None
        port = int(port)

        query_params = parse_qs(parsed.query)
        sni_list = query_params.get("sni", [None])
        sni = sni_list if isinstance(sni_list, list) and sni_list else None
        server_hostname = sni if sni else ip

        context = ssl._create_unverified_context()
        start_time = time.time()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                return (time.time() - start_time) * 1000
    except Exception:
        return None

def check_via_xray_core(link, xray_path, timeout=5):
    actual_path = xray_path if os.path.exists(xray_path) else (xray_path + ".exe" if os.path.exists(xray_path + ".exe") else None)
    if not actual_path:
        return None

    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        local_port = random.randint(20000, 30000)
        config_path = f"temp_config_{local_port}.json"
        security_type = query.get("security", [""]).lower()

        outbound_settings = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": parsed.hostname,
                    "port": int(parsed.port),
                    "users": [{
                        "id": parsed.username,
                        "encryption": query.get("encryption", ["none"]),
                        "flow": query.get("flow", [""])
                    }]
                }]
            },
            "streamSettings": {
                "network": query.get("type", ["tcp"]),
                "security": security_type
            }
        }

        if security_type == "reality":
            outbound_settings["streamSettings"]["realitySettings"] = {
                "show": False,
                "fingerprint": query.get("fp", ["chrome"]),
                "serverName": query.get("sni", [""]),
                "publicKey": query.get("pbk", [""]),
                "shortId": query.get("sid", [""]),
                "spiderX": query.get("spx", [""])
            }
        elif security_type == "tls":
            outbound_settings["streamSettings"]["tlsSettings"] = {
                "serverName": query.get("sni", [""]),
                "fingerprint": query.get("fp", ["chrome"])
            }

        xray_config = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": local_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [outbound_settings]
        }

        with open(config_path, "w") as f:
            json.dump(xray_config, f)

        process = subprocess.Popen(
            [actual_path, "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        time.sleep(0.6)
        proxies = {"http": f"socks5://127.0.0.1:{local_port}", "https": f"socks5://127.0.0.1:{local_port}"}
        success = False
        try:
            res = requests.get("https://google.com", proxies=proxies, timeout=timeout)
            if res.status_code in [200, 204]:
                success = True
        except Exception:
            success = False
        finally:
            try:
                process.kill()
                process.wait()
            except Exception:
                pass
            if os.path.exists(config_path):
                os.remove(config_path)
        return success
    except Exception:
        return False

def test_link_and_get_ping(link, xray_available):
    try:
        parsed = urlparse(link)
        ip = parsed.hostname
        if not check_geoip_api(ip):
            return None
        
        ping = get_server_rtt(link)
        if ping is None or ping > 1500:
            return None

        if xray_available:
            if not check_via_xray_core(link, XRAY_PATH):
                return None
        return ping
    except Exception:
        return None

def parse_list(text, used_uuids=None):
    if used_uuids is None:
        used_uuids = set()
    candidates = []
    for line in text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                uuid = parsed.username

                if not ip or not uuid or uuid in used_uuids or is_russian_ip(ip):
                    continue

                query_params = parse_qs(parsed.query)
                security = query_params.get("security", [""]).lower()
                pbk = query_params.get("pbk", [""])
                sni_list = query_params.get("sni", ["blank"])
                sni = sni_list.lower() if sni_list else "blank"
                
                if security == "reality" and not pbk:
                    continue
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue

                used_uuids.add(uuid)
                candidates.append(clean_line)
            except Exception:
                continue
    return candidates

def thread_worker(link, xray_available):
    ping = test_link_and_get_ping(link, xray_available)
    return link, ping

def main():
    print(" Скачиваем базы серверов из источников...")
    all_candidates = []
    used_uuids = set()

    for url in URL_SOURCES:
        try:
            res = requests.get(url, timeout=7)
            if res.status_code == 200:
                parsed_servers = parse_list(res.text, used_uuids=used_uuids)
                all_candidates.extend(parsed_servers)
                print(f"[+] Скачано из {urlparse(url).hostname or 'источника'}: {len(parsed_servers)} шт.")
        except Exception as e:
            print(f"[-] Ошибка скачивания источника {url}: {e}")
            continue

    if not all_candidates:
        print("Ошибка: Все списки пусты или лежат.")
        return

    random.shuffle(all_candidates)
    print(f"\nВсего уникальных серверов для теста: {len(all_candidates)}")
    
    xray_available = os.path.exists(XRAY_PATH) or os.path.exists(XRAY_PATH + ".exe")
    valid_servers = []
    MAX_WORKERS = 40  

    print("\n Скрипт замеряет скорость всех серверов. Поиск 5 самых быстрых...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, link, xray_available): link for link in all_candidates}
        for future in as_completed(futures):
            link, ping = future.result()
            if ping is not None:
                valid_servers.append({"link": link, "ping": ping})
                print(f" Найдена рабочая прокси! Пинг: {int(ping)}ms")
                
                if len(valid_servers) >= 20:
                    for f in futures: f.cancel()
                    break

    if not valid_servers:
        print("\n[!] Живые серверы не обнаружены. Записываем аварийный набор.")
        working_links = all_candidates[:5]
    else:
        valid_servers.sort(key=lambda x: x["ping"])
        working_links = [srv["link"] for srv in valid_servers[:5]]

    subscription_content = "\n".join(working_links)

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
        
    print(f"\n[+] Скрипт отсортировал сервера по скорости и сохранил ТОП-5 лучших в {FILE_PATH}!")

if __name__ == "__main__":
    main()
