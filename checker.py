import ssl
import json
import random
import socket
import requests
import time
import subprocess
import os
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt" 
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"
XRAY_PATH = "./xray"

# База жесткого бана российских хостингов по первым цифрам IP
RUSSIAN_IP_PREFIXES = [
    "84.201.", "51.250.", "178.154.", "91.242.", "185.12.", "185.129.", "185.22.", "188.225.", 
    "193.124.", "194.58.", "194.67.", "195.19.", "195.208.", "195.242.", "212.193.", "213.180.", 
    "217.114.", "217.23.", "217.73.", "31.31.", "37.140.", "45.86.", "77.220.", "77.222.", 
    "79.137.", "80.78.", "80.93.", "81.177.", "82.146.", "82.202.", "83.219.", "85.113.", 
    "85.119.", "87.251.", "89.108.", "89.111.", "89.169.", "89.223.", "91.210.", "91.213.", 
    "92.53.", "93.180.", "94.198.", "94.250.", "95.163.", "95.213.", "185.178.", "185.204.", "194.54."
]

def is_russian_ip(ip):
    # Проверка принадлежности IP к хостингам РФ
    if not ip:
        return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"):
        return True
    return False

def check_geoip_api(ip):
    # Дополнительная проверка через внешнее GeoIP API
    try:
        response = requests.get(f"http://ip-api.com{ip}", timeout=2).json()
        if response.get("countryCode") == "RU":
            return False
        return True
    except Exception:
        return True

def is_server_alive_tls(link, timeout=3):
    # Способ 1: Быстрый TLS Handshake с замером RTT
    try:
        parsed = urlparse(link)
        ip = parsed.hostname
        port = parsed.port
        if not ip or not port:
            return False
        port = int(port)

        query_params = parse_qs(parsed.query)
        sni_list = query_params.get("sni", [None])
        sni = sni_list[0] if sni_list else None
        server_hostname = sni if sni else ip

        context = ssl._create_unverified_context()
        start_time = time.time()
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                rtt = (time.time() - start_time) * 1000
                if rtt > 1500:
                    return False
                return True
    except Exception:
        return False

def check_via_xray_core(link, xray_path, timeout=5):
    # Способ 2: Проверка трафиком через локальное ядро Xray
    actual_path = xray_path if os.path.exists(xray_path) else (xray_path + ".exe" if os.path.exists(xray_path + ".exe") else None)
    if not actual_path:
        return None

    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        local_port = random.randint(20000, 30000)
        config_path = f"temp_config_{local_port}.json"

        xray_config = {
            "log": {"loglevel": "none"},
            "inbounds": [{
                "port": local_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True}
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": parsed.hostname,
                        "port": int(parsed.port),
                        "users": [{
                            "id": parsed.username,
                            "encryption": query.get("encryption", ["none"])[0],
                            "flow": query.get("flow", [""])[0]
                        }]
                    }]
                },
                "streamSettings": {
                    "network": query.get("type", ["tcp"])[0],
                    "security": query.get("security", [""])[0],
                    "realitySettings": {
                        "show": False,
                        "fingerprint": query.get("fp", ["chrome"])[0],
                        "serverName": query.get("sni", [""])[0],
                        "publicKey": query.get("pbk", [""])[0],
                        "shortId": query.get("sid", [""])[0],
                        "spiderX": query.get("spx", [""])[0]
                    }
                }
            }]
        }

        with open(config_path, "w") as f:
            json.dump(xray_config, f)

        process = subprocess.Popen(
            [actual_path, "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        time.sleep(0.5)
        
        proxies = {
            "http": f"socks5://127.0.0.1:{local_port}",
            "https": f"socks5://127.0.0.1:{local_port}"
        }

        success = False
        try:
            res = requests.get("https://google.com", proxies=proxies, timeout=timeout)
            if res.status_code in [200, 204]:
                success = True
        except Exception:
            success = False
        finally:
            process.terminate()
            process.wait()
            if os.path.exists(config_path):
                os.remove(config_path)
                
        return success
    except Exception:
        return False

def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    try:
        res_keys = requests.get(KEYS_LIST_URL, timeout=10)
    except Exception as e:
        print(f"Ошибка сети: {e}")
        return

    if res_keys.status_code != 200:
        print("Ошибка скачивания базы.")
        return

    all_valid_candidates = []
    used_uuids = set()

    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                uuid = parsed.username

                if not ip or not port or not uuid:
                    continue

                if uuid in used_uuids:
                    continue

                if is_russian_ip(ip):
                    continue

                query_params = parse_qs(parsed.query)
                sni_list = query_params.get("sni", ["blank"])
                sni = sni_list[0].lower() if sni_list else "blank"
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue

                security = query_params.get("security", [""])[0].lower()
                pbk = query_params.get("pbk", [""])[0]
                
                if security == "reality" and not pbk:
                    continue

                used_uuids.add(uuid)
                all_valid_candidates.append(clean_line)
            except Exception:
                continue

    print(f"Валидных кандидатов найдено: {len(all_valid_candidates)}")
    if not all_valid_candidates:
        return

    random.shuffle(all_valid_candidates)
    working_links = []
    
    xray_available = os.path.exists(XRAY_PATH) or os.path.exists(XRAY_PATH + ".exe")

    for link in all_valid_candidates:
        if len(working_links) >= 5:
            break
            
        try:
            parsed = urlparse(link)
            ip = parsed.hostname
            port = parsed.port
            
            if not check_geoip_api(ip):
                continue

            is_alive = False
            if xray_available:
                res_xray = check_via_xray_core(link, XRAY_PATH)
                if res_xray is not None:
                    is_alive = res_xray
                else:
                    is_alive = is_server_alive_tls(link)
            else:
                is_alive = is_server_alive_tls(link)

            if is_alive:
                working_links.append(link)
                print(f"Добавлен рабочий IP: {ip}:{port} ({len(working_links)}/5)")
                
        except Exception:
            continue

    if not working_links:
        working_links = all_valid_candidates[:5]
    my_custom_text = "Привет! Подписка успешно обновлена. Актуальные сервера на сегодня."
    subscription_content = f"//profile-title: 67\n//profile-notice: {my_custom_text}\n" + "\n".join(working_links)
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
        
    print(f"Успех! Сохранено серверов: {len(working_links)}")

if __name__ == "__main__":
    main()
