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
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"
XRAY_PATH = "./xray"

# Официальный файл с серверов Telegram для замера чистой скорости внутри мессенджера
SPEED_TEST_URL = "https://telegram.org"

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
    return ip.endswith((".ru", ".su", ".by"))

def check_geoip_api(ip):
    try:
        response = requests.get(f"http://ip-api.com{ip}", timeout=2).json()
        if response.get("countryCode") == "RU":
            return False
        return True
    except Exception:
        return True

def get_server_rtt(link, timeout=1.5):
    """Быстрый замер задержки (пинг) до сервера"""
    try:
        parsed = urlparse(link)
        ip, port = parsed.hostname, parsed.port
        if not ip or not port:
            return None
        
        query_params = parse_qs(parsed.query)
        sni = query_params.get("sni", [None])
        server_hostname = sni if sni else ip

        context = ssl._create_unverified_context()
        start_time = time.time()
        
        with socket.create_connection((ip, int(port)), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname):
                rtt = (time.time() - start_time) * 1000
                return rtt
    except Exception:
        return None

def test_telegram_speed(link, xray_path, timeout=6):
    """Тестирует реальную скорость скачивания контента с серверов Telegram"""
    actual_path = xray_path if os.path.exists(xray_path) else (xray_path + ".exe" if os.path.exists(xray_path + ".exe") else None)
    if not actual_path:
        return 0.0

    local_port = random.randint(20000, 30000)
    config_path = f"temp_config_{local_port}.json"
    
    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)

        xray_config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": local_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": parsed.hostname,
                            "port": int(parsed.port),
                            "users": [{"id": parsed.username, "encryption": query.get("encryption", ["none"]), "flow": query.get("flow", [""])}]
                        }]
                    },
                    "streamSettings": {
                        "network": query.get("type", ["tcp"]),
                        "security": query.get("security", [""]),
                        "realitySettings": {
                            "show": False, "fingerprint": query.get("fp", ["chrome"]),
                            "serverName": query.get("sni", [""]), "publicKey": query.get("pbk", [""]),
                            "shortId": query.get("sid", [""]), "spiderX": query.get("spx", [""])
                        }
                    }
                },
                {"protocol": "freedom", "tag": "direct"}
            ]
        }

        with open(config_path, "w") as f:
            json.dump(xray_config, f)

        process = subprocess.Popen([actual_path, "run", "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.4) # даем Xray подняться
        
        proxies = {"http": f"socks5://127.0.0.1:{local_port}", "https": f"socks5://127.0.0.1:{local_port}"}
        
        start_time = time.time()
        # Скачиваем файл потоком, замеряя скорость в процессе
        res = requests.get(SPEED_TEST_URL, proxies=proxies, timeout=timeout, stream=True)
        
        bytes_downloaded = 0
        for chunk in res.iter_content(chunk_size=32768):
            if chunk:
                bytes_downloaded += len(chunk)
                # Если скачали больше 3 МБ, прерываем, чтобы не тратить трафик
                if bytes_downloaded > 3 * 1024 * 1024:
                    break
                    
        duration = time.time() - start_time
        
        process.terminate()
        process.wait()
        if os.path.exists(config_path):
            os.remove(config_path)

        if duration > 0 and bytes_downloaded > 1024:
            mbits = (bytes_downloaded / (1024 * 1024)) / duration # Скорость в Мбайт/сек
            return mbits
    except Exception:
        if 'process' in locals():
            process.terminate()
        if os.path.exists(config_path):
            os.remove(config_path)
    return 0.0

def main():
    print("1. Скачиваем базу ключей...")
    try:
        res_keys = requests.get(KEYS_LIST_URL, timeout=10)
    except Exception as e:
        print(f"Ошибка сети: {e}")
        return

    if res_keys.status_code != 200:
        return

    all_valid_candidates = []
    used_uuids = set()

    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                if not parsed.hostname or not parsed.port or not parsed.username:
                    continue
                if parsed.username in used_uuids or is_russian_ip(parsed.hostname):
                    continue

                query_params = parse_qs(parsed.query)
                sni = query_params.get("sni", ["blank"]).lower()
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue

                used_uuids.add(parsed.username)
                all_valid_candidates.append(clean_line)
            except Exception:
                continue

    print(f"Кандидатов для быстрого теста: {len(all_valid_candidates)}")
    if not all_valid_candidates:
        return

    # Шаг 1: Быстрый замер задержки в 20 потоков
    print("2. Многопоточный замер пинга до серверов...")
    alive_servers = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_link = {executor.submit(get_server_rtt, link): link for link in all_valid_candidates}
        for future in as_completed(future_to_link):
            link = future_to_link[future]
            rtt = future.result()
            if rtt is not None:
                alive_servers.append({"link": link, "rtt": rtt})

    alive_servers.sort(key=lambda x: x["rtt"])
    print(f"Доступных серверов: {len(alive_servers)}")
    
    if not alive_servers:
        return

    # Шаг 2: Тест скорости скачивания медиафайлов Telegram (Top-15 серверов с минимальным пингом)
    xray_available = os.path.exists(XRAY_PATH) or os.path.exists(XRAY_PATH + ".exe")
    top_candidates = alive_servers[:15]
    final_working_links = []

    if xray_available and top_candidates:
        print("3. Тестирование чистой скорости загрузки файлов Telegram...")
        for item in top_candidates:
            link = item["link"]
            parsed = urlparse(link)
            
            if not check_geoip_api(parsed.hostname):
                continue
                
            speed = test_telegram_speed(link, XRAY_PATH)
            if speed > 0.1: 
                item["speed"] = speed
                final_working_links.append(item)
                print(f"-> IP: {parsed.hostname} | Пинг: {item['rtt']:.1f}мс | Скорость в ТГ: {speed:.2f} МБ/с")
        
        # Главная сортировка: от максимальной скорости в Telegram к минимальной
        final_working_links.sort(key=lambda x: x["speed"], reverse=True)
    else:
        final_working_links = top_candidates[:5]

    result_links = [item["link"] for item in final_working_links[:5]]

    if not result_links:
        result_links = [item["link"] for item in alive_servers[:5]]

    # Запись лучших серверов в файл
    subscription_content = "\n".join(result_links)
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
        
    print(f"\nУспех! В файл записаны ТОП-{len(result_links)} серверов с максимальной скоростью для Telegram.")

if __name__ == "__main__":
    main()
