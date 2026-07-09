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
URL_WHITE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"
URL_BLACK = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"
XRAY_PATH = "./xray"

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

def is_server_alive_tls(link, timeout=3):
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
                return rtt <= 1500
    except Exception:
        return False

def check_via_xray_core(link, xray_path, timeout=5):
    actual_path = xray_path if os.path.exists(xray_path) else (xray_path + ".exe" if os.path.exists(xray_path + ".exe") else None)
    if not actual_path:
        return None

    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        local_port = random.randint(20000, 30000)
        config_path = f"temp_config_{local_port}.json"

        security_type = query.get("security", [""])[0].lower()

        outbound_settings = {
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
                "security": security_type
            }
        }

        if security_type == "reality":
            outbound_settings["streamSettings"]["realitySettings"] = {
                "show": False,
                "fingerprint": query.get("fp", ["chrome"])[0],
                "serverName": query.get("sni", [""])[0],
                "publicKey": query.get("pbk", [""])[0],
                "shortId": query.get("sid", [""])[0],
                "spiderX": query.get("spx", [""])[0]
            }
        elif security_type == "tls":
            outbound_settings["streamSettings"]["tlsSettings"] = {
                "serverName": query.get("sni", [""])[0],
                "fingerprint": query.get("fp", ["chrome"])[0]
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

def test_link(link, xray_available):
    try:
        parsed = urlparse(link)
        ip = parsed.hostname
        if not check_geoip_api(ip):
            return False
        if xray_available:
            res_xray = check_via_xray_core(link, XRAY_PATH)
            return res_xray if res_xray is not None else is_server_alive_tls(link)
        return is_server_alive_tls(link)
    except Exception:
        return False

def parse_list(text, is_white_list=False, used_uuids=None):
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
                security = query_params.get("security", [""])[0].lower()
                pbk = query_params.get("pbk", [""])[0]
                
                if security == "reality" and not pbk:
                    continue

                if is_white_list:
                    sni_list = query_params.get("sni", ["blank"])
                    sni = sni_list[0].lower() if sni_list else "blank"
                    if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                        continue

                used_uuids.add(uuid)
                candidates.append(clean_line)
            except Exception:
                continue
    random.shuffle(candidates)
    return candidates

from concurrent.futures import ThreadPoolExecutor, as_completed

# Список "надежных" SNI, под которые маскируются долгоживущие серверы
TRUSTED_SNIS = ["microsoft.com", "apple.com", "icloud.com", "samsung.com", "google.com", "cloudflare.com"]

def get_stability_score(link):
    """Приоритезирует серверы: 0 - высокая стабильность (надежный SNI), 1 - обычный"""
    try:
        parsed = urlparse(link)
        query_params = parse_qs(parsed.query)
        sni = query_params.get("sni", [""])[0].lower()
        if any(trusted in sni for trusted in TRUSTED_SNIS):
            return 0  # Сначала проверяем эти
    except Exception:
        pass
    return 1

def thread_worker(link, xray_available):
    """Воркер для параллельного тестирования серверов"""
    is_alive = test_link(link, xray_available)
    return link, is_alive

def main():
    print("[1] Скачиваем базы серверов...")
    try:
        res_white = requests.get(URL_WHITE, timeout=10)
        res_black = requests.get(URL_BLACK, timeout=10)
    except Exception as e:
        print(f"Ошибка сети: {e}")
        return

    if res_white.status_code != 200 or res_black.status_code != 200:
        print("Ошибка загрузки списков.")
        return

    used_uuids = set()
    
    # Парсим списки. ВАЖНО: уберите random.shuffle из parse_list, 
    # чтобы сохранить исходный порядок агрегатора (там свежие серверы обычно вверху)
    black_candidates = parse_list(res_black.text, is_white_list=False, used_uuids=used_uuids)
    white_candidates = parse_list(res_white.text, is_white_list=True, used_uuids=used_uuids)

    print(f"Найдено уникальных кандидатов: Черный список - {len(black_candidates)}, Белый список - {len(white_candidates)}")
    
    xray_available = os.path.exists(XRAY_PATH) or os.path.exists(XRAY_PATH + ".exe")
    if not xray_available:
        print("[!] Ядро Xray не найдено, проверка идет в режиме TLS Handshake.")

    # Сортируем кандидатов, выдвигая вперед потенциальных "долгожителей"
    black_candidates.sort(key=get_stability_score)
    white_candidates.sort(key=get_stability_score)

    black_working = []
    white_working = []
    
    # Настройки многопоточности
    MAX_WORKERS = 30  # Проверяем по 30 серверов одновременно

    # [2] Быстрая проверка ЧЕРНОГО списка
    print("\n[2] Быстрая многопоточная проверка зарубежных серверов (Черный список)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, link, xray_available): link for link in black_candidates}
        for future in as_completed(futures):
            link, is_alive = future.result()
            if is_alive:
                black_working.append(link)
                print(f" Найдена рабочая зарубежная прокси ({len(black_working)}/3)")
                if len(black_working) >= 3:
                    # Отменяем остальные задачи в этом пуле
                    for f in futures: f.cancel()
                    break

    # [3] Быстрая проверка БЕЛОГО списка
    print("\n[3] Быстрая многопоточная проверка резервных серверов (Белый список)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(thread_worker, link, xray_available): link for link in white_candidates}
        for future in as_completed(futures):
            link, is_alive = future.result()
            if is_alive:
                white_working.append(link)
                print(f" Найдена рабочая резервная прокси ({len(white_working)}/2)")
                if len(white_working) >= 2:
                    for f in futures: f.cancel()
                    break

    # Объединяем результаты
    working_links = black_working[:3] + white_working[:2]

    # Фолбэк на случай, если потоки ничего не успели найти
    if not working_links:
        print("\n[!] Живые серверы не обнаружены тестами. Записываем базовый набор.")
        working_links = black_candidates[:3] + white_candidates[:2]

    my_announcement = "База обновлена (3 ЧС + 2 БС). Многопоточный отбор завершен!"
    promo_url = "https://github.com"

    subscription_content = (
        f"//profile-title: {my_announcement}\n"
        f"//profile-web-page-url: {promo_url}\n"
        + "\n".join(working_links)
    )

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
        
    print(f"\n[+] Готово! Скрипт успешно сохранил {len(working_links)} серверов в файл {FILE_PATH}")

if __name__ == "main":
    main()
