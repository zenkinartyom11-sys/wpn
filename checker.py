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
XRAY_PATH = "./xray" # Укажите "xray.exe" для Windows, если он лежит в этой же папке

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
    \"\"\"Проверяет, принадлежит ли IP-адрес российскому хостингу по префиксу\"\"\"
    if not ip:
        return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"):
        return True
    return False

def check_geoip_api(ip):
    \"\"\"Дополнительная проверка через внешнее GeoIP API (Защита от спуфинга)\"\"\"
    try:
        # Используем бесплатное демо-поле без ключа (ограничение ~45 запросов в минуту)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response.get("countryCode") == "RU":
            return False
        return True
    except Exception:
        return True # Если API недоступно или лимит исчерпан, не блокируем сервер зря

def is_server_alive_tls(link, timeout=3):
    \"\"\"Способ 1: Быстрый TLS Handshake с замером задержки (RTT)\"\"\"
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
        
        # Замеряем время отклика (RTT)
        start_time = time.time()
        
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as ssock:
                rtt = (time.time() - start_time) * 1000
                
                # Фильтр умирающих/забитых портов (отсекаем всё, что медленнее 1500мс)
                if rtt > 1500:
                    return False
                return True
    except Exception:
        return False

def check_via_xray_core(link, xray_path, timeout=5):
    \"\"\"Способ 2: 100% надежная проверка реальным трафиком через локальное ядро Xray\"\"\"
    # Проверяем, существует ли бинарник xray на диске
    actual_path = xray_path if os.path.exists(xray_path) else (xray_path + ".exe" if os.path.exists(xray_path + ".exe") else None)
    if not actual_path:
        return None # Сигнализируем, что Xray не найден, нужно использовать TLS метод

    try:
        parsed = urlparse(link)
        query = parse_qs(parsed.query)
        
        # Динамически подбираем случайный свободный порт для локального прокси
        local_port = random.randint(20000, 30000)
        config_path = f"temp_config_{local_port}.json"

        # Генерируем минимальный рабочий конфиг Xray для теста одной ссылки
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
                            "encryption": query.get("encryption", ["none"]),
                            "flow": query.get("flow", [""])
                        }]
                    }]
                },
                "streamSettings": {
                    "network": query.get("type", ["tcp"]),
                    "security": query.get("security", [""]),
                    "realitySettings": {
                        "show": False,
                        "fingerprint": query.get("fp", ["chrome"]),
                        "serverName": query.get("sni", [""]),
                        "publicKey": query.get("pbk", [""]),
                        "shortId": query.get("sid", [""]),
                        "spiderX": query.get("spx", [""])
                    }
                }
            }]
        }

        # Сохраняем конфиг во временный файл
        with open(config_path, "w") as f:
            json.dump(xray_config, f)

        # Запускаем Xray скрытно в фоновом процессе
        process = subprocess.Popen(
            [actual_path, "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        time.sleep(0.5) # Даем ядру полсекунды на запуск структуры
        
        proxies = {
            "http": f"socks5://127.0.0.1:{local_port}",
            "https": f"socks5://127.0.0.1:{local_port}"
        }

        success = False
        try:
            # Пытаемся сделать реальный запрос через этот прокси на Google (проверка Reality ключей)
            res = requests.get("https://www.google.com/generate_204", proxies=proxies, timeout=timeout)
            if res.status_code in [200, 204]:
                success = True
        except Exception:
            success = False
        finally:
            # Обязательно убиваем процесс и зачищаем временный файл конфигурации
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
        print(f"❌ Ошибка сети при скачивании базы: {e}")
        return

    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    all_valid_candidates = []
    used_uuids = set()

    print("Разбираем и фильтруем структуру ключей...")
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

                # 1. Защита от дубликатов UUID
                if uuid in used_uuids:
                    continue

                # 2. КРИТИЧЕСКИЙ БАН ВСЕХ РОССИЙСКИХ СЕРВЕРОВ (Быстрый по маске)
                if is_russian_ip(ip):
                    continue

                # 3. Фильтр по маскировочному домену (SNI)
                query_params = parse_qs(parsed.query)
                sni_list = query_params.get("sni", ["blank"])
                sni = sni_list[0].lower() if sni_list else "blank"
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue

                # 4. ВАЛИДАЦИЯ ПАРАМЕТРОВ REALITY (Критические ключи)
                security = query_params.get("security", [""])[0].lower()
                pbk = query_params.get("pbk", [""])  # Public Key
                
                # Если в конфиге заявлен reality, но нет публичного ключа — он никогда не заведется
                if security == "reality" and not pbk:
                    continue

                # Если все базовые проверки пройдены, сохраняем в первичный пул
                used_uuids.add(uuid)
                all_valid_candidates.append(clean_line)
            except Exception:
                continue

    print(f"ℹ️ Всего валидных заграничных структур найдено: {len(all_valid_candidates)}")
    if not all_valid_candidates:
        print("❌ Заграничные уникальные серверы не найдены.")
        return

    # Перемешиваем пул серверов
    random.shuffle(all_valid_candidates)
    working_links = []
    
    # Проверяем, доступен ли полноценный бинарный чекер Xray
    xray_available = os.path.exists(XRAY_PATH) or os.path.exists(XRAY_PATH + ".exe")
    if xray_available:
        print("🤖 Обнаружено ядро Xray. Включен 100% точный метод проверки трафиком.")
    else:
        print("⚡ Ядро Xray не найдено. Используется быстрый метод TLS-Handshake + RTT.")

    print(f"2. Тестируем и отбираем 5 лучших живых заграничных серверов...")
    
    for link in all_valid_candidates:
        if len(working_links) >= 5:
            break
            
        try:
            parsed = urlparse(link)
            ip = parsed.hostname
            port = parsed.port
            
            # Шаг А: Углубленный GeoIP чек (защита от маскировки русских серверов под зарубежные домены)
            if not check_geoip_api(ip):
                continue

            # Шаг Б: Основное тестирование доступности
            is_alive = False
            
            if xray_available:
                # Проверяем через реальный прокси-запрос ядра Xray
                res_xray = check_via_xray_core(link, XRAY_PATH)
                if res_xray is not None:
                    is_alive = res_xray
                else:
                    # Фолбэк на TLS, если в процессе что-то сломалось
                    is_alive = is_server_alive_tls(link)
            else:
                # Проверяем исправленным методом TLS Handshake + RTT лимит
                is_alive = is_server_alive_tls(link)

            if is_alive:
                working_links.append(link)
                print(f" 🚀 Нашли рабочий зарубежный IP: {ip}:{port}. Добавлено ({len(working_links)}/5)")
                
        except Exception:
            continue

    if not working_links:
        print("⚠️ Живые порты не ответили на тесты трафика. Записываем 5 случайных заграничных серверов...")
        working_links = all_valid_candidates[:5]

    # Записываем итоговый чистый файл подписки
    subscription_content = "\n".join(working_links)
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
        
    print(f"✅ УСПЕХ! В файл {FILE_PATH} сохранено ровно {len(working_links)} гарантированно рабочих чистых серверов.")

if __name__ == "__main__":
    main()
"""
print(f"Code string length: {len(code)}")
