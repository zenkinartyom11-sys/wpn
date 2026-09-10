import ssl, socket, requests, time, base64, re, random, json, subprocess, os, signal, shutil
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# === НАСТРОЙКИ ===
TARGET_COUNT    = 10
CHECK_TIMEOUT   = 3
FETCH_WORKERS   = 10
HANDSHAKE_POOL  = 60
REAL_CHECK_POOL = 40        # больше кандидатов
XRAY_TIMEOUT    = 8         # больше таймаут для загрузки реального контента
XRAY_WORKERS    = 12        # больше потоков (Actions бесплатный)

# Квоты по регионам (сумма = TARGET_COUNT)
# ВАЖНО: США ограничены, чтобы не заполонить подписку
PRIORITY_QUOTAS = {
    "DE": 4,                 # Германия — 4 места
    "FI": 3,                 # Финляндия — 3 места
    "US": 1,                 # США — только 1 место!
    "OTHER": 2,              # Остальные страны — 2 места
}

# Карты эмодзи флагов и ключевых слов для определения страны
COUNTRY_PATTERNS = {
    "DE": ["🇩🇪", "germany", "deutschland", "frankfurt", "munich", "berlin", "hessen", "bayern", ".de"],
    "FI": ["🇫🇮", "finland", "suomi", "helsinki", "tampere", ".fi"],
    "US": ["🇺🇸", "usa", "united states", "new york", "california", "texas", "los angeles", "chicago", "miami", "seattle", "san jose", "dallas", ".us"],
    "NL": ["🇳🇱", "netherlands", "holland", "amsterdam", ".nl"],
    "SE": ["🇸🇪", "sweden", "stockholm", ".se"],
    "NO": ["🇳🇴", "norway", "oslo", ".no"],
    "GB": ["🇬🇧", "uk", "britain", "london", ".uk", ".co.uk"],
    "FR": ["🇫🇷", "france", "paris", ".fr"],
    "CA": ["🇨🇦", "canada", "toronto", "vancouver", ".ca"],
    "PL": ["🇵🇱", "poland", "warsaw", ".pl"],
}

URLS_WHITE = [
    "https://raw.githubusercontent.com/HenonBank/Russia_LTE/refs/heads/main/v2ray_sub.txt",
    "https://raw.githubusercontent.com/Ai123999/WhiteKeys/refs/heads/main/WhiteKeys",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt",
]
URLS_BLACK = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/refs/heads/main/Config_jo.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/refs/heads/main/deploy/subscriptions/11.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/refs/heads/main/deploy/subscriptions/1.txt",
]

TRUSTED_SNIS = [
    "stripe.com", "paypal.com", "checkout.com", "adyen.com", "braintreepayments.com",
    "worldpay.com", "skrill.com", "neteller.com", "payoneer.com", "authorize.net",
    "klarna.com", "shopify.com", "swift.com", "revolut.com", "wise.com",
    "visa.com", "mastercard.com", "americanexpress.com", "hsbc.com", "chase.com",
    "binance.com", "coinbase.com", "kraken.com",
]

VALID_PROTOCOLS = ("vless://", "hysteria2://", "hy2://")

RUSSIAN_PREFIXES = [
    "5.42.", "5.43.", "5.101.", "5.130.", "5.143.", "5.187.", "5.188.", "31.28.", "31.31.", "31.40.",
    "31.43.", "31.134.", "31.162.", "31.173.", "37.18.", "37.29.", "37.110.", "37.140.", "37.143.",
    "37.192.", "37.235.", "45.8.", "45.9.", "45.12.", "45.66.", "45.67.", "45.81.", "45.86.",
    "45.89.", "45.90.", "45.95.", "45.130.", "45.132.", "45.135.", "45.141.", "45.142.", "45.145.",
    "45.155.", "45.156.", "46.3.", "46.8.", "46.17.", "46.38.", "46.39.", "46.146.", "46.147.",
    "46.148.", "46.161.", "46.182.", "46.242.", "51.124.", "51.250.", "62.33.", "62.76.", "62.109.",
    "62.117.", "62.148.", "62.152.", "62.213.", "77.37.", "77.41.", "77.51.", "77.72.", "77.73.",
    "77.74.", "77.82.", "77.108.", "77.220.", "77.222.", "77.232.", "77.242.", "77.244.", "78.25.",
    "78.29.", "78.36.", "78.37.", "78.46.", "78.47.", "78.81.", "78.85.", "78.108.", "78.109.",
    "78.140.", "79.104.", "79.111.", "79.120.", "79.133.", "79.134.", "79.137.", "79.143.", "79.174.",
    "80.64.", "80.68.", "80.78.", "80.80.", "80.82.", "80.83.", "80.87.", "80.92.", "80.93.",
]

XRAY_PATH = "./xray" if os.path.exists("./xray") else "xray"

_dns_cache = {}
def resolve(host):
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = None
    _dns_cache[host] = ip
    return ip

def is_russian_ip(ip_or_domain):
    if not ip_or_domain:
        return False
    target_ip = ip_or_domain
    if not ip_or_domain.replace('.', '').isdigit():
        target_ip = resolve(ip_or_domain)
        if not target_ip:
            return True
    if any(target_ip.startswith(p) for p in RUSSIAN_PREFIXES):
        return True
    try:
        parts = target_ip.split('.')
        if len(parts) >= 4:
            first_octet = int(parts[0])
            if 91 <= first_octet <= 95 or first_octet in (176, 178, 185, 188, 212, 213) or 193 <= first_octet <= 195:
                return True
            if first_octet == 128 and 68 <= int(parts[1]) <= 75:
                return True
    except Exception:
        pass
    return target_ip.endswith((".ru", ".su", ".by"))

def detect_country(link, sni=""):
    """Определяет страну по имени ссылки (#комментарий) и SNI домену. Без сторонних сервисов."""
    # Смотрим часть после #
    fragment = ""
    if "#" in link:
        fragment = link.split("#", 1)[1].lower()
    
    # Смотрим SNI
    check_texts = [fragment, sni.lower() if sni else ""]
    
    for country, patterns in COUNTRY_PATTERNS.items():
        for pattern in patterns:
            for text in check_texts:
                if pattern in text:
                    return country
    return "OTHER"

def smart_decode(text):
    result_lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if any(line.startswith(p) for p in VALID_PROTOCOLS):
            result_lines.append(line)
            continue
        t = line
        decoded = False
        for _ in range(3):
            try:
                pad = '=' * (-len(t) % 4)
                dec = base64.b64decode(t + pad).decode('utf-8', errors='ignore')
                if any(p in dec for p in VALID_PROTOCOLS):
                    result_lines.extend([l.strip() for l in dec.splitlines() if l.strip()])
                    decoded = True
                    break
                t = dec.strip()
                if not t:
                    break
            except Exception:
                break
        if not decoded and "://" in line:
            matches = re.findall(r'(vless://[^\s<>"\'`,]+|hysteria2://[^\s<>"\'`,]+|hy2://[^\s<>"\'`,]+)', line)
            result_lines.extend(matches)
    return "\n".join(result_lines)

def fetch_one(url):
    try:
        r = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return smart_decode(r.text.lstrip('\ufeff'))
    except Exception:
        pass
    return ""

def extract_info(line):
    try:
        parsed = urlparse(line)
        host, port, user = parsed.hostname, parsed.port, parsed.username
        if not host or not port:
            tail = line.split('://', 1)[1]
            user = tail.split('@', 1)[0]
            hostport = tail.split('@', 1)[1].split('/', 1)[0].split('?', 1)[0]
            host, port = hostport.rsplit(':', 1)
            port = int(port)
        q = parse_qs(parsed.query)
        sni = (q.get('sni', ['']) or [''])[0].lower()
        security = (q.get('security', ['']) or [''])[0]
        typ = (q.get('type', ['tcp']) or ['tcp'])[0]
        path = (q.get('path', ['']) or [''])[0]
        pbk = (q.get('pbk', ['']) or [''])[0]
        return host, port, user, sni, security, typ, path, pbk
    except Exception:
        return None

def parse_source_text(text, used_keys, is_white_list=False):
    candidates, seen = [], set()
    for line in text.splitlines():
        line = line.strip().lstrip('\ufeff')
        if not any(line.startswith(p) for p in VALID_PROTOCOLS):
            continue
        proto = line.split('://', 1)[0]
        if proto in ('hysteria2', 'hy2'):
            continue
        info = extract_info(line)
        if not info:
            continue
        host, port, user, sni, security, typ, path, pbk = info
        key = (user, host, port)
        if key in seen or key in used_keys:
            continue
        if security == 'reality' and not pbk:
            continue
        has_trusted = any(t in sni for t in TRUSTED_SNIS) if sni else False
        
        if is_white_list:
            if not has_trusted:
                continue
        else:
            if is_russian_ip(host):
                continue
        
        # Определяем страну сразу при парсинге
        country = detect_country(line, sni)
        
        seen.add(key)
        used_keys.add(key)
        candidates.append((line, has_trusted, country))
    return candidates

def handshake_check(item):
    line, has_trusted, country = item
    try:
        info = extract_info(line)
        if not info:
            return None
        host, port, user, sni, security, typ, path, pbk = info
        if not host or not port:
            return None
        sni = sni or host
        if security == 'reality' and not pbk:
            return None
        t0 = time.monotonic()
        sock = socket.create_connection((host, port), timeout=CHECK_TIMEOUT)
        if security in ('tls', 'reality', 'xtls'):
            ctx = ssl._create_unverified_context()
            try:
                ctx.set_ciphers('DEFAULT@SECLEVEL=0')
            except Exception:
                pass
            try:
                sock.settimeout(CHECK_TIMEOUT)
                with ctx.wrap_socket(sock, server_hostname=sni):
                    pass
                sock = None
            except Exception:
                if security != 'reality':
                    try: sock.close()
                    except: pass
                    return None
        if sock:
            try: sock.close()
            except: pass
        score = time.monotonic() - t0
        if score > CHECK_TIMEOUT:
            return None
        return (line, score, has_trusted, country)
    except Exception:
        return None

def vless_to_xray_config(link, local_port):
    parsed = urlparse(link)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port
    q = parse_qs(parsed.query)
    g = lambda k, d="": (q.get(k, [d]) or [d])[0]
    security = g("security", "none")
    typ = g("type", "tcp")
    sni = g("sni", host)
    pbk = g("pbk")
    sid = g("sid")
    fp = g("fp", "chrome")
    flow = g("flow")
    path = g("path", "/")
    host_header = g("host", sni)
    service_name = g("serviceName", "")
    encryption = g("encryption", "none")
    user_obj = {"id": uuid, "encryption": encryption or "none"}
    if flow:
        user_obj["flow"] = flow
    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user_obj]}]},
        "streamSettings": {"network": typ, "security": security}
    }
    ss = outbound["streamSettings"]
    if security == "reality":
        ss["realitySettings"] = {
            "serverName": sni, "fingerprint": fp, "publicKey": pbk,
            "shortId": sid, "spiderX": "/"
        }
    elif security == "tls":
        ss["tlsSettings"] = {"serverName": sni, "allowInsecure": True}
    if typ == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": host_header}}
    elif typ == "grpc":
        ss["grpcSettings"] = {"serviceName": service_name}
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": local_port,
            "protocol": "http", "settings": {"allowTransparent": False}
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}]
    }

def wait_for_port(port, timeout=4):
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.2)
    return False

def real_check_strict(line, local_port, is_white_list, timeout=XRAY_TIMEOUT):
    """
    ЖЕЛЕЗОБЕТОННАЯ проверка через загрузку реального контента.
    - Для белых списков: грузим instagram.com (разрешён в РФ)
    - Для чёрных: грузим youtube.com (разблокирован через прокси)
    """
    config = vless_to_xray_config(line, local_port)
    config_path = f"/tmp/xray_cfg_{local_port}.json"
    proc = None
    try:
        with open(config_path, "w") as f:
            json.dump(config, f)
        proc = subprocess.Popen(
            [XRAY_PATH, "run", "-c", config_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
        if not wait_for_port(local_port, timeout=4):
            return None, 0
        
        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}"
        }
        
        # Выбираем целевой сайт для проверки
        if is_white_list:
            # Instagram работает через белые списки в РФ
            # Если через прокси грузится — сервер рабочий
            target_url = "https://www.instagram.com/"
            min_size = 10000  # минимум 10KB настоящей HTML
            forbidden_markers = [b"<title>Instagram</title>"]  # должно быть в ответе
        else:
            # YouTube проверяет черный список
            target_url = "https://www.youtube.com/"
            min_size = 15000
            forbidden_markers = [b"<title>YouTube</title>"]
        
        # === ОСНОВНАЯ ПРОВЕРКА: загрузка реального сайта ===
        try:
            t0 = time.monotonic()
            r = requests.get(target_url, proxies=proxies, timeout=timeout,
                             headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"})
            elapsed = time.monotonic() - t0
            if r.status_code != 200:
                return None, 0
            content = r.content
            # Заглушки обычно очень маленькие (<5KB)
            if len(content) < min_size:
                return None, 0
            # Проверяем что это настоящий сайт, а не страница блокировки
            if not any(marker in content for marker in forbidden_markers):
                return None, 0
            # Исключаем страницы с "доступ запрещён", "заблокировано"
            block_markers = [b"forbidden", b"access denied", b"blocked", 
                             b"403", b"451", b"unavailable for legal reasons",
                             b"\xd0\xb7\xd0\xb0\xd0\xb1\xd0\xbb\xd0\xbe\xd0\xba"]  # "заблок" в UTF-8
            for marker in block_markers:
                if marker in content.lower():
                    return None, 0
            return elapsed, len(content) / elapsed / 1024  # КБ/с
        except Exception:
            return None, 0
            
    except Exception:
        return None, 0
    finally:
        if proc:
            try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except: pass
            try: proc.wait(timeout=1)
            except: pass
        try: os.remove(config_path)
        except: pass

def verify_real_strict(candidates, need, is_white_list):
    random.shuffle(candidates)
    to_check = candidates[:REAL_CHECK_POOL]
    results = []
    
    def check_one(item, idx):
        line = item[0]
        has_trusted = item[1]
        country = item[2]
        port = 15000 + idx
        elapsed, speed_kbps = real_check_strict(line, port, is_white_list)
        return (line, elapsed, has_trusted, country, speed_kbps)
    
    with ThreadPoolExecutor(max_workers=XRAY_WORKERS) as ex:
        futures = [ex.submit(check_one, item, i) for i, item in enumerate(to_check)]
        for f in as_completed(futures):
            line, elapsed, has_trusted, country, speed_kbps = f.result()
            if country is not None and elapsed is not None:
                results.append((line, elapsed, has_trusted, country, speed_kbps))
                print(f"    [+] {country:3s} | {speed_kbps:7.1f} KB/s | {elapsed:.2f}s | {line[:40]}...")
            else:
                print(f"    [-] МЁРТВ | {line[:55]}...")
    
    return results

def select_balanced(results, need):
    """Умные квоты: если страны нет, её квота идёт в OTHER (НЕ в США)."""
    by_country = {}
    for r in results:
        c = r[3]
        if c not in by_country:
            by_country[c] = []
        by_country[c].append(r)
    
    # Сортируем внутри страны по скорости
    for c in by_country:
        by_country[c].sort(key=lambda x: x[1])
    
    selected = []
    used = set()
    
    quotas = PRIORITY_QUOTAS.copy()
    
    # 1. Забираем по квотам из приоритетных стран (DE, FI, US)
    for country in ["DE", "FI", "US"]:
        quota = quotas.get(country, 0)
        if country in by_country:
            taken = 0
            for r in by_country[country]:
                if r[0] not in used and taken < quota:
                    selected.append(r)
                    used.add(r[0])
                    taken += 1
    
    # 2. OTHER — все остальные страны (включая NL, SE, GB и т.д.)
    # ВАЖНО: США сюда НЕ попадает, только остальные
    other_quota = quotas.get("OTHER", 0)
    other_taken = 0
    all_other = []
    for country, servers in by_country.items():
        if country in {"DE", "FI", "US", "OTHER"}:
            continue
        all_other.extend(servers)
    # OTHER из самой категории OTHER
    if "OTHER" in by_country:
        all_other.extend(by_country["OTHER"])
    all_other.sort(key=lambda x: x[1])
    for r in all_other:
        if r[0] not in used and other_taken < other_quota:
            selected.append(r)
            used.add(r[0])
            other_taken += 1
    
    # 3. Если не набрали need — добиваем ЛЮБЫМИ оставшимися (по скорости)
    # Но СНАЧАЛА добиваем из DE/FI/NL (хорошие страны), потом из остальных
    if len(selected) < need:
        priority_fill = []
        other_fill = []
        for country, servers in by_country.items():
            for r in servers:
                if r[0] not in used:
                    if country in {"DE", "FI", "NL", "SE", "NO", "GB"}:
                        priority_fill.append(r)
                    else:
                        other_fill.append(r)
        priority_fill.sort(key=lambda x: x[1])
        other_fill.sort(key=lambda x: x[1])
        for r in priority_fill + other_fill:
            if len(selected) >= need:
                break
            if r[0] not in used:
                selected.append(r)
                used.add(r[0])
    
    # Сортируем финальный список по скорости
    selected.sort(key=lambda x: x[1])
    return selected[:need]

def read_old_servers(filename):
    if not os.path.exists(filename):
        return []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
        return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    except Exception:
        return []

def write_subscription(filename, title, servers):
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"#profile-title: {title}\n" + "\n".join(servers))

def merge_new_and_old(new_results, old_servers, is_white_list):
    if not new_results and not old_servers:
        return []
    
    new_links = [r[0] for r in new_results] if new_results else []
    new_keys = set()
    for link in new_links:
        info = extract_info(link)
        if info:
            new_keys.add((info[2], info[0], info[1]))
    
    old_to_check = []
    for link in old_servers:
        info = extract_info(link)
        if not info:
            continue
        key = (info[2], info[0], info[1])
        if key in new_keys:
            continue
        has_trusted = any(t in info[3] for t in TRUSTED_SNIS) if info[3] else False
        sni = info[3] if info else ""
        country = detect_country(link, sni)
        old_to_check.append((link, has_trusted, country))
    
    print(f"[*] Проверяю {len(old_to_check)} старых серверов (хендшейк)...")
    old_alive = []
    if old_to_check:
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(handshake_check, item) for item in old_to_check]
            for f in as_completed(futures):
                r = f.result()
                if r:
                    old_alive.append(r)
    
    old_alive.sort(key=lambda x: x[1])
    old_links = [l for l, s, t, c in old_alive]
    print(f"[+] Живых старых: {len(old_links)}")
    
    combined = new_links + old_links
    seen, deduped = set(), []
    for link in combined:
        info = extract_info(link)
        if info:
            key = (info[2], info[0], info[1])
            if key not in seen:
                seen.add(key)
                deduped.append(link)
    return deduped[:TARGET_COUNT]

def print_distribution(results):
    counts = {}
    for r in results:
        c = r[3]
        counts[c] = counts.get(c, 0) + 1
    parts = [f"{c}:{n}" for c, n in sorted(counts.items())]
    print(f"    Распределение по странам: {', '.join(parts) if parts else 'нет данных'}")

def main():
    t_start = time.monotonic()
    print("[*] Парсер v15: определение страны по имени + загрузка реального контента")
    print(f"[*] Квоты: {PRIORITY_QUOTAS} (США ограничено!)")
    
    xray_found = os.path.exists(XRAY_PATH) or shutil.which("xray")
    if not xray_found:
        print("[!] xray не найден. Выход.")
        return
    
    print("[*] Скачиваю источники...")
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        white_text = "\n".join(r for r in ex.map(fetch_one, URLS_WHITE) if r)
        black_text = "\n".join(r for r in ex.map(fetch_one, URLS_BLACK) if r)
    
    print("[*] Парсинг (РАЗДЕЛЬНЫЕ пулы, с определением страны)...")
    white_keys = set()
    black_keys = set()
    white_c = parse_source_text(white_text, white_keys, is_white_list=True)
    black_c = parse_source_text(black_text, black_keys, is_white_list=False)
    print(f"[*] Кандидатов: белых {len(white_c)}, чёрных {len(black_c)}")
    
    # Показываем распределение по странам ДО проверки
    print("\n[*] Распределение кандидатов по странам:")
    white_countries = {}
    for _, _, c in white_c:
        white_countries[c] = white_countries.get(c, 0) + 1
    print(f"    Белые: {', '.join(f'{c}:{n}' for c, n in sorted(white_countries.items()))}")
    black_countries = {}
    for _, _, c in black_c:
        black_countries[c] = black_countries.get(c, 0) + 1
    print(f"    Чёрные: {', '.join(f'{c}:{n}' for c, n in sorted(black_countries.items()))}")
    
    print("\n[*] ЭТАП 1: хендшейк...")
    white_hs, black_hs = [], []
    with ThreadPoolExecutor(max_workers=30) as ex:
        fw = [ex.submit(handshake_check, c) for c in white_c[:HANDSHAKE_POOL]]
        for f in as_completed(fw):
            r = f.result()
            if r: white_hs.append(r)
        fb = [ex.submit(handshake_check, c) for c in black_c[:HANDSHAKE_POOL]]
        for f in as_completed(fb):
            r = f.result()
            if r: black_hs.append(r)
    print(f"[+] Прошли хендшейк: белых {len(white_hs)}, чёрных {len(black_hs)}")
    
    print("\n[*] ЭТАП 2: ЖЕЛЕЗОБЕТОННАЯ проверка (загрузка instagram.com / youtube.com)...")
    print("--- Белые (грузим instagram.com) ---")
    white_real = verify_real_strict(white_hs, TARGET_COUNT, is_white_list=True)
    print_distribution(white_real)
    print("--- Чёрные (грузим youtube.com) ---")
    black_real = verify_real_strict(black_hs, TARGET_COUNT, is_white_list=False)
    print_distribution(black_real)
    
    print("\n[*] ЭТАП 3: выбор по квотам...")
    white_selected = select_balanced(white_real, TARGET_COUNT)
    black_selected = select_balanced(black_real, TARGET_COUNT)
    print(f"[+] Отобрано по квотам: белых {len(white_selected)}, чёрных {len(black_selected)}")
    print_distribution(white_selected)
    
    old_white = read_old_servers("white_subscription.txt")
    old_black = read_old_servers("black_subscription.txt")
    
    print("\n[*] Мердж: новые + живые старые...")
    final_white = merge_new_and_old(white_selected, old_white, is_white_list=True)
    final_black = merge_new_and_old(black_selected, old_black, is_white_list=False)
    
    if final_white:
        write_subscription("white_subscription.txt", "Белый список (РКН)", final_white)
        print(f"[+] Белый список ОБНОВЛЁН: {len(final_white)} серверов")
    else:
        print("[!] Белый список пуст")
    
    if final_black:
        write_subscription("black_subscription.txt", "Чёрный список (РКН)", final_black)
        print(f"[+] Чёрный список ОБНОВЛЁН: {len(final_black)} серверов")
    else:
        print("[!] Чёрный список пуст")
    
    print(f"\n[*] Общее время: {time.monotonic() - t_start:.1f} сек")

if __name__ == "__main__":
    main()
