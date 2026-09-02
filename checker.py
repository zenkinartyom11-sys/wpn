import ssl, socket, requests, time, base64, re, random, json, subprocess, os, signal, shutil
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# === НАСТРОЙКИ ===
TARGET_COUNT    = 10
CHECK_TIMEOUT   = 3
FETCH_WORKERS   = 10
HANDSHAKE_POOL  = 40
REAL_CHECK_POOL = 30
XRAY_TIMEOUT    = 7
MIN_WORKING     = 3      # минимум рабочих, чтобы обновить файл
PRIORITY_COUNTRIES = {"DE", "FI"}

URLS_WHITE = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/Ai123999/WhiteKeys/refs/heads/main/WhiteKeys",
    "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/main-sub.txt",
    "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part1.txt",
]
URLS_BLACK = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/BlackList.txt",
    "https://raw.githubusercontent.com/Mihuil121/vpn-checker-backend-fox/main/checked/My_Euro/euro_black.txt",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt",
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
    "81.9.", "81.18.", "81.19.", "81.23.", "81.25.", "81.30.", "81.95.", "81.163.", "81.176.",
    "81.177.", "81.195.", "81.200.", "81.211.", "82.112.", "82.138.", "82.140.", "82.146.", "82.148.",
    "82.162.", "82.179.", "82.193.", "82.194.", "82.200.", "82.202.", "83.102.", "83.142.", "83.149.",
    "83.166.", "83.217.", "83.219.", "83.220.", "83.222.", "83.234.", "83.239.", "83.242.", "84.22.",
    "84.38.", "84.52.", "84.53.", "84.201.", "84.204.", "84.253.", "85.12.", "85.15.", "85.21.",
    "85.26.", "85.93.", "85.95.", "85.112.", "85.113.", "85.114.", "85.115.", "85.118.", "85.119.",
    "85.142.", "85.143.", "85.158.", "85.172.", "85.173.", "85.174.", "85.175.", "85.192.", "85.233.",
    "85.234.", "85.236.", "85.249.", "87.103.", "87.117.", "87.224.", "87.225.", "87.226.", "87.228.",
    "87.237.", "87.241.", "87.242.", "87.244.", "87.247.", "87.249.", "87.250.", "87.251.", "88.84.",
    "88.212.", "89.108.", "89.109.", "89.111.", "89.113.", "89.169.", "89.175.", "89.178.", "89.179.",
    "89.189.", "89.207.", "89.208.", "89.222.", "89.223.", "89.249.", "89.250.", "89.251.", "109.106.",
    "109.184.", "109.194.", "109.195.", "109.252.", "141.8.", "141.101.", "151.249.", "217.21.",
    "217.23.", "217.66.", "217.73.", "217.107.", "217.114.", "217.118.", "217.150.", "217.174.",
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
        has_trusted = any(t in sni for t in TRUSTED_SNIS)
        if not (is_white_list and has_trusted):
            if is_russian_ip(host):
                continue
        seen.add(key)
        used_keys.add(key)
        candidates.append((line, has_trusted))
    return candidates

# === ЭТАП 1: быстрый отсев хендшейками ===
def handshake_check(item):
    line, has_trusted = item
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
                    try:
                        sock.close()
                    except Exception:
                        pass
                    return None
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        score = time.monotonic() - t0
        if score > CHECK_TIMEOUT:
            return None
        return (line, score, has_trusted)
    except Exception:
        return None

# === ЭТАП 2: конвертация в конфиг xray ===
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

def wait_for_port(port, timeout=5):
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.2)
    return False

# === ЭТАП 3: реальная проверка через xray (двойная) ===
def real_check_xray(line, local_port, timeout=XRAY_TIMEOUT):
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
            return None, None
        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}"
        }
        speeds = []
        country = None
        for attempt in range(2):
            try:
                t0 = time.monotonic()
                r = requests.get("http://ip-api.com/json/?fields=status,countryCode",
                                 proxies=proxies, timeout=timeout)
                dt = time.monotonic() - t0
                if r.status_code == 200:
                    data = r.json()
                    if data.get("status") == "success":
                        speeds.append(dt)
                        country = data.get("countryCode")
            except Exception:
                pass
            time.sleep(0.3)
        if len(speeds) < 2 or not country:
            return None, None
        return sum(speeds) / len(speeds), country
    except Exception:
        return None, None
    finally:
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
            try:
                proc.wait(timeout=2)
            except Exception:
                pass
        try:
            os.remove(config_path)
        except Exception:
            pass

def verify_real(candidates, need):
    random.shuffle(candidates)
    to_check = candidates[:REAL_CHECK_POOL]
    results = []
    base_port = 15000
    for i, item in enumerate(to_check):
        line = item[0]
        has_trusted = item[2] if len(item) > 2 else False
        port = base_port + i
        speed, country = real_check_xray(line, port)
        if speed is not None:
            priority = 0 if country in PRIORITY_COUNTRIES else 1
            results.append((line, speed, has_trusted, country, priority))
            print(f"    [+] {country} | {speed:.2f}s | {line[:55]}...")
        else:
            print(f"    [-] МЁРТВ | {line[:55]}...")
        good = [r for r in results if r[4] == 0]
        if len(results) >= need * 2 and len(good) >= need:
            break
    results.sort(key=lambda x: (x[4], x[1]))
    return results

def main():
    t_start = time.monotonic()
    print("[*] Парсер в11: двойная реальная проверка через xray")
    print("[*] Приоритет: Германия (DE), Финляндия (FI)")

    xray_found = os.path.exists(XRAY_PATH) or shutil.which("xray")
    if not xray_found:
        print("[!] xray не найден — реальная проверка невозможна. Выход.")
        return

    print("[*] Скачиваю источники...")
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        white_text = "\n".join(r for r in ex.map(fetch_one, URLS_WHITE) if r)
        black_text = "\n".join(r for r in ex.map(fetch_one, URLS_BLACK) if r)

    print("[*] Парсинг...")
    used_keys = set()
    white_c = parse_source_text(white_text, used_keys, is_white_list=True)
    black_c = parse_source_text(black_text, used_keys, is_white_list=False)
    print(f"[*] Кандидатов: белых {len(white_c)}, чёрных {len(black_c)}")

    print("[*] ЭТАП 1: быстрый отсев хендшейками...")
    white_hs, black_hs = [], []
    with ThreadPoolExecutor(max_workers=30) as ex:
        fw = [ex.submit(handshake_check, c) for c in white_c[:HANDSHAKE_POOL]]
        for f in as_completed(fw):
            r = f.result()
            if r:
                white_hs.append(r)
        fb = [ex.submit(handshake_check, c) for c in black_c[:HANDSHAKE_POOL]]
        for f in as_completed(fb):
            r = f.result()
            if r:
                black_hs.append(r)
    print(f"[+] Прошли хендшейк: белых {len(white_hs)}, чёрных {len(black_hs)}")

    print("[*] ЭТАП 2: двойная реальная проверка через xray...")
    print("--- Белые ---")
    white_real = verify_real(white_hs, TARGET_COUNT)
    print("--- Чёрные ---")
    black_real = verify_real(black_hs, TARGET_COUNT)

    final_white = [l for l, s, t, c, p in white_real[:TARGET_COUNT]]
    final_black = [l for l, s, t, c, p in black_real[:TARGET_COUNT]]

    print(f"\n[+] Найдено рабочих: белых {len(final_white)}, чёрных {len(final_black)}")

    if len(final_white) >= MIN_WORKING:
        with open("white_subscription.txt", "w", encoding="utf-8") as f:
            f.write("#profile-title: Белый список (РКН)\n" + "\n".join(final_white))
        print(f"[+] Белый список ОБНОВЛЁН ({len(final_white)} серверов)")
    else:
        print(f"[!] Белых рабочих < {MIN_WORKING} — файл НЕ обновлён (остались старые)")

    if len(final_black) >= MIN_WORKING:
        with open("black_subscription.txt", "w", encoding="utf-8") as f:
            f.write("#profile-title: Чёрный список (РКН)\n" + "\n".join(final_black))
        print(f"[+] Чёрный список ОБНОВЛЁН ({len(final_black)} серверов)")
    else:
        print(f"[!] Чёрных рабочих < {MIN_WORKING} — файл НЕ обновлён (остались старые)")

    print(f"[*] Время: {time.monotonic() - t_start:.1f} сек")

if __name__ == "__main__":
    main()
