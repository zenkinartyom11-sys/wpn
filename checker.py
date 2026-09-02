import ssl, socket, requests, time, base64, re, random
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_COUNT   = 10
CHECK_TIMEOUT  = 3
MAX_CHECK      = 50
FETCH_WORKERS  = 10
CHECK_WORKERS  = 30
HTTP_TIMEOUT   = 8

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
    "goldmansachs.com", "morganstanley.com", "citibank.com", "bankofamerica.com",
    "barclays.com", "ubs.com", "binance.com", "coinbase.com", "kraken.com",
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

_dns_cache = {}
def resolve(host):
    if host in _dns_cache: return _dns_cache[host]
    try: ip = socket.gethostbyname(host)
    except: ip = None
    _dns_cache[host] = ip
    return ip

def is_russian_ip(ip_or_domain):
    if not ip_or_domain: return False
    target_ip = ip_or_domain
    if not ip_or_domain.replace('.', '').isdigit():
        target_ip = resolve(ip_or_domain)
        if not target_ip: return True
    if any(target_ip.startswith(p) for p in RUSSIAN_PREFIXES): return True
    try:
        parts = target_ip.split('.')
        if len(parts) >= 4:
            first_octet = int(parts[0])
            if 91 <= first_octet <= 95 or first_octet in (176, 178, 185, 188, 212, 213) or 193 <= first_octet <= 195: return True
            if first_octet == 128 and 68 <= int(parts[1]) <= 75: return True
    except: pass
    return target_ip.endswith((".ru", ".su", ".by"))

def smart_decode(text):
    result_lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
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
                if not t: break
            except: break
        if not decoded and "://" in line:
            matches = re.findall(r'(vless://[^\s<>"\'`,]+|hysteria2://[^\s<>"\'`,]+|hy2://[^\s<>"\'`,]+)', line)
            result_lines.extend(matches)
    return "\n".join(result_lines)

def fetch_one(url):
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return smart_decode(r.text.lstrip('\ufeff'))
    except: pass
    return ""

def extract_info(line):
    """Возвращает (host, port, user, sni, security, typ, path, pbk) или None."""
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
    except: return None

def parse_source_text(text, used_keys, is_white_list=False):
    candidates, seen = [], set()
    for line in text.splitlines():
        line = line.strip().lstrip('\ufeff')
        if not any(line.startswith(p) for p in VALID_PROTOCOLS): continue
        info = extract_info(line)
        if not info: continue
        host, port, user, sni, security, typ, path, pbk = info
        key = (user, host, port)
        if key in seen or key in used_keys: continue
        
        # ЖЁСТКИЙ ФИЛЬТР: Reality без ключа = мёртвый, отбрасываем сразу
        if security == 'reality' and not pbk:
            continue
        
        has_trusted = any(t in sni for t in TRUSTED_SNIS)
        if not (is_white_list and has_trusted):
            if is_russian_ip(host): continue
        seen.add(key)
        used_keys.add(key)
        candidates.append((line, has_trusted))
    return candidates

def test_server(item):
    """Проверяет живость сервера. Возвращает (ссылка, score, has_trusted) или None."""
    line, has_trusted = item
    try:
        proto = line.split('://', 1)[0]
        info = extract_info(line)
        if not info: return None
        host, port, user, sni, security, typ, path, pbk = info
        if not host or not port: return None
        sni = sni or host
        
        # hy2 работает по UDP, из Python не проверить — низкий приоритет
        if proto in ('hysteria2', 'hy2'):
            if resolve(host) is None: return None
            return (line, 8.0, has_trusted)
        
        # Reality без ключа — мёртвый
        if security == 'reality' and not pbk:
            return None
        
        t0 = time.monotonic()
        sock = socket.create_connection((host, port), timeout=CHECK_TIMEOUT)
        
        # Для WS с TLS: проверяем реальный путь через HTTP-запрос
        if typ == 'ws' and security == 'tls':
            ws_path = path if path else '/'
            request = (
                f"GET {ws_path} HTTP/1.1\r\n"
                f"Host: {sni}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            try:
                sock.sendall(request.encode())
                sock.settimeout(CHECK_TIMEOUT)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                # 404 = путь неверный, сервер мёртв
                if '404' in response:
                    return None
                # 101 или 403 или 400 = сервер жив (может требовать авторизацию)
                if any(code in response for code in ['101', '403', '400', '200']):
                    score = time.monotonic() - t0
                    return (line, score, has_trusted)
                # Любой другой ответ — мёртвый
                return None
            except Exception:
                try: sock.close()
                except: pass
                return None
        
        # Для остальных протоколов — стандартный TLS-хендшейк
        score = time.monotonic() - t0 + 0.5
        if security in ('tls', 'reality', 'xtls'):
            ctx = ssl._create_unverified_context()
            try: ctx.set_ciphers('DEFAULT@SECLEVEL=0')
            except: pass
            try:
                sock.settimeout(CHECK_TIMEOUT)
                with ctx.wrap_socket(sock, server_hostname=sni):
                    score = time.monotonic() - t0
                sock = None
            except Exception:
                if security != 'reality':
                    try: sock.close()
                    except: pass
                    return None
                score = time.monotonic() - t0 + 2.0
        if sock:
            try: sock.close()
            except: pass
        
        # Отбрасываем медленные/перегруженные сервера
        if score > CHECK_TIMEOUT:
            return None
        
        return (line, score, has_trusted)
    except Exception:
        return None

def verify_candidates(candidates, need):
    random.shuffle(candidates)
    to_check = candidates[:MAX_CHECK]
    alive = []
    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as ex:
        futures = [ex.submit(test_server, c) for c in to_check]
        for f in as_completed(futures):
            res = f.result()
            if res:
                alive.append(res)
                if len(alive) >= need * 2:
                    for fut in futures: fut.cancel()
                    break
    return alive

def main():
    t_start = time.monotonic()
    print(f"[*] Парсер v9: жёсткая проверка живости")
    print(f"[*] Белых источников: {len(URLS_WHITE)}, чёрных: {len(URLS_BLACK)}")

    print("[*] Скачиваю источники...")
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        white_text = "\n".join(r for r in ex.map(fetch_one, URLS_WHITE) if r)
        black_text = "\n".join(r for r in ex.map(fetch_one, URLS_BLACK) if r)

    print(f"[+] Скачано: белых {len(white_text)} байт, чёрных {len(black_text)} байт")
    print("[*] Парсинг (только vless + hy2, отбрасываю Reality без ключа)...")
    
    used_keys = set()
    white_c = parse_source_text(white_text, used_keys, is_white_list=True)
    black_c = parse_source_text(black_text, used_keys, is_white_list=False)

    print(f"[*] Кандидатов: белых {len(white_c)}, чёрных {len(black_c)}")
    print("[*] Проверяю живость (жёсткий режим)...")

    white_alive = verify_candidates(white_c, TARGET_COUNT)
    black_alive = verify_candidates(black_c, TARGET_COUNT)

    print(f"[+] Живых: белых {len(white_alive)}, чёрных {len(black_alive)}")

    white_alive.sort(key=lambda x: (0 if x[2] else 1, x[1]))
    black_alive.sort(key=lambda x: x[1])

    final_white = [l for l, s, t in white_alive[:TARGET_COUNT]]
    final_black = [l for l, s, t in black_alive[:TARGET_COUNT]]

    if final_white:
        with open("white_subscription.txt", "w", encoding="utf-8") as f:
            f.write("#profile-title: Белый список (РКН)\n" + "\n".join(final_white))
        print(f"[+] Белый список: {len(final_white)} серверов")
    else:
        print("[!] Белый список не обновлён — нет живых")

    if final_black:
        with open("black_subscription.txt", "w", encoding="utf-8") as f:
            f.write("#profile-title: Чёрный список (РКН)\n" + "\n".join(final_black))
        print(f"[+] Чёрный список: {len(final_black)} серверов")
    else:
        print("[!] Чёрный список не обновлён — нет живых")

    print(f"[*] Время: {time.monotonic() - t_start:.1f} сек")

if __name__ == "__main__":
    main()
