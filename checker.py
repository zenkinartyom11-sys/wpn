# -*- coding: utf-8 -*-
"""
ПАРСЕР v23.1 — источники: сайт ЭтоНеЯ + все зеркала (вкл. gitverse), Reality на любых портах.

ЛОГИКА (полностью переделана по ТЗ):
 1. Со страницы сайта собирает ВСЕ ссылки-зеркала разделов
    «белые списки» (*/whitelist) и «чёрные списки» (*/blacklist).
 2. Скачивает каждый файл (файлы без расширения — парсеру всё равно).
 3. Достаёт из них ВСЕ зарубежные серверы (vless + hysteria2).
 4. Проверяет каждый через реальный туннель (xray/sing-box):
    HTTP-204 → HTTPS-204 → Telegram (обязательно) → реальный контент → скорость.
 5. В white_subscription.txt / black_subscription.txt пишет ВСЕ живые
    (не 10, а сколько набралось), отсортированные по скорости.
    Ни одного живого — файл не трогает (старый сохраняется).
 6. proven.txt (если есть) — серверы, проверенные тобой вручную: идут первыми.

state.json больше НЕ ведётся. Внешние списки (Subzio/igareck/индексы) убраны.
"""

import ssl, socket, requests, time, base64, re, random, json, subprocess, os, signal, shutil, ipaddress
from urllib.parse import urlparse, parse_qs, unquote, quote
from concurrent.futures import ThreadPoolExecutor

# ================== НАСТРОЙКИ ==================
SITE_PAGE   = "https://xn--e1apcp8cq.xn--p1ai/"   # страница с зеркалами списков
# запасные зеркала, если страница не отдаст ссылки
FALLBACK_WHITE = [
    "https://gitverse.ru/api/repos/etoneya/sub/raw/branch/master/whitelist",
    "https://internet-tenshi.kangel.tech/whitelist",
    "https://whitelist.etoneya.baby",
    "https://etoneya.su/whitelist",
    "https://etoneya.best/whitelist",
    "https://etoneya.vercel.app/whitelist",
    "https://ety.twinkvibe.gay/whitelist",
    "https://alley.serv00.net/whitelist",
    "https://etoskam.ru/whitelist",
    "https://xn--e1apcp8cq.xn--p1ai/whitelist",
]
FALLBACK_BLACK = [
    "https://blacklist.etoneya.baby",
    "https://etoneya.best/other",
    "https://etoneya.su/other",
]

MAX_REAL_CHECKS = int(os.environ.get("MAX_REAL_CHECKS", "250"))  # бюджет полных проверок НА СПИСОК
CHECK_ALL = os.environ.get("CHECK_ALL", "0") == "1"  # 1 = проверять ВСЕХ кандидатов без бюджета
HS_POOL = int(os.environ.get("HS_POOL", "400"))      # сколько кандидатов проходит хендшейк
CHECK_TIMEOUT   = 4
FETCH_WORKERS   = 10
HS_WORKERS      = 40
REAL_WORKERS    = 10          # одновременных туннелей (Actions: 2 ядра)
XRAY_START_WAIT = 3
STAGE_TIMEOUT   = 6
FETCH_TIMEOUT_S = int(os.environ.get("FETCH_TIMEOUT_S", "25"))
INDEX_FILE_MAX  = int(os.environ.get("INDEX_FILE_MAX", "6"))    # мегабайт на источник

PROVEN_FILE     = "proven.txt"            # золотой запас (проверено телефоном)
WHITE_FILE      = "white_subscription.txt"
BLACK_FILE      = "black_subscription.txt"

VALID_PROTOCOLS = ("vless://",)
HY2_PREFIXES    = ("hysteria2://", "hy2://")

XRAY_PATH = os.environ.get("XRAY_PATH") or (
    "./xray" if os.path.exists("./xray") else
    "./xray.exe" if os.path.exists("./xray.exe") else "xray")
SINGBOX_PATH = os.environ.get("SINGBOX_PATH") or (
    "./sing-box" if os.path.exists("./sing-box") else
    "./sing-box.exe" if os.path.exists("./sing-box.exe") else "sing-box")

# ---------- Классы серверов и SNI ----------
TRUSTED_SNIS = [
    # RU — «белые» домены
    "yandex.ru", "ya.ru", "mail.ru", "vk.com", "vkontakte.ru", "ok.ru",
    "sberbank.ru", "sber.ru", "gosuslugi.ru", "mos.ru", "nalog.gov.ru",
    "vtb.ru", "tbank.ru", "tinkoff.ru", "alfabank.ru", "gazprom.ru",
    "rbc.ru", "rambler.ru", "dzen.ru", "lenta.ru", "wildberries.ru",
    "ozon.ru", "avito.ru", "hh.ru", "rutube.ru", "kinopoisk.ru", "max.ru",
    # мировые крупные
    "stripe.com", "paypal.com", "checkout.com", "adyen.com",
    "braintreepayments.com", "worldpay.com", "skrill.com", "neteller.com",
    "payoneer.com", "authorize.net", "klarna.com", "shopify.com",
    "swift.com", "revolut.com", "wise.com", "visa.com", "mastercard.com",
    "americanexpress.com", "hsbc.com", "chase.com", "binance.com",
    "coinbase.com", "kraken.com", "tesla.com", "apple.com", "icloud.com",
    "microsoft.com", "samsung.com", "nike.com", "ikea.com",
    "www.google.com", "google.com", "www.youtube.com", "youtube.com",
    "www.cloudflare.com", "cloudflare.com", "www.amazon.com", "www.yahoo.com",
    "www.bing.com", "duckduckgo.com", "cdn.jsdelivr.net", "telegram.org",
    "www.nvidia.com", "www.ea.com", "steamcommunity.com", "store.steampowered.com",
]

def is_white_sni(sni):
    sni = (sni or "").lower()
    if not sni:
        return False
    if sni.endswith((".ru", ".su", ".xn--p1ai", ".xn--p1acf", ".moscow")):
        return True
    return any(t in sni for t in TRUSTED_SNIS)

COUNTRY_PATTERNS = {
    "DE": ["🇩🇪", "germany", "deutschland", "frankfurt", "munich", "münchen", "berlin", "hessen", "bayern", "nürnberg", "dusseldorf", "düsseldorf", "falkenstein", "nuremberg"],
    "FI": ["🇫🇮", "finland", "suomi", "helsinki", "tampere", "espoo"],
    "US": ["🇺🇸", "usa", "united states", "united-states", "new york", "new-york", "california", "texas", "los angeles", "chicago", "miami", "seattle", "san jose", "dallas", "ashburn", "virginia", "phoenix", "atlanta"],
    "NL": ["🇳🇱", "netherlands", "holland", "amsterdam"],
    "SE": ["🇸🇪", "sweden", "stockholm"],
    "NO": ["🇳🇴", "norway", "oslo"],
    "GB": ["🇬🇧", "uk", "britain", "london", "england"],
    "FR": ["🇫🇷", "france", "paris"],
    "CA": ["🇨🇦", "canada", "toronto", "vancouver", "montreal"],
    "PL": ["🇵🇱", "poland", "warsaw", "gdansk"],
    "LV": ["🇱🇻", "latvia", "riga"],
    "LT": ["🇱🇹", "lithuania", "vilnius"],
    "EE": ["🇪🇪", "estonia", "tallinn"],
    "TR": ["🇹🇷", "turkey", "istanbul"],
    "KZ": ["🇰🇿", "kazakhstan", "almaty", "astana"],
    "JP": ["🇯🇵", "japan", "tokyo", "osaka"],
    "SG": ["🇸🇬", "singapore"],
    "HK": ["🇭🇰", "hong kong", "hongkong"],
    "AE": ["🇦🇪", "uae", "dubai"],
    "CH": ["🇨🇭", "switzerland", "zurich", "zürich"],
    "AT": ["🇦🇹", "austria", "vienna", "wien"],
}
_CODE_RE = re.compile(r"(?:^|[^a-zа-я])(fi|nl|us|de|se|no|gb|fr|ca|pl|lv|lt|ee|tr|kz|jp|sg|hk|ae|ch|at)(?:[^a-zа-я]|$)")

def detect_country(link, sni=""):
    fragment = unquote(link.split("#", 1)[1].lower()) if "#" in link else ""
    texts = [fragment, (sni or "").lower()]
    for country, patterns in COUNTRY_PATTERNS.items():
        if any(p in t for t in texts if t for p in patterns):
            return country
    m = _CODE_RE.search(fragment)
    if m:
        return m.group(1).upper()
    return "OTHER"

# ---------- Сеть / утилиты ----------
CF_RANGES = [ipaddress.ip_network(n) for n in [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]]
RUSSIAN_PREFIXES = [
    "5.42.", "5.43.", "5.101.", "5.130.", "5.143.", "5.187.", "5.188.", "31.28.", "31.31.", "31.40.",
    "31.43.", "31.134.", "31.162.", "31.173.", "37.18.", "37.29.", "37.110.", "37.140.", "37.143.",
    "37.192.", "37.235.", "45.8.", "45.9.", "45.12.", "45.66.", "45.67.", "45.81.", "45.86.",
    "45.89.", "45.90.", "45.95.", "45.130.", "45.132.", "45.135.", "45.141.", "45.142.", "45.145.",
    "45.155.", "45.156.", "46.3.", "46.8.", "46.17.", "46.38.", "46.39.", "46.146.", "46.147.",
    "46.148.", "46.161.", "46.182.", "46.242.", "51.124.", "51.250.", "62.33.", "62.76.", "62.109.",
    "62.117.", "62.148.", "62.152.", "62.213.", "77.37.", "77.41.", "77.51.", "77.72.", "77.73.",
    "77.74.", "77.82.", "77.108.", "77.220.", "77.222.", "77.232.", "77.242.", "77.244.", "78.25.",
    "78.29.", "78.36.", "78.37.", "78.81.", "78.85.", "78.108.", "78.109.", "78.140.", "79.104.",
    "79.111.", "79.120.", "79.133.", "79.134.", "79.137.", "79.143.", "79.174.", "80.64.", "80.68.",
    "80.78.", "80.80.", "80.82.", "80.83.", "80.87.", "80.92.", "80.93.",
]

_dns_cache = {}
def resolve(host):
    if host in _dns_cache:
        return _dns_cache[host]
    try:
        ip = host if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) else socket.gethostbyname(host)
    except Exception:
        ip = None
    _dns_cache[host] = ip
    return ip

def is_cf_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in CF_RANGES)
    except Exception:
        return False

def is_russian_ip(ip_or_domain):
    if not ip_or_domain:
        return False
    target = resolve(ip_or_domain)
    if not target:
        return True
    if any(target.startswith(p) for p in RUSSIAN_PREFIXES):
        return True
    try:
        first = int(target.split(".")[0])
        if 91 <= first <= 95 or first in (176, 178, 185, 188, 212, 213) or 193 <= first <= 195:
            return True
    except Exception:
        pass
    return ip_or_domain.endswith((".ru", ".su", ".by", ".рф"))

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

def extract_info(line):
    try:
        parsed = urlparse(line)
        host, port, user = parsed.hostname, parsed.port, parsed.username
        if not host or not port:
            tail = line.split("://", 1)[1]
            user = tail.split("@", 1)[0]
            hostport = tail.split("@", 1)[1].split("/", 1)[0].split("?", 1)[0]
            host, port = hostport.rsplit(":", 1)
            port = int(port)
        q = parse_qs(parsed.query)
        g = lambda k, d="": (q.get(k, [d]) or [d])[0]
        info = {
            "host": host, "port": int(port), "uuid": user or "",
            "sni": g("sni").lower(), "security": g("security", "none"),
            "net": g("type", "tcp"), "path": unquote(g("path", "/")),
            "host_header": g("host", ""), "pbk": g("pbk"), "sid": g("sid"),
            "fp": g("fp", "chrome"), "flow": g("flow"),
            "serviceName": g("serviceName"),
            "obfs": g("obfs"), "obfs_password": g("obfs-password"),
            "proto": "vless",
        }
        if line.startswith(HY2_PREFIXES):
            info["proto"] = "hy2"
            info["security"] = "hy2"
            info["uuid"] = unquote(line.split("://", 1)[1].split("@", 1)[0])
        return info
    except Exception:
        return None

def server_key(info):
    return f"{info['uuid']}|{info['host']}|{info['port']}"

def white_ok(info):
    """БЕЛЫЙ, режим CHECK_ALL: пропускаем ВСЁ (кроме заведомых помоек).
    Фильтры SNI/портов убраны — правильность решает полная проверка
    (Telegram + контент), а не догадки о режиме оператора."""
    return True

# ================== СКАЧИВАНИЕ ==================
def smart_decode(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if any(line.startswith(p) for p in VALID_PROTOCOLS + HY2_PREFIXES):
            out.append(line)
            continue
        t = line
        decoded = False
        for _ in range(3):
            try:
                pad = "=" * (-len(t) % 4)
                dec = base64.b64decode(t + pad).decode("utf-8", errors="ignore")
            except Exception:
                break
            if not dec:
                break
            found = re.findall(r"(?:vless|hysteria2|hy2)://[^\s<>\"'`,]+", dec)
            if found:
                out.extend(x.strip() for x in found)
                decoded = True
                break
            t = dec.strip()
            if not t:
                break
        if not decoded and "://" in line:
            out.extend(re.findall(r"(?:vless|hysteria2|hy2)://[^\s<>\"'`,]+", line))
    return "\n".join(out)

def fetch_raw(url):
    """Скачивает файл (расширение не важно). Возвращает текст или ''. """
    try:
        r = requests.get(url, timeout=FETCH_TIMEOUT_S, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return r.text[:INDEX_FILE_MAX * 1_000_000].lstrip("\ufeff")
    except Exception:
        pass
    return ""

def fetch_one(url):
    t = fetch_raw(url)
    return smart_decode(t) if t else ""

def get_site_mirrors():
    """Со страницы сайта собирает зеркала /whitelist и /blacklist."""
    try:
        r = requests.get(SITE_PAGE, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
        html = r.text if r.status_code == 200 else ""
    except Exception:
        html = ""
    white = sorted(set(u for u in re.findall(r'https?://[^"\'\s ]+', html)
                       if "/whitelist" in u and "translate" not in u and not u.endswith(".yaml")))
    black = sorted(set(u for u in re.findall(r'https?://[^"\'\s ]+', html)
                       if "blacklist" in u and "translate" not in u and not u.endswith(".yaml")))
    return white, black

# ================== ПАРСИНГ ==================
def parse_sources(texts, used_keys, ip_count, subnet_count, is_white):
    candidates = []
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            if not (line.startswith(VALID_PROTOCOLS) or (is_white and line.startswith(HY2_PREFIXES))):
                continue
            info = extract_info(line)
            if not info:
                continue
            if info["proto"] == "vless" and not UUID_RE.fullmatch(info["uuid"] or ""):
                continue
            if info["proto"] == "hy2" and not (info["uuid"] or "").strip():
                continue
            if not info["host"] or not (0 < info["port"] < 65536):
                continue
            if info["proto"] == "vless" and info["security"] == "reality" and (not info["pbk"] or len(info["pbk"]) < 40):
                continue
            if is_white:
                if not white_ok(info):
                    continue
            else:
                if is_russian_ip(info["host"]):
                    continue
            key = server_key(info)
            if key in used_keys:
                continue
            ip = resolve(info["host"]) or info["host"]
            if ip_count.get(ip, 0) >= 2:
                continue
            subnet = ".".join(ip.split(".")[:3]) + ".x" if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) else ip
            if subnet_count.get(subnet, 0) >= 4:
                continue
            used_keys.add(key)
            ip_count[ip] = ip_count.get(ip, 0) + 1
            subnet_count[subnet] = subnet_count.get(subnet, 0) + 1
            candidates.append({
                "line": line, "info": info, "key": key,
                "has_trusted": any(t in (info["sni"] or "") for t in TRUSTED_SNIS),
                "country": detect_country(line, info["sni"]),
            })
    return candidates

# ================== ПРОВЕРКИ ==================
def handshake_check(cand):
    info = cand["info"]
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((info["host"], info["port"]), timeout=CHECK_TIMEOUT)
        if info["security"] in ("tls", "reality", "xtls"):
            ctx = ssl._create_unverified_context()
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=0")
            except Exception:
                pass
            sock.settimeout(CHECK_TIMEOUT)
            try:
                ctx.wrap_socket(sock, server_hostname=info["sni"] or info["host"]).close()
            except Exception:
                if info["security"] != "reality":
                    return None
        cand["hs_score"] = time.monotonic() - t0
        return cand
    except Exception:
        return None

def vless_to_xray_config(info, local_port):
    user_obj = {"id": info["uuid"], "encryption": "none"}
    if info["flow"]:
        user_obj["flow"] = info["flow"]
    net = info["net"] or "tcp"
    if net == "raw":
        net = "tcp"
    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": info["host"], "port": info["port"], "users": [user_obj]}]},
        "streamSettings": {"network": net, "security": info["security"] or "none"},
    }
    ss = outbound["streamSettings"]
    if info["security"] == "reality":
        ss["realitySettings"] = {
            "serverName": info["sni"] or info["host"], "fingerprint": info["fp"] or "chrome",
            "publicKey": info["pbk"], "shortId": info["sid"] or "", "spiderX": "/",
        }
    elif info["security"] == "tls":
        ss["tlsSettings"] = {"serverName": info["sni"] or info["host"],
                             "fingerprint": info["fp"] or "chrome"}
    if net == "ws":
        ss["wsSettings"] = {"path": info["path"] or "/",
                            "headers": {"Host": info["host_header"] or info["sni"] or info["host"]}}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": info["serviceName"]}
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "http"}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }

def hy2_to_singbox_config(info, local_port):
    out = {
        "type": "hysteria2", "tag": "out",
        "server": info["host"], "server_port": info["port"],
        "password": info["uuid"],
        "tls": {"enabled": True, "server_name": info["sni"] or info["host"], "insecure": True},
    }
    if info.get("obfs"):
        out["obfs"] = {"type": info["obfs"], "password": info.get("obfs_password", "")}
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": local_port}],
        "outbounds": [out, {"type": "direct", "tag": "direct"}],
    }

def wait_for_port(port, proc, timeout):
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return True
        except Exception:
            time.sleep(0.15)
    return False

def _proxies(port):
    p = f"http://127.0.0.1:{port}"
    return {"http": p, "https": p}

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

SPEED_URL = "https://speed.cloudflare.com/__down?bytes=10000000"

def measure_speed(local_port, max_bytes=10_000_000, max_time=12.0):
    total, t0 = 0, time.monotonic()
    try:
        with requests.get(SPEED_URL, proxies=_proxies(local_port),
                          timeout=(5, 15), headers=UA, stream=True) as r:
            if r.status_code != 200:
                return 0.0
            for chunk in r.iter_content(chunk_size=16384):
                total += len(chunk)
                if total >= max_bytes or time.monotonic() - t0 > max_time:
                    break
    except Exception:
        pass
    dt = time.monotonic() - t0
    return total / 1024 / dt if dt > 0.05 and total > 50_000 else 0.0

BLACK_TARGETS = [
    ("https://web.telegram.org/k/", b"telegram", 3000),
    ("https://www.youtube.com/", b"<title>youtube", 15000),
    ("https://www.wikipedia.org/", b"wikimedia", 5000),
]
WHITE_TARGETS = [
    ("https://web.telegram.org/k/", b"telegram", 3000),
    ("https://www.instagram.com/", b"instagram", 8000),
    ("https://github.com/", b"GitHub", 5000),
]
BLOCK_MARKERS = [b"access denied", b"forbidden", b"unavailable for legal reasons",
                 "заблокирован".encode(), "доступ ограничен".encode()]

def real_check(cand, local_port, is_white, light=False):
    info = cand["info"]
    if info["proto"] == "hy2":
        cfg = hy2_to_singbox_config(info, local_port)
        engine, eng = [SINGBOX_PATH, "run", "-c"], "sing-box"
    else:
        cfg = vless_to_xray_config(info, local_port)
        engine, eng = [XRAY_PATH, "run", "-c"], "xray"
    cfg_path = f"/tmp/check_cfg_{local_port}.json"
    proc = None
    try:
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        proc = subprocess.Popen(engine + [cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                preexec_fn=os.setsid)
        if not wait_for_port(local_port, proc, XRAY_START_WAIT):
            return False, None, 0, (f"{eng} не поднял порт (битая ссылка)" if proc.poll() is not None else f"{eng} не поднял порт")
        if not light:
            try:
                r = requests.get("http://www.gstatic.com/generate_204", proxies=_proxies(local_port),
                                 timeout=STAGE_TIMEOUT, headers=UA)
                if r.status_code != 204:
                    return False, None, 0, f"http204 -> {r.status_code}"
            except Exception as e:
                return False, None, 0, f"http204 fail ({type(e).__name__})"
        t0 = time.monotonic()
        try:
            r = requests.get("https://www.gstatic.com/generate_204", proxies=_proxies(local_port),
                             timeout=STAGE_TIMEOUT, headers=UA)
        except Exception as e:
            return False, None, 0, f"https204 fail ({type(e).__name__})"
        if r.status_code != 204:
            return False, None, 0, f"https204 -> {r.status_code}"
        latency = time.monotonic() - t0

        targets = WHITE_TARGETS if is_white else BLACK_TARGETS
        tg_url, tg_marker, tg_min = targets[0]
        try:
            r = requests.get(tg_url, proxies=_proxies(local_port),
                             timeout=STAGE_TIMEOUT + 3, headers=UA)
            if r.status_code != 200:
                return False, None, 0, f"telegram -> {r.status_code}"
            low = r.content[:200000].lower()
            if len(r.content) < tg_min or tg_marker not in low:
                return False, None, 0, "telegram: не настоящая страница"
        except Exception as e:
            return False, None, 0, f"telegram fail ({type(e).__name__})"

        kbps, content_ok, last_reason = 0.0, False, "content fail"
        for url, marker, min_size in targets[1:]:
            try:
                t1 = time.monotonic()
                r = requests.get(url, proxies=_proxies(local_port), timeout=STAGE_TIMEOUT + 3, headers=UA)
                dt = time.monotonic() - t1
                if r.status_code != 200:
                    last_reason = f"{url.split('/')[2]} -> {r.status_code}"
                    continue
                content = r.content
                low = content[:200000].lower()
                if len(content) < min_size:
                    last_reason = f"{url.split('/')[2]} мал ({len(content)}B)"
                    continue
                if marker.lower() not in low:
                    last_reason = f"{url.split('/')[2]} нет маркера"
                    continue
                if any(b in low for b in BLOCK_MARKERS):
                    last_reason = f"{url.split('/')[2]} страница блокировки"
                    continue
                kbps = max(kbps, len(content) / 1024 / max(dt, 0.01))
                content_ok = True
                break
            except Exception as e:
                last_reason = f"{url.split('/')[2]} fail ({type(e).__name__})"
        if not content_ok:
            return False, None, 0, last_reason

        sp = measure_speed(local_port)
        if sp > 0:
            kbps = sp
        return True, latency, kbps, ""
    except Exception as e:
        return False, None, 0, f"exc ({type(e).__name__})"
    finally:
        if proc:
            try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception: pass
            try: proc.wait(timeout=1)
            except Exception: pass
        try: os.remove(cfg_path)
        except Exception: pass

def verify_candidates(cands, is_white, light=False, limit=None):
    """Проверяет всех (волнами по 2*REAL_WORKERS). Возвращает живых."""
    verified = []
    pool = list(cands)
    checks = 0
    wave_size = REAL_WORKERS * 2
    while pool:
        if limit is not None and checks >= limit:
            print(f"    [*] Бюджет {limit} проверок исчерпан (осталось кандидатов: {len(pool)}).")
            break
        wave, pool = pool[:wave_size], pool[wave_size:]
        if limit is not None:
            wave = wave[:limit - checks]
        if not wave:
            break
        checks += len(wave)
        def one(idx_item):
            idx, cand = idx_item
            ok, latency, kbps, reason = real_check(cand, 15000 + idx, is_white, light=light)
            return cand, ok, latency, kbps, reason
        with ThreadPoolExecutor(max_workers=REAL_WORKERS) as ex:
            for cand, ok, latency, kbps, reason in ex.map(one, enumerate(wave)):
                if ok:
                    verified.append({**cand, "latency": latency, "kbps": kbps})
                    print(f"    [+] {cand['country']:3s} | {kbps:8.1f} KB/s | {cand['info']['host']}:{cand['info']['port']}")
                else:
                    print(f"    [-] {cand['country']:3s} | {reason:34s} | {cand['info']['host']}:{cand['info']['port']}")
    return verified

# ================== ФАЙЛЫ ==================
def read_lines_file(filename):
    if not os.path.exists(filename):
        return []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [l.strip() for l in f.read().splitlines() if l.strip() and not l.strip().startswith("#")]
    except Exception:
        return []

FM_FRAGMENT = {"tcp": [{"type": "fragment", "settings": {
    "packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}}]}

def ensure_fragment(link):
    if "fm=" in link:
        return link
    payload = "fm=" + quote(json.dumps(FM_FRAGMENT, separators=(",", ":")))
    head, frag = (link.split("#", 1) + [""])[:2]
    head = head + ("&" if "?" in head else "?") + payload
    return head + (("#" + frag) if frag else "")

def write_subscription(filename, title, servers, is_white=False, protected=None):
    protected = protected or set()
    if is_white:
        out = []
        for l in servers:
            if l in protected:
                out.append(l)
                continue
            is_hy2 = l.startswith(HY2_PREFIXES)
            i = extract_info(l)
            if (not is_hy2) and i and i["security"] != "reality":
                l = ensure_fragment(l)
            out.append(l)
        servers = out
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"#profile-title: {title}\n#updated: {time.strftime('%Y-%m-%d %H:%M')} UTC\n"
                "#verified: xray+204+telegram-web+content+speed\n\n" + "\n".join(servers) + "\n")

# ================== СПИСОК ==================
def process_list(is_white):
    name = "БЕЛЫЙ" if is_white else "ЧЁРНЫЙ"
    print(f"\n{'='*60}\n[*] {name} СПИСОК\n{'='*60}")

    # --- 1. Зеркала с сайта ---
    site_white, site_black = get_site_mirrors()
    if is_white:
        mirrors = list(dict.fromkeys((site_white or []) + FALLBACK_WHITE))
    else:
        mirrors = list(dict.fromkeys((site_black or []) + FALLBACK_BLACK))
    print(f"[*] Зеркал из раздела сайта: {len(mirrors)}")
    for m in mirrors:
        print(f"    {m}")

    # --- 2. Скачиваем все файлы ---
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        texts = [t for t in ex.map(fetch_one, mirrors) if t]
    print(f"[+] Файлов скачано: {len(texts)}/{len(mirrors)}")

    # --- 3. Кандидаты ---
    candidates = parse_sources(texts, set(), {}, {}, is_white)
    print(f"[+] Зарубежных кандидатов: {len(candidates)}")

    # --- 4. proven.txt — золотой запас, проверяем первыми ---
    proven_verified, proven_lines = [], set()
    proven_lines_raw = read_lines_file(PROVEN_FILE)
    if proven_lines_raw:
        pseen, proven_cands = set(), []
        for line in proven_lines_raw:
            info = extract_info(line)
            if not info:
                continue
            if line.startswith(HY2_PREFIXES) and not (info["uuid"] or "").strip():
                continue
            if info["proto"] == "vless" and not UUID_RE.fullmatch(info["uuid"] or ""):
                continue
            k = server_key(info)
            if k in pseen:
                continue
            pseen.add(k)
            proven_lines.add(line)
            proven_cands.append({"line": line, "info": info, "key": k, "has_trusted": True,
                                 "country": detect_country(line, info["sni"])})
        if proven_cands:
            print(f"\n[*] PROVEN: перепроверяю {len(proven_cands)} серверов из proven.txt...")
            proven_verified = verify_candidates(proven_cands, is_white, light=True)
            print(f"[+] PROVEN живых: {len(proven_verified)} — идут первыми")

    # --- 5. Хендшейк (быстрый отсев мёртвых TCP) ---
    pv_keys = {v["key"] for v in proven_verified}
    rest = [c for c in candidates if c["key"] not in pv_keys]
    if is_white:   # hy2 = QUIC, TCP-хендшейк не нужен
        hy2_pool = [c for c in rest if c["info"]["proto"] == "hy2"]
        rest = [c for c in rest if c["info"]["proto"] != "hy2"]
    else:
        hy2_pool = []
    random.shuffle(rest)
    print(f"\n[*] Хендшейк {min(len(rest), 400)} кандидатов...")
    hs_passed = []
    with ThreadPoolExecutor(max_workers=HS_WORKERS) as ex:
        for r in ex.map(handshake_check, rest if CHECK_ALL else rest[:HS_POOL]):
            if r:
                hs_passed.append(r)
    hs_passed.sort(key=lambda c: c.get("hs_score", 9))
    if hy2_pool:
        # чередуем классы 1:1 — hy2 и vless не вытесняют друг друга
        mixed, a, b = [], list(hy2_pool), list(hs_passed)
        while a or b:
            if a: mixed.append(a.pop(0))
            if b: mixed.append(b.pop(0))
        hs_passed = mixed
    print(f"[+] Прошли хендшейк: {len(hs_passed)} (+hy2 без хендшейка: {len(hy2_pool)})")

    # --- 6. Полная проверка: ВСЕ, кого влезло в бюджет ---
    if CHECK_ALL:
        print(f"\n[*] Полная проверка ВСЕХ {len(hs_passed)} кандидатов (CHECK_ALL=1)...")
        new_verified = verify_candidates(hs_passed, is_white, light=False, limit=None)
    else:
        print(f"\n[*] Полная проверка (бюджет {MAX_REAL_CHECKS})...")
        new_verified = verify_candidates(hs_passed, is_white, light=False, limit=MAX_REAL_CHECKS)

    # --- 7. Итог: proven первыми, затем ВСЕ живые по скорости ---
    all_verified = proven_verified + [v for v in new_verified if v["key"] not in pv_keys]
    all_verified.sort(key=lambda v: -(v.get("kbps") or 0))
    print(f"\n[+] Итог {name}: живых {len(all_verified)} (proven: {len(proven_verified)})")
    if all_verified:
        write_subscription(WHITE_FILE if is_white else BLACK_FILE,
                           "Белый список (РКН)" if is_white else "Чёрный список (РКН)",
                           [v["line"] for v in all_verified], is_white,
                           protected=proven_lines)
        print(f"[+] {WHITE_FILE if is_white else BLACK_FILE} ЗАПИСАН: {len(all_verified)} серверов")
    else:
        print(f"[!] Ни одного живого — файл не трогаю (старый сохранён).")

# ================== MAIN ==================
def main():
    t0 = time.monotonic()
    print("[*] Парсер v23.1: ЭтоНеЯ-зеркала (10 шт., вкл. gitverse) + Reality любых портов + CHECK_ALL")
    if os.environ.get("CHECK_ALL") == "1":
        print("[*] РЕЖИМ CHECK_ALL=1: глубокая проверка ВСЕХ кандидатов (без бюджета)")
    if not (os.path.exists(XRAY_PATH) or shutil.which(XRAY_PATH)):
        print("[!] xray не найден — выход. Положи xray (xray.exe) рядом с checker.py.")
        return
    if not (os.path.exists(SINGBOX_PATH) or shutil.which(SINGBOX_PATH)):
        print("[!] sing-box не найден: hysteria2 проверяться НЕ будут.")
    try:
        process_list(True)     # белый
        process_list(False)    # чёрный
    except KeyboardInterrupt:
        print("\n[!] Прервано.")
    print(f"\n[*] Общее время: {time.monotonic() - t0:.1f} сек")

if __name__ == "__main__":
    main()
