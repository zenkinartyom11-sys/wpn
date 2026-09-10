# -*- coding: utf-8 -*-
"""
ПАРСЕР v21 — «железобетонная» проверка для 2 подписок.
PROVEN: файл proven.txt (корень репо) — серверы, проверенные вручную на телефоне.
Они всегда проходят полную проверку и идут в подписку ПЕРВЫМИ; ссылки из proven.txt
не модифицируются. Фильтр стран: выключен по умолчанию (на МТС жёсткий FI/NL/US/DE
дал 0 рабочих), квоты стран работают как приоритет при выборе.
БЕЛЫЙ (полностью новая логика): источники — специализированные белые списки
(Subzio, zieng2/wl, igareck). Классы: hysteria2 с белым SNI (проверка через
sing-box), vless Reality с белым SNI (.ru и крупные мировые) на 443, запас —
vless TLS за Cloudflare 443 (в ссылку добавляется fm= фрагментация).
Все кандидаты: 4 проверки + замер РЕАЛЬНОЙ скорости; в файл — топ-10 быстрых,
приоритет «родным» для белых списков классам.
ЧЁРНЫЙ: как в v17 — xray, Telegram обязателен, квоты DE/FI/US, Reality/443.

Что исправлено по сравнению с v15 (причины мёртвых серверов в подписке):
  1. РАНЬШЕ: старые серверы возвращались в файл после одного TCP/TLS хендшейка
     (merge_new_and_old) — хендшейк НЕ проверяет, что сервер пропускает трафик.
     ТЕПЕРЬ: старые серверы проходят ПОЛНУЮ проверку заново каждый запуск.
     Не прошёл — заменяется (рабочие остаются, нерабочие заменяются).
  2. РАНЬШЕ: новый сервер проверялся 1 раз — флапающий сервер мог пройти 1 раз
     и висеть в файле час. ТЕПЕРЬ: новый кандидат обязан пройти 3 независимых
     проверки (HTTP-204 + HTTPS-204 + загрузка реального контента).
  3. РАНЬШЕ: проверялись только первые 40 кандидатов — если они умирали,
     дозабора не было, и в файл попадали «старые» по хендшейку.
     ТЕПЕРЬ: волны дозабора, пока не наберётся нужное число живых.
  4. РАНЬШЕ: несколько ссылок могли указывать на один IP — умирает IP,
     умирают 3-4 места сразу. ТЕПЕРЬ: не более 2 серверов на один IP.
  5. Белые списки: серверы на нестандартных портах не работают в режиме
     «белых списков» на мобильном интернете — оставляем только 443/80 и
     Cloudflare-порты; приоритет доверенному SNI и Cloudflare-IP.
  6. Диагностика: печатается ПРИЧИНА, почему сервер забракован.

Без сторонних сайтов-геолокаторов: страна определяется по имени/SNI.
Проверка — только xray + реальные запросы через поднятый туннель.
"""

import ssl, socket, requests, time, base64, re, random, json, subprocess, os, signal, shutil, ipaddress
from urllib.parse import urlparse, parse_qs, unquote, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ================== НАСТРОЙКИ ==================
TARGET_COUNT    = 10          # сколько серверов в каждой подписке
CHECK_TIMEOUT   = 4           # сек, TCP/TLS хендшейк
FETCH_WORKERS   = 10          # потоков на скачивание источников
HS_WORKERS      = 40          # потоков на хендшейки
REAL_WORKERS    = 10          # xray-инстансов одновременно (Actions: 2 ядра)
XRAY_START_WAIT = 3           # ждём поднятия inbound (с ранним выходом при ошибке)
STAGE_TIMEOUT   = 6           # таймаут ОДНОГО запроса через туннель
MAX_REAL_CHECKS = int(os.environ.get("MAX_REAL_CHECKS", "100"))  # бюджет: сколько НОВЫХ кандидатов максимум реально проверять на список
RESERVE_EXTRA   = 4           # проверяем на 4 больше, чем нужно (резерв на выбор по странам)

STATE_FILE      = "state.json"          # история проверок (коммитится в репо)
WHITE_FILE      = "white_subscription.txt"
BLACK_FILE      = "black_subscription.txt"
PROVEN_FILE     = "proven.txt"     # серверы, проверенные ВРУЧНУЮ на телефоне — приоритет №1

# ========== СТРАНЫ ==========
# ЖЁСТКИЙ фильтр: впиши страны, и все остальные будут отбрасываться до проверок.
# ПУСТО = фильтр выключен. На МТС жёсткий "FI/NL/US/DE по имени" дал 0 рабочих
# (именованные страны в публичных списках — самые заблокированные IP), поэтому
# по умолчанию выключен; квоты ниже продолжают работать как ПРИОРИТЕТ.
ALLOWED_COUNTRIES = set()

# Квоты для ЧЁРНОГО списка (раскладка 10 мест; недобор добирается из
# оставшихся разрешённых стран по скорости). Белый: просто топ по скорости.
PRIORITY_QUOTAS = {"DE": 3, "FI": 3, "NL": 2, "US": 2}

VALID_PROTOCOLS = ("vless://",)
HY2_PREFIXES = ("hysteria2://", "hy2://")   # только для БЕЛОГО списка (проверка через sing-box)

# Доверенные SNI для БЕЛОГО списка: крупные РФ-домены + платёжные/мировые
TRUSTED_SNIS = [
    # Россия — основные
    "yandex.ru", "ya.ru", "mail.ru", "vk.com", "vkontakte.ru", "ok.ru",
    "sberbank.ru", "sber.ru", "gosuslugi.ru", "mos.ru", "nalog.gov.ru",
    "vtb.ru", "tbank.ru", "tinkoff.ru", "alfabank.ru", "gazprom.ru",
    "rbc.ru", "rambler.ru", "dzen.ru", "lenta.ru", "wildberries.ru",
    "ozon.ru", "avito.ru", "hh.ru", "rutube.ru", "sportmaster.ru",
    # Платёжные / мировые (обычно в белых списках операторов)
    "stripe.com", "paypal.com", "checkout.com", "adyen.com",
    "braintreepayments.com", "worldpay.com", "skrill.com", "neteller.com",
    "payoneer.com", "authorize.net", "klarna.com", "shopify.com",
    "swift.com", "revolut.com", "wise.com", "visa.com", "mastercard.com",
    "americanexpress.com", "hsbc.com", "chase.com", "binance.com",
    "coinbase.com", "kraken.com", "tesla.com", "apple.com", "icloud.com",
    "microsoft.com", "samsung.com", "nike.com", "ikea.com",
]

def is_white_sni(sni):
    """SNI, который ТСПУ пропускает в режиме белых списков: RU-зоны + крупные известные."""
    sni = (sni or "").lower()
    if not sni:
        return False
    if sni.endswith((".ru", ".su", ".xn--p1ai", ".xn--p1acf", ".moscow", ".москва")):
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

# Диапазоны Cloudflare (чтобы узнавать CF-фронт без сторонних сервисов)
CF_RANGES = [ipaddress.ip_network(n) for n in [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]]

# БЕЛЫЙ v18: только 443 (см. white_ok)

# RU-префиксы (для ЧЁРНОГО списка: РФ-выходы не нужны)
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

# ============ ИСТОЧНИКИ ============
URLS_WHITE = [
    # --- специализированные белые списки (RU mobile) ---
    "https://raw.githubusercontent.com/Subzio/subzio/main/WHITE_LIST_PROXY_COLLECTION.txt",
    "https://raw.githubusercontent.com/Subzio/subzio/main/HYSTERIA2.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    # --- общие агрегаторы (CF+443 как запасной класс) ---
    "https://raw.githubusercontent.com/HenonBank/Russia_LTE/refs/heads/main/v2ray_sub.txt",
    "https://raw.githubusercontent.com/Ai123999/WhiteKeys/refs/heads/main/WhiteKeys",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
]
URLS_BLACK = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/refs/heads/main/Config_jo.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/refs/heads/main/deploy/subscriptions/11.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/refs/heads/main/deploy/subscriptions/1.txt",
    # резервные крупные агрегаторы (если основных мало живых)
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
]

XRAY_PATH = os.environ.get("XRAY_PATH") or (
    "./xray" if os.path.exists("./xray") else
    "./xray.exe" if os.path.exists("./xray.exe") else "xray")
SINGBOX_PATH = os.environ.get("SINGBOX_PATH") or (
    "./sing-box" if os.path.exists("./sing-box") else
    "./sing-box.exe" if os.path.exists("./sing-box.exe") else "sing-box")

_dns_cache = {}
def resolve(host):
    if host in _dns_cache:
        return _dns_cache[host]
    ip = None
    try:
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            ip = host
        else:
            ip = socket.gethostbyname(host)
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
    target_ip = resolve(ip_or_domain)
    if not target_ip:
        return True  # не резолвится — не рискуем
    if any(target_ip.startswith(p) for p in RUSSIAN_PREFIXES):
        return True
    try:
        parts = target_ip.split(".")
        first = int(parts[0])
        if 91 <= first <= 95 or first in (176, 178, 185, 188, 212, 213) or 193 <= first <= 195:
            return True
    except Exception:
        pass
    return ip_or_domain.endswith((".ru", ".su", ".by", ".рф"))

_CODE_RE = re.compile(r"(?:^|[^a-zа-я])(fi|nl|us|de)(?:[^a-zа-я]|$)")

def detect_country(link, sni=""):
    fragment = unquote(link.split("#", 1)[1].lower()) if "#" in link else ""
    texts = [fragment, (sni or "").lower()]
    # сперва слова/эмодзи (точнее), затем 2-буквенные коды: "FI-1234", "US 5474", "#NL"
    for country, patterns in COUNTRY_PATTERNS.items():
        if any(p in t for t in texts if t for p in patterns):
            return country
    m = _CODE_RE.search(fragment)
    if m:
        return m.group(1).upper()
    return "OTHER"

# ================== ПАРСИНГ ИСТОЧНИКОВ ==================
def smart_decode(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if any(line.startswith(p) for p in VALID_PROTOCOLS):
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

def fetch_one(url):
    try:
        r = requests.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return smart_decode(r.text[:3_000_000].lstrip("\ufeff"))
    except Exception:
        pass
    return ""

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
        return {
            "host": host, "port": int(port), "uuid": user or "",
            "sni": g("sni").lower(), "security": g("security", "none"),
            "net": g("type", "tcp"), "path": unquote(g("path", "/")),
            "host_header": g("host", ""), "pbk": g("pbk"), "sid": g("sid"),
            "fp": g("fp", "chrome"), "flow": g("flow"),
            "serviceName": g("serviceName"), "alpn": g("alpn"),
            "obfs": g("obfs"), "obfs_password": g("obfs-password"),
            "proto": "vless",
        }
    except Exception:
        return None

def server_key(info):
    return f"{info['uuid']}|{info['host']}|{info['port']}"

def white_ok(info, line=""):
    """БЕЛЫЙ v19 — три класса, которые реально живут в режиме белых списков:
    1) hysteria2 с белым SNI (vk.com и т.п.) — QUIC/UDP, ТСПУ так просто не режет;
    2) vless REALITY с белым SNI (.ru / крупный мировой) на 443;
    3) vless TLS за Cloudflare на 443 (запасной класс, в ссылку добавится fm=)."""
    if info["proto"] == "hy2":
        return bool(is_white_sni(info["sni"]))
    if info["port"] != 443:
        return False
    if info["security"] == "reality":
        return is_white_sni(info["sni"])
    ip = resolve(info["host"])
    return bool(ip and is_cf_ip(ip))

def parse_sources(texts, used_keys, ip_count, subnet_count, is_white):
    candidates, seen = [], set()
    for line in text_join(texts).splitlines():
        line = line.strip()
        is_hy2 = is_white and line.startswith(HY2_PREFIXES)
        if not (line.startswith(VALID_PROTOCOLS) or is_hy2):
            continue
        info = extract_info(line)
        if not info:
            continue
        if is_hy2:
            info["proto"] = "hy2"
            info["security"] = "hy2"
            try:                                  # пароль hysteria2 = userinfo до @
                pwd = unquote(line.split("://", 1)[1].split("@", 1)[0])
            except Exception:
                continue
            if not pwd:
                continue
            info["uuid"] = pwd
        else:
            if not UUID_RE.fullmatch(info["uuid"]):
                continue
        if not info["host"] or not (0 < info["port"] < 65536):
            continue
        if info["proto"] == "vless" and info["security"] == "reality" and (not info["pbk"] or len(info["pbk"]) < 40):
            continue
        if is_white:
            if not white_ok(info, line):
                continue
        else:
            if is_russian_ip(info["host"]):
                continue
        key = server_key(info)
        if key in seen or key in used_keys:
            continue
        ip = resolve(info["host"]) or info["host"]
        if ip_count.get(ip, 0) >= 2:      # не больше 2 серверов на один IP
            continue
        subnet = ".".join(ip.split(".")[:3]) + ".x" if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) else ip
        if subnet_count.get(subnet, 0) >= 4:   # и не больше 4 на подсеть /24
            continue
        seen.add(key); used_keys.add(key)
        ip_count[ip] = ip_count.get(ip, 0) + 1
        subnet_count[subnet] = subnet_count.get(subnet, 0) + 1
        candidates.append({
            "line": line, "info": info, "key": key,
            "has_trusted": any(t in (info["sni"] or "") for t in TRUSTED_SNIS),
            "country": detect_country(line, info["sni"]),
        })
    return candidates

def text_join(texts):
    return "\n".join(t for t in texts if t)

# ================== ЭТАП 1: ХЕНДШЕЙК ==================
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
                    return None   # reality может не отвечать на «пустой» TLS — не бракуем
        score = time.monotonic() - t0
        cand["hs_score"] = score
        return cand
    except Exception:
        return None

# ============ ЭТАП 2: КОНФИГИ (xray для vless, sing-box для hysteria2) ============
def hy2_to_singbox_config(info, local_port):
    out = {
        "type": "hysteria2", "tag": "out",
        "server": info["host"], "server_port": info["port"],
        "password": info["uuid"],
        "tls": {"enabled": True, "server_name": info["sni"] or info["host"],
                "insecure": True},
    }
    if info.get("obfs"):
        out["obfs"] = {"type": info["obfs"], "password": info.get("obfs_password", "")}
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1",
                      "listen_port": local_port}],
        "outbounds": [out, {"type": "direct", "tag": "direct"}],
    }

def vless_to_xray_config(info, local_port):
    user_obj = {"id": info["uuid"], "encryption": "none"}
    if info["flow"]:
        user_obj["flow"] = info["flow"]
    net = info["net"] or "tcp"
    if net == "raw":          # новое имя tcp (sing-box-стиль) — xray ждёт "tcp"
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
    elif info["security"] in ("tls",):
        # ВАЖНО: без allowInsecure — новые Xray-core (25+) его удалили,
        # конфиг с ним отвергается ЦЕЛИКОМ (раньше это ломало массу проверок)
        ss["tlsSettings"] = {"serverName": info["sni"] or info["host"],
                             "fingerprint": info["fp"] or "chrome"}
    if (info["net"] or "tcp") == "ws":
        ss["wsSettings"] = {"path": info["path"] or "/",
                            "headers": {"Host": info["host_header"] or info["sni"] or info["host"]}}
    elif info["net"] == "grpc":
        ss["grpcSettings"] = {"serviceName": info["serviceName"]}
    return {
        "log": {"loglevel": "none"},
        # ВАЖНО: без "settings" — новые Xray-core (25+) отвергают allowTransparent
        "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "http"}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }

def wait_for_port(port, proc, timeout):
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if proc.poll() is not None:      # xray упал (битый конфиг) — не ждём
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.4):
                return True
        except Exception:
            time.sleep(0.15)
    return False

# Цели загрузки контента: (url, маркер, минимальный размер).
# ПЕРВАЯ цель — ОБЯЗАТЕЛЬНАЯ: сервер попадает в подписку только если через
# него РЕАЛЬНО открывается Telegram (web-версия). Остальные — хотя бы одна.
BLACK_TARGETS = [
    ("https://web.telegram.org/k/", b"telegram", 3000),        # ОБЯЗАТЕЛЬНО
    ("https://www.youtube.com/", b"<title>youtube", 15000),
    ("https://www.wikipedia.org/", b"wikimedia", 5000),
]
WHITE_TARGETS = [
    ("https://web.telegram.org/k/", b"telegram", 3000),        # ОБЯЗАТЕЛЬНО
    ("https://www.instagram.com/", b"instagram", 8000),
    ("https://github.com/", b"GitHub", 5000),
]

# SNI, под которыми Reality-серверы чаще всего выживают после ТСПУ
REALITY_GOOD_SNIS = [
    "www.google.com", "google.com", "www.youtube.com", "youtube.com",
    "www.cloudflare.com", "cloudflare.com", "www.apple.com", "apple.com",
    "www.microsoft.com", "microsoft.com", "www.samsung.com", "samsung.com",
    "www.tesla.com", "tesla.com", "www.amazon.com", "www.yahoo.com",
    "duckduckgo.com", "cdn.jsdelivr.net", "telegram.org", "www.bing.com",
]
BLOCK_MARKERS = [b"access denied", b"forbidden", b"unavailable for legal reasons",
                 "заблокирован".encode(), "доступ ограничен".encode()]

def _proxies(port):
    p = f"http://127.0.0.1:{port}"
    return {"http": p, "https": p}

SPEED_URL = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10 МБ

def measure_speed(local_port, max_bytes=10_000_000, max_time=12.0):
    """Скачивает файл через туннель, возвращает реальную скорость в KB/s (0 = не вышло)."""
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

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"}

def real_check(cand, local_port, is_white, light=False):
    """Проверка через реальный туннель.
    light=True  — для старых (инкумбентов): HTTPS-204 + контент (2 проверки).
    light=False — для новых: +HTTP-204 (3 независимые проверки подряд).
    Возвращает (ok, latency, kbps, причина_отказа)."""
    info = cand["info"]
    if info["proto"] == "hy2":
        cfg = hy2_to_singbox_config(info, local_port)
        engine = [SINGBOX_PATH, "run", "-c"]
        eng_name = "sing-box"
    else:
        cfg = vless_to_xray_config(info, local_port)
        engine = [XRAY_PATH, "run", "-c"]
        eng_name = "xray"
    cfg_path = f"/tmp/check_cfg_{local_port}.json"
    proc = None
    try:
        with open(cfg_path, "w") as f:
            json.dump(cfg, f)
        proc = subprocess.Popen(engine + [cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                preexec_fn=os.setsid)
        if not wait_for_port(local_port, proc, XRAY_START_WAIT):
            reason = f"{eng_name}_error (битый конфиг)" if proc.poll() is not None else f"{eng_name} не поднял порт"
            return False, None, 0, reason

        # --- Проверка 1: HTTP через туннель (generate_204) — только для новых ---
        if not light:
            try:
                r = requests.get("http://www.gstatic.com/generate_204", proxies=_proxies(local_port),
                                 timeout=STAGE_TIMEOUT, headers=UA)
                if r.status_code != 204:
                    return False, None, 0, f"http204 -> {r.status_code}"
            except Exception as e:
                return False, None, 0, f"http204 fail ({type(e).__name__})"

        # --- Проверка 2: HTTPS через туннель + замер скорости (generate_204) ---
        t0 = time.monotonic()
        try:
            r = requests.get("https://www.gstatic.com/generate_204", proxies=_proxies(local_port),
                             timeout=STAGE_TIMEOUT, headers=UA)
        except Exception as e:
            return False, None, 0, f"https204 fail ({type(e).__name__})"
        if r.status_code != 204:
            return False, None, 0, f"https204 -> {r.status_code}"
        latency = time.monotonic() - t0

        # --- Проверка 3: загрузка РЕАЛЬНОГО контента ---
        # Цель №1 (Telegram) обязательна: без неё сервер НЕ попадает в подписку.
        targets = WHITE_TARGETS if is_white else BLACK_TARGETS
        tg_url, tg_marker, tg_min = targets[0]
        try:
            r = requests.get(tg_url, proxies=_proxies(local_port),
                             timeout=STAGE_TIMEOUT + 3, headers=UA)
            if r.status_code != 200:
                return False, None, 0, f"telegram -> {r.status_code}"
            content = r.content
            low = content[:200000].lower()
            if len(content) < tg_min or tg_marker not in low:
                return False, None, 0, "telegram: не настоящая страница"
        except Exception as e:
            return False, None, 0, f"telegram fail ({type(e).__name__})"

        kbps = 0.0
        content_ok = False
        last_reason = "content fail"
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

        # --- Замер РЕАЛЬНОЙ скорости (точный, вместо грубой оценки со страницы) ---
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

# ================== ВОЛНЫ ПРОВЕРОК ==================
def verify_candidates(cands, is_white, diag, light=False, limit=None, stop_when=None):
    """Волны по 2*REAL_WORKERS, пока не кончатся кандидаты или лимит проверок.
    Возвращает (verified, checked): verified — прошедшие, checked — все проверенные."""
    verified, checked = [], []
    checks = 0
    wave_size = REAL_WORKERS * 2
    pool = list(cands)
    while pool:
        if stop_when is not None and len(verified) >= stop_when:
            print(f"    [*] Достаточно проверенных ({len(verified)}) — дозабор остановлен.")
            break
        if limit is not None and checks >= limit:
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
                checked.append(cand)
                if ok:
                    verified.append({**cand, "latency": latency, "kbps": kbps})
                    print(f"    [+] {cand['country']:3s} | {kbps:7.1f} KB/s | {latency:4.2f}s | {cand['info']['host']}:{cand['info']['port']}")
                else:
                    tag = reason.split(" ")[0].split("(")[0]
                    diag[tag] = diag.get(tag, 0) + 1
                    print(f"    [-] {cand['country']:3s} | {reason} | {cand['info']['host']}:{cand['info']['port']}")
    return verified, checked

# ================== СОСТОЯНИЕ (ИСТОРИЯ ПРОВЕРОК) ==================
def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"white": {}, "black": {}}

def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=1)

def bump_entry(state_list, cand, ok, kbps=None):
    key = cand["key"]
    e = state_list.get(key) or {
        "link": cand["line"], "country": cand["country"],
        "passes": 0, "fails": 0, "streak": 0, "best_kbps": 0.0,
        "last_ok": 0, "last_fail": 0,
    }
    e["link"] = cand["line"]; e["country"] = cand["country"]
    if ok:
        e["passes"] += 1; e["streak"] += 1
        e["last_ok"] = int(time.time())
        if kbps: e["best_kbps"] = round(max(e["best_kbps"], kbps), 1)
    else:
        e["fails"] += 1; e["streak"] = 0
        e["last_fail"] = int(time.time())
    state_list[key] = e
    return e

# ================== ВЫБОР ПО КВОТАМ ==================
def tspu_bonus(info):
    """Наценка профилю, который чаще выживает после ТСПУ.
    Проверка идёт не из РФ, поэтому «русская живучесть» оценивается эвристикой:
    Reality с крупным SNI, порт 443, Cloudflare-фронт."""
    b = 0.0
    if info["security"] == "reality":
        b += 3.0
        if any(s in (info["sni"] or "") for s in REALITY_GOOD_SNIS):
            b += 1.5
        if info.get("flow") == "xtls-rprx-vision":
            b += 0.5
    if info["port"] == 443:
        b += 1.0
    ip = resolve(info["host"])
    if ip and is_cf_ip(ip):
        b += 1.0
    return b

def score_of(v, streak):
    base = 100.0 / (0.4 + v["latency"])          # быстрее = выше
    if v.get("kbps"): base += min(v["kbps"] / 50.0, 6.0)
    if v.get("has_trusted"): base += 2.0          # белый список: доверенный SNI
    base += tspu_bonus(v["info"])                 # выживаемость после ТСПУ
    base *= (0.92 ** min(streak, 5))              # проверенный временем чуть выше
    return base

def select_balanced(verified, state_list, need):
    by_country = {}
    for v in verified:
        by_country.setdefault(v["country"], []).append(v)
    for c in by_country:
        by_country[c].sort(key=lambda v: -score_of(v, state_list.get(v["key"], {}).get("streak", 0)))
    selected, used = [], set()
    def take(c, n):
        taken = 0
        for v in by_country.get(c, []):
            if v["key"] in used: continue
            if taken >= n: break
            selected.append(v); used.add(v["key"]); taken += 1
        return taken
    for c in ("DE", "FI", "NL", "US"):
        take(c, PRIORITY_QUOTAS.get(c, 0))
    # добор ЛЮБЫМИ недостающими (сначала приличные страны), по скорости
    if len(selected) < need:
        rest = [v for vs in by_country.values() for v in vs if v["key"] not in used]
        rest.sort(key=lambda v: -score_of(v, state_list.get(v["key"], {}).get("streak", 0)))
        for v in rest:
            if len(selected) >= need: break
            selected.append(v); used.add(v["key"])
    return selected[:need]

# ================== ФАЙЛЫ ==================
def read_old_servers(filename):
    if not os.path.exists(filename):
        return []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return [l.strip() for l in f.read().splitlines()
                    if l.strip() and not l.startswith("#")]
    except Exception:
        return []

FM_FRAGMENT = {"tcp": [{"type": "fragment", "settings": {
    "packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0"}}]}

def ensure_fragment(link):
    """Для БЕЛОГО списка: добавляет в ссылку fm= (TLS-фрагментация), если её нет.
    Клиент (Happ) фрагментирует ClientHello — ТСПУ не видит SNI и не режет соединение.
    Проверка сервера при этом шла без фрагментации: это независимые уровни."""
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
            if l in protected:                # proven-ссылки не изменяем никогда
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

# ================== ОСНОВНОЙ ЦИКЛ ПО СПИСКУ ==================
def process_list(is_white, state, t_start):
    name = "БЕЛЫЙ" if is_white else "ЧЁРНЫЙ"
    urls = URLS_WHITE if is_white else URLS_BLACK
    sub_file = WHITE_FILE if is_white else BLACK_FILE
    print(f"\n{'='*60}\n[*] {name} СПИСОК\n{'='*60}")

    # --- 1. Качаем источники ---
    print("[*] Скачиваю источники...")
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        texts = list(ex.map(fetch_one, urls))
    good = sum(1 for t in texts if t)
    print(f"[+] Источников ответило: {good}/{len(urls)}")

    # --- 2. Парсим кандидатов ---
    used_keys, ip_count, subnet_count = set(), {}, {}
    candidates = parse_sources(texts, used_keys, ip_count, subnet_count, is_white)
    print(f"[+] Кандидатов после фильтров: {len(candidates)}")
    before = len(candidates)
    if ALLOWED_COUNTRIES:
        candidates = [c for c in candidates if c["country"] in ALLOWED_COUNTRIES]
        print(f"[*] Только {','.join(sorted(ALLOWED_COUNTRIES))}: {len(candidates)} из {before}")
    if not candidates:
        print("[!] Кандидатов нужных стран нет — файл не трогаю.")
        return

    # --- 3. Инкумбенты: старые серверы из файла проходят ПОЛНУЮ проверку ---
    old_lines = read_old_servers(sub_file)
    old_cands = []
    seen_old = set()
    for line in old_lines:
        info = extract_info(line)
        if not info:
            continue
        if info["proto"] == "vless" and not UUID_RE.fullmatch(info["uuid"] or ""):
            continue
        if ALLOWED_COUNTRIES and detect_country(line, info["sni"]) not in ALLOWED_COUNTRIES:
            continue                      # жёсткий фильтр стран включён — чужие вон
        if line.startswith(HY2_PREFIXES):
            try:
                info["proto"] = "hy2"
                info["security"] = "hy2"
                info["uuid"] = unquote(line.split("://", 1)[1].split("@", 1)[0])
            except Exception:
                continue
        k = server_key(info)
        if k in seen_old: continue
        seen_old.add(k)
        match = next((c for c in candidates if c["key"] == k), None)
        if match:
            old_cands.append(match)
        else:
            ip = resolve(info["host"]) or info["host"]
            if ip_count.get(ip, 0) < 2 and (not is_white or white_ok(info, line)) and (is_white or not is_russian_ip(info["host"])):
                old_cands.append({"line": line, "info": info, "key": k,
                                  "has_trusted": any(t in (info["sni"] or "") for t in TRUSTED_SNIS),
                                  "country": detect_country(line, info["sni"])})
                ip_count[ip] = ip_count.get(ip, 0) + 1

    state_list = state["white"] if is_white else state["black"]
    print(f"\n[*] ЭТАП 1: перепроверяю {len(old_cands)} старых серверов (полная проверка, НЕ хендшейк)...")
    old_verified, old_checked = verify_candidates(old_cands, is_white, {}, light=True)
    for c in old_cands:
        bump_entry(state_list, c, any(v["key"] == c["key"] for v in old_verified))
    print(f"[+] Старых живых: {len(old_verified)} (мёртвые будут заменены)")

    # --- 4. Хендшейк всех кандидатов (быстрый отсев) ---
    old_keys = {v["key"] for v in old_verified}
    rest = [c for c in candidates if c["key"] not in old_keys]
    random.shuffle(rest)                          # случайно, а не «первые 40 из файла»
    print(f"\n[*] ЭТАП 2: хендшейк {min(len(rest), 150)} новых кандидатов...")
    hs_pool = rest[:150]
    hs_passed = []
    with ThreadPoolExecutor(max_workers=HS_WORKERS) as ex:
        for r in ex.map(handshake_check, hs_pool):
            if r: hs_passed.append(r)
    hs_passed.sort(key=lambda c: c.get("hs_score", 9))
    print(f"[+] Прошли хендшейк: {len(hs_passed)}")

    need_new = max(0, TARGET_COUNT + RESERVE_EXTRA - len(old_verified))

    # hysteria2 (QUIC/UDP) в TCP-хендшейке не нуждается — проверяем их первыми
    hy2_pool = [c for c in rest if c["info"]["proto"] == "hy2"] if is_white else []
    rest = [c for c in rest if c["info"]["proto"] != "hy2"] if is_white else rest

    # КУЛДАУН: кто умер 2+ раза подряд в прошлых запусках — пропускаем (если есть кем заменить)
    def on_cooldown(c):
        e = state_list.get(c["key"])
        return bool(e and e.get("streak", 0) == 0 and e.get("fails", 0) >= 2)
    hot = [c for c in hs_passed if not on_cooldown(c)]
    cooled = len(hs_passed) - len(hot)
    if cooled:
        print(f"[*] Кулдаун: пропускаю {cooled} давно умерших (economia бюджета)")
    hs_passed = hot if len(hot) >= need_new * 2 else hs_passed
    if is_white and hy2_pool:
        print(f"[*] hysteria2-кандидатов (без хендшейка, QUIC): {len(hy2_pool)}")
        # чередуем классы 1:1 — ни hy2, ни vless не съедают весь бюджет проверок
        mixed = []
        a, b = list(hy2_pool), list(hs_passed)
        while a or b:
            if a: mixed.append(a.pop(0))
            if b: mixed.append(b.pop(0))
        hs_passed = mixed

    # --- 5. Волны полной (тройной) проверки новых, пока не наберём ---
    new_verified = []
    if need_new > 0:
        budget = MAX_REAL_CHECKS
        print(f"[*] Нужно новых: {need_new}, бюджет полных проверок: {budget}")
        new_verified, new_checked = verify_candidates(hs_passed, is_white, {}, light=False,
                                                          limit=budget, stop_when=need_new + 2)
        vkeys = {v["key"] for v in new_verified}
        for c in new_checked:                     # историю пишем только КТО ПРОВЕРЯЛСЯ
            if c["key"] in vkeys:
                bump_entry(state_list, c, True,
                           next((v["kbps"] for v in new_verified if v["key"] == c["key"]), None))
            else:
                bump_entry(state_list, c, False)
    else:
        print("[*] Дозабор новых не нужен.")

    # --- 6. Выбор по квотам: живые старые + проверенные новые ---
    # --- 5b. PROVEN: серверы из proven.txt (проверены тобой на телефоне) ---
    proven_verified, proven_lines_set = [], set()
    if os.path.exists(PROVEN_FILE):
        try:
            with open(PROVEN_FILE, "r", encoding="utf-8") as f:
                plines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
        except Exception:
            plines = []
        pseen, proven_cands = set(), []
        for line in plines:
            info = extract_info(line)
            if not info:
                continue
            if info["proto"] == "vless" and not UUID_RE.fullmatch(info["uuid"] or ""):
                continue
            if line.startswith(HY2_PREFIXES):
                info["proto"] = "hy2"; info["security"] = "hy2"
                try:
                    info["uuid"] = unquote(line.split("://", 1)[1].split("@", 1)[0])
                except Exception:
                    continue
            k = server_key(info)
            if k in pseen:
                continue
            pseen.add(k)
            proven_lines_set.add(line)
            # Country-фильтры к proven НЕ применяем: телефон важнее эвристики
            proven_cands.append({"line": line, "info": info, "key": k,
                                 "has_trusted": True,
                                 "country": detect_country(line, info["sni"])})
        if proven_cands:
            print(f"\n[*] PROVEN: перепроверяю {len(proven_cands)} серверов из proven.txt...")
            proven_verified, pchecked = verify_candidates(proven_cands, is_white, {}, light=True)
            pvk = {v["key"] for v in proven_verified}
            for c in proven_cands:
                bump_entry(state_list, c, c["key"] in pvk)
            print(f"[+] PROVEN живых: {len(proven_verified)} — идут в файл первыми")

    # --- 6. Выбор: proven -> инкумбенты/новые по квотам/тирам ---
    pv_keys = {v["key"] for v in proven_verified}
    seen_keys, pool = set(), []
    for v in old_verified + new_verified:
        if v["key"] in seen_keys or v["key"] in pv_keys:
            continue
        seen_keys.add(v["key"])
        pool.append(v)
    slots = max(0, TARGET_COUNT - len(proven_verified))
    all_verified = pool
    if is_white:
        # БЕЛЫЙ v19: сначала «родные» классы (hysteria2, Reality+белый SNI),
        # самые быстрые по замеру; свободные места — быстрые CF+443
        def white_tier(v):
            i = v["info"]
            if i["proto"] == "hy2":
                return 1
            if i["security"] == "reality" and is_white_sni(i["sni"]):
                return 1
            return 2
        t1 = sorted((v for v in all_verified if white_tier(v) == 1),
                    key=lambda v: -(v.get("kbps") or 0))
        t2 = sorted((v for v in all_verified if white_tier(v) == 2),
                    key=lambda v: -(v.get("kbps") or 0))
        selected = (proven_verified + (t1 + t2)[:slots])[:TARGET_COUNT]
    else:
        selected = (proven_verified + select_balanced(pool, state_list, slots))[:TARGET_COUNT]
    print(f"\n[+] Итог {name}: {len(selected)} серверов")
    dist = {}
    for v in selected: dist[v["country"]] = dist.get(v["country"], 0) + 1
    print(f"    Распределение: {', '.join(f'{c}:{n}' for c, n in sorted(dist.items())) or '—'}")

    if selected:
        write_subscription(sub_file,
                           "Белый список (РКН)" if is_white else "Чёрный список (РКН)",
                           [v["line"] for v in selected], is_white,
                           protected=proven_lines_set)
        print(f"[+] {sub_file} ЗАПИСАН ({len(selected)} проверенных серверов)")
    else:
        print(f"[!] Ни одного живого — {sub_file} НЕ трогаю (старый файл сохранён).")

# ================== MAIN ==================
def main():
    t0 = time.monotonic()
    print("[*] Парсер v21: proven.txt (твои рабочие) в приоритете + фильтр стран выкл (квоты как приоритет)")
    if not (os.path.exists(XRAY_PATH) or shutil.which(XRAY_PATH)):
        print("[!] xray не найден — выход.")
        return
    state = load_state()
    try:
        process_list(True, state, t0)     # белый
        process_list(False, state, t0)    # чёрный
    finally:
        # чистим историю: мёртвые точки старше 7 дней больше не нужны
        cutoff = time.time() - 7 * 86400
        for lst in (state.get("white", {}), state.get("black", {})):
            for k in [k for k, e in lst.items() if e.get("streak", 0) == 0 and e.get("last_fail", 0) < cutoff]:
                lst.pop(k, None)
        save_state(state)
    print(f"\n[*] Общее время: {time.monotonic() - t0:.1f} сек")

if __name__ == "__main__":
    main()
