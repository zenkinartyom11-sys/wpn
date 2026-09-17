# -*- coding: utf-8 -*-
"""
GAME CHECKER — «свой DNS»: следит за JSON-конфигом Happ (роутинг для игр).

Что делает:
 1. Читает game_config.json (структура НЕ меняется: inbounds/routing/remarks — трогать запрещено).
 2. Вытаскивает из outbounds все vless-серверы (proxy, amazon, ...).
 3. Проверяет каждого: поднимает реальный туннель (xray) → HTTPS → Telegram →
    замер ПИНГА → UDP-тест (реальный DNS-запрос UDP через SOCKS5-ассоциированный канал).
    Для игр UDP и пинг важнее скорости.
 4. Мёртвый сервер ЗАМЕНЯЕТСЯ кандидатом из источников ЭтоНеЯ С ТОЧНО ТЕМ ЖЕ ТИПОМ
    подключения: protocol + security + network + flow (напр. vless/reality/tcp/vision).
    В outbound подменяются только адрес/порт/uuid/reality-ключи; тег, роутинг,
    порты inbound, стратегия DNS — неприкосновенны.
 5. Пишет: game_config.json (обновлённый), game_report.txt (что заменено),
    game_link.txt (deeplink happ://routing/import/... — импорт в Happ одним тапом).

Запуск: python game_checker.py   (xray рядом или в PATH)
Env:    MAX_CANDIDATES (сколько кандидатов на тип проверять, по умолч. 60)
"""

import ssl, socket, requests, time, base64, re, json, subprocess, os, signal, shutil, struct, random
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor

# ================== НАСТРОЙКИ ==================
CONFIG_FILE     = "game_config.json"
REPORT_FILE     = "game_report.txt"
LINK_FILE       = "game_link.txt"

FALLBACK_WHITE = [
    "https://gitverse.ru/api/repos/etoneya/sub/raw/branch/master/whitelist",
    "https://internet-tenshi.kangel.tech/whitelist",
    "https://whitelist.etoneya.baby",
    "https://etoneya.su/whitelist",
    "https://xn--e1apcp8cq.xn--p1ai/whitelist",
]
FALLBACK_BLACK = [
    "https://blacklist.etoneya.baby",
    "https://etoneya.best/other",
]

CHECK_TIMEOUT   = 4
STAGE_TIMEOUT   = 6
XRAY_START_WAIT = 3
MAX_CANDIDATES  = int(os.environ.get("MAX_CANDIDATES", "60"))  # на каждый тип подключения
REAL_WORKERS    = 8

XRAY_PATH = os.environ.get("XRAY_PATH") or (
    "./xray" if os.path.exists("./xray") else
    "./xray.exe" if os.path.exists("./xray.exe") else "xray")

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"}

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# ================== ПАРСИНГ ИСТОЧНИКОВ ==================
def smart_decode(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        if line.startswith(("vless://", "hysteria2://", "hy2://")):
            out.append(line)
            continue
        t = line
        for _ in range(3):
            try:
                dec = base64.b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", errors="ignore")
            except Exception:
                break
            if not dec:
                break
            found = re.findall(r"(?:vless|hysteria2|hy2)://[^\s<>\"'`,]+", dec)
            if found:
                out.extend(x.strip() for x in found)
                break
            t = dec.strip()
            if not t:
                break
        else:
            if "://" in line:
                out.extend(re.findall(r"(?:vless|hysteria2|hy2)://[^\s<>\"'`,]+", line))
    return "\n".join(out)

def fetch_one(url):
    try:
        r = requests.get(url, timeout=25, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return smart_decode(r.text[:6_000_000].lstrip("\ufeff"))
    except Exception:
        pass
    return ""

def extract_link_info(line):
    try:
        parsed = urlparse(line)
        q = parse_qs(parsed.query)
        g = lambda k, d="": (q.get(k, [d]) or [d])[0]
        return {
            "host": parsed.hostname, "port": parsed.port,
            "uuid": parsed.username or "",
            "sni": g("sni").lower(), "security": g("security", "none"),
            "net": g("type", "tcp"), "pbk": g("pbk"), "sid": g("sid"),
            "fp": g("fp", "chrome"), "flow": g("flow"),
            "line": line,
        }
    except Exception:
        return None

def type_signature(info):
    """Тип подключения, который НЕЛЬЗЯ менять при замене сервера."""
    net = (info.get("net") or "tcp").lower()
    if net == "raw":
        net = "tcp"
    return (info.get("security") or "none").lower(), net, (info.get("flow") or "").lower()

# ================== XRAY-ПРОВЕРКА ==================
def outbound_to_config(o, local_port):
    """Конфиг xray из JSON-outbound (тот же движок, что и в клиенте)."""
    v = o["settings"]["vnext"][0]
    ss = o.get("streamSettings", {})
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "socks",
                      "settings": {"udp": True}}],
        "outbounds": [o, {"protocol": "freedom", "tag": "direct"}],
    }

def link_to_outbound(info, tag):
    """Собирает vless-outbound в JSON-формате из ссылки-кандидата."""
    net = (info["net"] or "tcp").lower()
    if net == "raw":
        net = "tcp"
    user = {"id": info["uuid"], "encryption": "none"}
    if info.get("flow"):
        user["flow"] = info["flow"]
    o = {
        "tag": tag,
        "protocol": "vless",
        "settings": {"vnext": [{"address": info["host"], "port": info["port"], "users": [user]}]},
        "streamSettings": {"network": net, "security": info["security"] or "none"},
    }
    ss = o["streamSettings"]
    if info["security"] == "reality":
        ss["realitySettings"] = {
            "serverName": info["sni"] or info["host"],
            "fingerprint": info["fp"] or "chrome",
            "publicKey": info["pbk"], "shortId": info["sid"] or "",
            "spiderX": "/",
        }
    elif info["security"] == "tls":
        ss["tlsSettings"] = {"serverName": info["sni"] or info["host"], "fingerprint": info["fp"] or "chrome"}
    if net == "ws":
        parsed = urlparse(info["line"])
        q = parse_qs(parsed.query)
        ss["wsSettings"] = {"path": unquote((q.get("path", [" /"])[0]).strip() or "/"),
                            "headers": {"Host": (q.get("host", [""])[0]) or info["sni"] or info["host"]}}
    elif net == "grpc":
        parsed = urlparse(info["line"])
        ss["grpcSettings"] = {"serviceName": parse_qs(parsed.query).get("serviceName", [""])[0]}
    return o

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

def socks5_udp_dns_check(socks_port, timeout=5):
    """Реальный UDP-тест: SOCKS5 UDP ASSOCIATE → DNS-запрос 8.8.8.8 → ответ.
    Для игр (порт 9339/UDP) это главная проверка."""
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=3)
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")                      # greeting: no auth
        if s.recv(2) != b"\x05\x00":
            s.close(); return False
        # UDP ASSOCIATE: VER CMD RSV ATYP(IPv4=0x01) DST.ADDR DST.PORT
        s.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack(">H", 0))
        resp = s.recv(64)
        if len(resp) < 8 or resp[1] != 0:
            s.close(); return False
        relay_ip = resp[4:8] if resp[3] == 1 else None
        relay_port = struct.unpack(">H", resp[-2:])[0]
        if not relay_ip or relay_ip == b"\x00\x00\x00\x00":
            relay_ip = socket.inet_aton("127.0.0.1")
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(timeout)
        # DNS-запрос: ya.ru A
        q = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x02ya\x02ru\x00\x00\x01\x00\x01"
        # RSV(2) FRAG(1) ATYP(1=IPv4) ADDR(4) PORT(2)
        pkt = b"\x00\x00\x00\x01" + socket.inet_aton("8.8.8.8") + struct.pack(">H", 53) + q
        u.sendto(pkt, (socket.inet_ntoa(relay_ip), relay_port))
        data, _ = u.recvfrom(1500)
        u.close(); s.close()
        return len(data) > len(q) - 5   # есть ответ
    except Exception:
        return False

def check_outbound(o, local_port):
    """Возвращает (alive, ping_s, udp_ok, reason)."""
    cfg_path = f"/tmp/game_cfg_{local_port}.json"
    with open(cfg_path, "w") as f:
        json.dump(outbound_to_config(o, local_port), f)
    proc = None
    try:
        proc = subprocess.Popen([XRAY_PATH, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                preexec_fn=os.setsid)
        if not wait_for_port(local_port, proc, XRAY_START_WAIT):
            return False, None, False, "xray не поднял порт (битый сервер)"
        try:
            import socks  # noqa: F401  (PySocks)
        except ImportError:
            return False, None, False, "нет PySocks (pip install pysocks)"
        px = {"http": f"socks5h://127.0.0.1:{local_port}",
              "https": f"socks5h://127.0.0.1:{local_port}"}
        t0 = time.monotonic()
        try:
            r = requests.get("https://www.gstatic.com/generate_204", proxies=px,
                             timeout=STAGE_TIMEOUT, headers=UA)
        except Exception as e:
            return False, None, False, f"https fail ({type(e).__name__})"
        if r.status_code != 204:
            return False, None, False, f"https -> {r.status_code}"
        ping = time.monotonic() - t0
        try:
            r = requests.get("https://web.telegram.org/k/", proxies=px,
                             timeout=STAGE_TIMEOUT + 3, headers=UA)
            if r.status_code != 200 or b"telegram" not in r.content[:200000].lower():
                return False, None, False, "telegram fail"
        except Exception as e:
            return False, None, False, f"telegram fail ({type(e).__name__})"
        udp_ok = socks5_udp_dns_check(local_port)
        return True, ping, udp_ok, "" if udp_ok else "UDP не работает (для игры плохо)"
    except Exception as e:
        return False, None, False, f"exc ({type(e).__name__})"
    finally:
        if proc:
            try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception: pass
            try: proc.wait(timeout=1)
            except Exception: pass
        try: os.remove(cfg_path)
        except Exception: pass

# ================== ОСНОВНОЙ ЦИКЛ ==================
def load_outbounds(cfg):
    return [o for o in cfg.get("outbounds", [])
            if o.get("protocol") == "vless" and o.get("settings", {}).get("vnext")]

def main():
    t0 = time.monotonic()
    print("[*] GAME CHECKER v1: живой JSON для Happ — замена мёртвых серверов с сохранением типа подключения")
    if not (os.path.exists(XRAY_PATH) or shutil.which(XRAY_PATH)):
        print("[!] xray не найден — выход.")
        return
    if not os.path.exists(CONFIG_FILE):
        print(f"[!] {CONFIG_FILE} не найден — выход.")
        return
    with open(CONFIG_FILE, encoding="utf-8") as f:
        cfg = json.load(f)
    outbounds = load_outbounds(cfg)
    print(f"[*] В конфиге vless-серверов: {len(outbounds)} ({', '.join(o.get('tag','?') for o in outbounds)})")

    # --- 1. Проверяем текущих ---
    results = {}
    def cur_check(i_o):
        i, o = i_o
        ok, ping, udp, reason = check_outbound(o, 18000 + i)
        return o.get("tag", f"out{i}"), ok, ping, udp, reason
    print("\n[*] Проверяю текущие серверы конфига...")
    with ThreadPoolExecutor(REAL_WORKERS) as ex:
        for tag, ok, ping, udp, reason in ex.map(cur_check, enumerate(outbounds)):
            results[tag] = (ok, ping, udp)
            if ok:
                print(f"    [ЖИВ] {tag:10s} ping={ping:5.2f}s udp={'да' if udp else 'НЕТ'}")
            else:
                print(f"    [МЁРТВ] {tag:10s} {reason}")

    dead_tags = [o.get("tag", f"out{i}") for i, o in enumerate(outbounds) if not results.get(o.get("tag", f"out{i}"), (False,))[0]]
    report = [f"# GAME CHECK {time.strftime('%Y-%m-%d %H:%M')} UTC",
              f"Серверов в конфиге: {len(outbounds)}; мёртвых: {len(dead_tags)}"]

    # --- 2. Если всё живо — выходим, файл не трогаем ---
    if not dead_tags:
        print("\n[+] Все серверы живы — конфиг не трогаю.")
        with open(REPORT_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(report) + "\nВсе серверы живы.\n")
        return

    # --- 3. Качаем источники кандидатов ---
    print("\n[*] Качаю источники ЭтоНеЯ...")
    mirrors = FALLBACK_WHITE + FALLBACK_BLACK
    with ThreadPoolExecutor(10) as ex:
        texts = [t for t in ex.map(fetch_one, mirrors) if t]
    raw = "\n".join(texts)
    candidates = []
    seen = set()
    for line in set(l.strip() for l in raw.splitlines() if l.strip().startswith("vless://")):
        i = extract_link_info(line)
        if not i or not i["host"] or not i["port"] or not UUID_RE.fullmatch(i["uuid"] or ""):
            continue
        if i["security"] == "reality" and len(i.get("pbk") or "") < 40:
            continue
        key = f"{i['uuid']}|{i['host']}|{i['port']}"
        if key in seen:
            continue
        seen.add(key)
        candidates.append(i)
    print(f"[+] Кандидатов всего: {len(candidates)}")

    # --- 4. Для каждого мёртвого — замена ТОЧНО того же типа ---
    # индекс: тип -> [кандидаты]
    by_type = {}
    for i in candidates:
        by_type.setdefault(type_signature(i), []).append(i)

    for o in outbounds:
        tag = o.get("tag", "?")
        cur = o["settings"]["vnext"][0]
        ss = o.get("streamSettings", {})
        sig_old = ((ss.get("security") or "none").lower(),
                   (ss.get("network") or "tcp").lower(),
                   (cur["users"][0].get("flow") or "").lower())
        if tag not in dead_tags:
            continue
        pool = by_type.get(sig_old, [])
        random.shuffle(pool)
        if not pool:
            print(f"[!] {tag}: нет кандидатов типа {sig_old} — оставляю как есть (тип менять нельзя).")
            report.append(f"{tag}: НЕ заменён — нет живых кандидатов типа {sig_old}")
            continue
        print(f"\n[*] {tag}: ищу замену типа {sig_old} (кандидатов: {len(pool[:MAX_CANDIDATES])})...")
        best = None
        def cand_check(i_c):
            i, c = i_c
            o_try = link_to_outbound(c, "try")
            ok, ping, udp, reason = check_outbound(o_try, 18200 + i)
            return c, ok, ping, udp
        checked = 0
        with ThreadPoolExecutor(REAL_WORKERS) as ex:
            for c, ok, ping, udp in ex.map(cand_check, enumerate(pool[:MAX_CANDIDATES])):
                checked += 1
                if ok:
                    print(f"    [ЖИВ] ping={ping:5.2f}s udp={'да' if udp else 'НЕТ'} | {c['host']}:{c['port']}")
                    # приоритет: UDP работает, потом минимальный пинг
                    score = (1 if udp else 0, -ping)
                    if best is None or score > best[0]:
                        best = (score, c)
                if checked >= MAX_CANDIDATES and best:
                    break
        if not best:
            print(f"[!] {tag}: живых кандидатов типа {sig_old} не нашлось — оставляю как есть.")
            report.append(f"{tag}: НЕ заменён — кандидаты типа {sig_old} все мертвы")
            continue
        new = best[1]
        # --- подмена с сохранением структуры ---
        cur["address"], cur["port"] = new["host"], new["port"]
        cur["users"][0]["id"] = new["uuid"]
        cur["users"][0]["flow"] = new.get("flow") or cur["users"][0].get("flow", "")
        # streamSettings: security/network не меняются (тип совпадает), подменяем ключи
        if new["security"] == "reality" and "realitySettings" in ss:
            rs = ss["realitySettings"]
            rs["serverName"] = new["sni"] or new["host"]
            rs["publicKey"] = new["pbk"]
            rs["shortId"] = new["sid"] or ""
            rs["fingerprint"] = new["fp"] or rs.get("fingerprint", "chrome")
        elif new["security"] == "tls" and "tlsSettings" in ss:
            ts = ss["tlsSettings"]
            ts["serverName"] = new["sni"] or new["host"]
        print(f"[+] {tag}: ЗАМЕНЁН -> {new['host']}:{new['port']} (sni={new['sni']})")
        report.append(f"{tag}: заменён -> {new['host']}:{new['port']} sni={new['sni']} (тип {sig_old} сохранён)")

    # --- 5. Пишем файлы ---
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    print(f"\n[+] {CONFIG_FILE} обновлён.")

    b64 = base64.urlsafe_b64encode(json.dumps(cfg, ensure_ascii=False).encode()).decode()
    with open(LINK_FILE, "w", encoding="utf-8") as f:
        f.write("happ://routing/import/" + b64 + "\n")
    report.append(f"Время: {time.monotonic()-t0:.0f} сек")
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(report) + "\n")
    print(f"[+] {LINK_FILE} (deeplink для импорта в Happ одним тапом)")

if __name__ == "__main__":
    main()
