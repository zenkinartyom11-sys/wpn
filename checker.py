import ssl, json, random, socket, requests, time, os
from urllib.parse import urlparse, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# === ТВОИ 4 ССЫЛКИ НА ИСТОЧНИКИ ===
# Сюда в кавычки вставь свои вторые источники для белого и черного списков
URLS_WHITE = [
    "https://githubusercontent.com",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"
]

URLS_BLACK = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"
]

TRUSTED_SNIS = ["microsoft.com", "apple.com", "icloud.com", "samsung.com", "google.com", "cloudflare.com"]

RUSSIAN_IP_PREFIXES = [
    "5.101.", "5.143.", "5.187.", "5.188.", "31.31.", "31.40.", "31.134.", "37.140.", "37.143.", 
    "37.192.", "45.8.", "45.12.", "45.67.", "45.86.", "45.90.", "45.132.", "45.142.", "46.17.", 
    "46.39.", "46.146.", "46.147.", "46.148.", "46.182.", "51.250.", "62.76.", "77.37.", "77.82.", 
    "77.220.", "77.222.", "77.244.", "78.46.", "78.109.", "79.133.", "79.137.", "79.174.", "80.64.", 
    "80.78.", "80.87.", "80.93.", "81.9.", "81.19.", "81.163.", "81.176.", "81.177.", "82.146.", 
    "82.202.", "83.149.", "83.219.", "83.220.", "84.38.", "84.52.", "84.201.", "85.21.", "85.93.", 
    "85.112.", "85.113.", "85.114.", "85.119.", "85.142.", "85.143.", "85.192.", "87.224.", "87.226.", 
    "87.249.", "87.251.", "88.212.", "89.108.", "89.111.", "89.169.", "89.175.", "89.208.", "89.223.", 
    "91.76.", "91.105.", "91.122.", "91.189.", "91.197.", "91.200.", "91.210.", "91.213.", "91.217.", 
    "91.226.", "91.242.", "92.53.", "92.63.", "92.242.", "93.80.", "93.81.", "93.100.", "93.159.", 
    "93.180.", "93.185.", "93.186.", "94.19.", "94.25.", "94.100.", "94.137.", "94.181.", "94.198.", 
    "94.228.", "94.250.", "94.261.", "95.24.", "95.25.", "95.26.", "95.27.", "95.28.", "95.29.", 
    "95.31.", "95.67.", "95.70.", "95.71.", "95.78.", "95.79.", "95.83.", "95.84.", "95.104.", 
    "95.105.", "95.141.", "95.163.", "95.165.", "95.174.", "95.213.", "109.184.", "109.194.", "109.252.", 
    "128.0.", "128.68.", "128.72.", "141.8.", "151.249.", "176.14.", "176.99.", "176.111.", "176.121.", 
    "176.154.", "176.212.", "176.213.", "176.214.", "176.215.", "178.19.", "178.45.", "178.46.", "178.47.", 
    "178.64.", "178.70.", "178.71.", "178.130.", "178.140.", "178.154.", "178.159.", "178.176.", "178.177.", 
    "178.204.", "178.213.", "178.219.", "185.2.", "185.6.", "185.12.", "185.15.", "185.22.", "185.26.", 
    "185.32.", "185.43.", "185.46.", "185.51.", "185.54.", "185.60.", "185.86.", "185.129.", "185.178.", 
    "185.204.", "188.16.", "188.32.", "188.64.", "188.65.", "188.68.", "188.93.", "188.123.", "188.162.", 
    "188.170.", "188.191.", "188.225.", "188.226.", "188.242.", "188.243.", "188.244.", "193.19.", "193.26.", 
    "193.106.", "193.124.", "193.169.", "194.54.", "194.58.", "194.67.", "194.85.", "194.135.", "194.226.", 
    "195.19.", "195.98.", "195.208.", "195.239.", "195.242.", "195.245.", "212.1.", "212.33.", "212.44.", 
    "212.45.", "212.57.", "212.92.", "212.119.", "212.192.", "212.193.", "213.24.", "213.33.", "213.59.", 
    "213.80.", "213.85.", "213.87.", "213.158.", "213.170.", "213.180.", "213.221.", "213.234.", "217.21.", 
    "217.23.", "217.66.", "217.73.", "217.107.", "217.114.", "217.118.", "217.150.", "217.174."
]

def is_russian_ip(ip):
    if not ip: return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix): return True
    return ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by")

def get_stability_score(link):
    try:
        parsed = urlparse(link)
        sni = parse_qs(parsed.query).get("sni", [""])[0].lower()
        if any(trusted in sni for trusted in TRUSTED_SNIS): return 0
    except: pass
    return 1

def test_link(link):
    try:
        parsed = urlparse(link)
        ip, port = parsed.hostname, int(parsed.port)
        with socket.create_connection((ip, port), timeout=3) as sock:
            sni = parse_qs(parsed.query).get("sni", [ip])[0]
            with ssl._create_unverified_context().wrap_socket(sock, server_hostname=sni):
                return True
    except: return False

def parse_source_text(text, used_ips, used_uuids):
    candidates = []
    for line in text.splitlines():
        if line.startswith("vless://"):
            try:
                link = line.strip()
                parsed = urlparse(link)
                ip = parsed.hostname
                if not ip or ip in used_ips or parsed.username in used_uuids or is_russian_ip(ip): continue
                used_uuids.add(parsed.username)
                used_ips.add(ip)
                candidates.append(link)
            except: continue
    return candidates

def thread_worker(link):
    return link, test_link(link)

def main():
    raw_white_text = ""
    raw_black_text = ""
    
    # Скачиваем обе ссылки белого списка
    for url in URLS_WHITE:
        if not url or "СЮДА_" in url: continue
        try: raw_white_text += "\n" + requests.get(url, timeout=10).text
        except: print(f"⚠️ Ошибка скачивания источника белого списка: {url[:40]}...")

    # Скачиваем обе ссылки черного списка
    for url in URLS_BLACK:
        if not url or "СЮДА_" in url: continue
        try: raw_black_text += "\n" + requests.get(url, timeout=10).text
        except: print(f"⚠️ Ошибка скачивания источника черного списка: {url[:40]}...")

    used_uuids = set()
    used_ips = set()
    
    # Парсим и склеиваем дубликаты
    white_c = parse_source_text(raw_white_text, used_ips, used_uuids)
    black_c = parse_source_text(raw_black_text, used_ips, used_uuids)
    
    white_c.sort(key=get_stability_score)
    black_c.sort(key=get_stability_score)
    
    black_w, white_w = [], []

    with ThreadPoolExecutor(max_workers=30) as ex:
        if white_c:
            f = {ex.submit(thread_worker, l): l for l in white_c}
            for fut in as_completed(f):
                link, alive = fut.result()
                if alive:
                    white_w.append(link)
                    if len(white_w) >= 5: break
                    
        if black_c:
            f = {ex.submit(thread_worker, l): l for l in black_c}
            for fut in as_completed(f):
                link, alive = fut.result()
                if alive:
                    black_w.append(link)
                    if len(black_w) >= 5: break

    # Фолбэк (на случай, если тесты упали, берем первые попавшиеся)
    if len(white_w) < 5 and white_c:
        for l in white_c:
            if len(white_w) >= 5: break
            if l not in white_w: white_w.append(l)
            
    if len(black_w) < 5 and black_c:
        for l in black_c:
            if len(black_w) >= 5: break
            if l not in black_w: black_w.append(l)

    # === ЗАПИСЬ В ДВА ФАЙЛА С АВТОНАЗВАНИЕМ ДЛЯ HAPP PROXY ===
    with open("white_subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: Белый список (РКН)\n" + "\n".join(white_w[:5]))
        
    with open("black_subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: Черный список (РКН)\n" + "\n".join(black_w[:5]))
        
    print(f"[+] Сгенерировано: {len(white_w[:5])} Белых и {len(black_w[:5])} Черных серверов из 4 источников.")

if __name__ == "__main__":
    main()
