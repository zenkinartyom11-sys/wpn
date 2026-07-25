import ssl, json, random, socket, requests, time, os
from urllib.parse import urlparse, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

FILE_PATH = "subscription.txt"

# === ТВОИ 2 ССЫЛКИ НА ИСТОЧНИКИ ===
URL_WHITE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"
URL_BLACK = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"

TRUSTED_SNIS = ["microsoft.com", "apple.com", "icloud.com", "samsung.com", "google.com", "cloudflare.com"]
RUSSIAN_IP_PREFIXES = ["84.201.", "51.250.", "178.154.", "91.242.", "185.12.", "185.129.", "185.22.", "188.225."]

def is_russian_ip(ip):
    return any(ip.startswith(p) for p in RUSSIAN_IP_PREFIXES) if ip else False

def inject_marker_to_link(link, marker_text):
    try: return urlunparse(urlparse(link)._replace(fragment=marker_text))
    except: return f"{link}#{marker_text}"

def get_stability_score(link):
    try:
        parsed = urlparse(link)
        query_params = parse_qs(parsed.query)
        sni = query_params.get("sni", [""])[0].lower()
        if any(trusted in sni for trusted in TRUSTED_SNIS):
            return 0
    except: pass
    return 1

def test_link(link):
    try:
        parsed = urlparse(link)
        ip, port = parsed.hostname, int(parsed.port)
        with socket.create_connection((ip, port), timeout=3) as sock:
            query = parse_qs(parsed.query)
            sni = query.get("sni", [ip])[0]
            with ssl._create_unverified_context().wrap_socket(sock, server_hostname=sni) as ssock:
                return True
    except: return False

def parse_and_classify_lists(text_white, text_black, used_uuids):
    white_cand, black_cand = [], []
    used_ips = set()
    
    # Жесткий парсинг БЕЛОГО списка
    for line in text_white.splitlines():
        if line.startswith("vless://"):
            try:
                link = line.strip()
                parsed = urlparse(link)
                ip = parsed.hostname
                if not ip or ip in used_ips or parsed.username in used_uuids or is_russian_ip(ip): continue
                used_uuids.add(parsed.username)
                used_ips.add(ip)
                white_cand.append(link)
            except: continue

    # Жесткий парсинг ЧЕРНОГО списка
    for line in text_black.splitlines():
        if line.startswith("vless://"):
            try:
                link = line.strip()
                parsed = urlparse(link)
                ip = parsed.hostname
                if not ip or ip in used_ips or parsed.username in used_uuids or is_russian_ip(ip): continue
                used_uuids.add(parsed.username)
                used_ips.add(ip)
                black_cand.append(link)
            except: continue
            
    return white_cand, black_cand

def thread_worker(link):
    return link, test_link(link)

def main():
    try:
        raw_w = requests.get(URL_WHITE, timeout=10).text
        raw_b = requests.get(URL_BLACK, timeout=10).text
    except Exception as e:
        print(f"❌ Ошибка скачивания баз: {e}")
        return

    white_c, black_c = parse_and_classify_lists(raw_w, raw_b, set())
    
    white_c.sort(key=get_stability_score)
    black_c.sort(key=get_stability_score)
    
    black_w, white_w = [], []

    with ThreadPoolExecutor(max_workers=30) as ex:
        if white_c:
            f = {ex.submit(thread_worker, l): l for l in white_c}
            for fut in as_completed(f):
                link, alive = fut.result()
                if alive:
                    white_w.append(inject_marker_to_link(link, f"WHITE-{len(white_w)+1}"))
                    if len(white_w) >= 5: break
                    
        if black_c:
            f = {ex.submit(thread_worker, l): l for l in black_c}
            for fut in as_completed(f):
                link, alive = fut.result()
                if alive:
                    black_w.append(inject_marker_to_link(link, f"BLACK-{len(black_w)+1}"))
                    if len(black_w) >= 5: break

    # Фолбэк на случай, если тесты ничего живого не нашли
    if len(white_w) < 5 and white_c:
        for l in white_c:
            if len(white_w) >= 5: break
            marked = inject_marker_to_link(l, f"WHITE-{len(white_w)+1}")
            if marked not in white_w: white_w.append(marked)
            
    if len(black_w) < 5 and black_c:
        for l in black_c:
            if len(black_w) >= 5: break
            marked = inject_marker_to_link(l, f"BLACK-{len(black_w)+1}")
            if marked not in black_w: black_w.append(marked)

    # === ЗАПИСЬ В ДВА РАЗНЫХ ФАЙЛА ПОДПИСОК ===
    with open("white_subscription.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(white_w[:5]))
        
    with open("black_subscription.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(black_w[:5]))
        
    print("[+] Сгенерировано 2 отдельных файла подписок по 5 серверов в каждом.")

if __name__ == "__main__":
    main()
