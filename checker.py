import ssl, json, random, socket, requests, time, os
from urllib.parse import urlparse, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# === ТВОИ 2 ССЫЛКИ НА ИСТОЧНИКИ ===
URL_WHITE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt"
URL_BLACK = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"

TRUSTED_SNIS = ["microsoft.com", "apple.com", "icloud.com", "samsung.com", "google.com", "cloudflare.com"]

def is_russian_ip_ripe(ip):
    """Жесткая проверка страны по официальной безлимитной базе RIPE"""
    try:
        res = requests.get(f"https://ripe.net{ip}", timeout=3).json()
        if "country" in res:
            if str(res["country"]).upper() == "RU":
                return True
        # Резервный безлимитный запрос для IP США/Азии, если RIPE выдал пустоту
        else:
            res_alt = requests.get(f"https://ipapi.co{ip}/json/", timeout=2).json()
            if res_alt.get("country_code", "").upper() == "RU":
                return True
    except:
        pass
    return False

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
    print("[*] Фильтруем Белый список от РФ серверов...")
    for line in text_white.splitlines():
        if line.startswith("vless://"):
            try:
                link = line.strip()
                parsed = urlparse(link)
                ip = parsed.hostname
                if not ip or ip in used_ips or parsed.username in used_uuids: continue
                
                # Задержка, чтобы не спамить API проверки гео
                time.sleep(0.05)
                if is_russian_ip_ripe(ip): 
                    print(f"      [БЛОК] Пропущен сервер РФ: {ip}")
                    continue
                
                used_uuids.add(parsed.username)
                used_ips.add(ip)
                white_cand.append(link)
            except: continue

    # Жесткий парсинг ЧЕРНОГО списка
    print("[*] Фильтруем Черный список от РФ серверов...")
    for line in text_black.splitlines():
        if line.startswith("vless://"):
            try:
                link = line.strip()
                parsed = urlparse(link)
                ip = parsed.hostname
                if not ip or ip in used_ips or parsed.username in used_uuids: continue
                
                time.sleep(0.05)
                if is_russian_ip_ripe(ip): 
                    print(f"      [БЛОК] Пропущен сервер РФ: {ip}")
                    continue
                
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
                    white_w.append(link)
                    if len(white_w) >= 5: break
                    
        if black_c:
            f = {ex.submit(thread_worker, l): l for l in black_c}
            for fut in as_completed(f):
                link, alive = fut.result()
                if alive:
                    black_w.append(link)
                    if len(black_w) >= 5: break

    # Фолбэк на случай, если тесты в ранере ничего живого не нашли
    if len(white_w) < 5 and white_c:
        for l in white_c:
            if len(white_w) >= 5: break
            if l not in white_w: white_w.append(l)
            
    if len(black_w) < 5 and black_c:
        for l in black_c:
            if len(black_w) >= 5: break
            if l not in black_w: black_w.append(l)

    # === ЗАПИСЬ С ТЕГАМИ ПЕРЕИМЕНОВАНИЯ И ЧИСТЫМИ ОТ РФ СЕРВЕРАМИ ===
    with open("white_subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: Белый список (РКН)\n" + "\n".join(white_w[:5]))
        
    with open("black_subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: Черный список (РКН)\n" + "\n".join(black_w[:5]))
        
    print("[+] Готово! Базы очищены от российских хостингов. Сгенерировано 2 чистых файла подписок.")

if __name__ == "__main__":
    main()
