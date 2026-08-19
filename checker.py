import ssl, json, random, socket, requests, time, os
from urllib.parse import urlparse, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# === ТВОИ ССЫЛКИ НА ИСТОЧНИКИ (МАКСИМАЛЬНО БОЛЬШИЕ МИРОВЫЕ БАЗЫ) ===
URLS_WHITE = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt", 
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
]

URLS_BLACK = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"
]

VALID_PROTOCOLS = ("vless://", "vmess://", "hysteria2://", "hy2://", "ss://")

# Тотальный, расширенный пул префиксов IP Казахстана (включая новые облачные VPS и мобильные сети)
KAZAKHSTAN_PREFIXES = [
    "2.132.", "2.133.", "2.134.", "2.135.", "5.34.", "5.76.", "5.251.", "31.41.", "37.99.", "37.150.", 
    "37.151.", "45.82.", "45.92.", "45.137.", "45.142.", "45.159.", "46.34.", "46.227.", "77.74.", "79.142.", 
    "80.241.", "82.200.", "85.29.", "88.204.", "89.40.", "89.218.", "89.219.", "91.185.", "92.46.", "92.47.", 
    "94.247.", "95.56.", "95.57.", "95.58.", "95.59.", "109.229.", "145.249.", "147.30.", "176.64.", "176.65.", 
    "178.88.", "178.89.", "178.90.", "178.91.", "185.22.", "185.98.", "185.115.", "185.120.", "185.146.", 
    "185.178.", "193.27.", "193.108.", "193.232.", "194.39.", "195.82.", "195.189.", "212.13.", "212.19.", 
    "212.154.", "213.157.", "217.76."
]

def is_kazakhstan_server(ip_or_domain, line_text):
    if not ip_or_domain: return False
    
    # Триггер 1: Проверка по текстовой метке в названии (самый надежный способ для паблик баз)
    line_lower = line_text.lower()
    if "kz" in line_lower or "kazakhstan" in line_lower or "almaty" in line_lower or "astana" in line_lower:
        return True

    # Триггер 2: Проверка доменной зоны
    if ip_or_domain.endswith(".kz"):
        return True

    # Триггер 3: Резолв домена в IP и сверка с масками подсетей РК
    target_ip = ip_or_domain
    if not ip_or_domain.replace('.', '').isdigit():
        try: target_ip = socket.gethostbyname(ip_or_domain)
        except: return False

    if any(target_ip.startswith(p) for p in KAZAKHSTAN_PREFIXES): 
        return True
        
    return False

def test_link(link):
    try:
        parsed = urlparse(link)
        ip = parsed.hostname
        port = int(parsed.port) if parsed.port else 443
        
        if not ip:
            netloc = link.split('://')[-1].split('#')[0]
            if '@' in netloc: netloc = netloc.split('@')[-1]
            ip = netloc.split(':')[0]
            port = int(netloc.split(':')[1]) if ':' in netloc else 443
            
        if not ip: return False
        
        with socket.create_connection((ip, port), timeout=2.5):
            return True
    except: pass
    return False

def parse_source_text(text, used_uuids):
    candidates, used_ips, count = [], set(), 0
    for line in text.splitlines():
        line_clean = line.strip()
        if any(line_clean.startswith(proto) for proto in VALID_PROTOCOLS):
            try:
                parsed = urlparse(line_clean)
                ip = parsed.hostname
                username = parsed.username
                
                if not ip:
                    try:
                        ip = line_clean.split('@')[-1].split(':')[0]
                        username = line_clean.split('://')[-1].split('@')[0]
                    except: continue

                if not ip or ip in used_ips or username in used_uuids: continue
                
                # Запускаем наш умный комбинированный KZ-фильтр (Текст + IP)
                if not is_kazakhstan_server(ip, line_clean): continue
                
                used_uuids.add(username)
                used_ips.add(ip)
                candidates.append(line_clean)
                count += 1
                if count >= 1000: break  # Перерываем базы максимально глубоко
            except: continue
    return candidates

def thread_worker(link): return link, test_link(link)

def main():
    print("[*] Запуск парсера: глубокий комбинированный поиск серверов КАЗАХСТАНА...")
    raw_text = ""
    
    for url in URLS_WHITE + URLS_BLACK:
        try: raw_text += "\n" + requests.get(url, timeout=10).text
        except: pass

    used_uuids = set()
    kz_candidates = parse_source_text(raw_text, used_uuids)
    print(f"[*] Найдено {len(kz_candidates)} потенциальных серверов Казахстана. Начинаем тесты...")
    
    random.shuffle(kz_candidates)
    kz_alive = []

    with ThreadPoolExecutor(max_workers=30) as ex:
        if kz_candidates:
            f = {ex.submit(thread_worker, l): l for l in kz_candidates[:100]}
            for fut in as_completed(f):
                link, alive = fut.result()
                if alive:
                    kz_alive.append(link)
                    if len(kz_alive) >= 10: break

    # Фолбэк, если жесткие порты закрыты на гитхабе, забираем кандидатов текстом
    if len(kz_alive) < 5 and kz_candidates:
        for l in kz_candidates:
            if len(kz_alive) >= 5: break
            if l not in kz_alive: kz_alive.append(l)

    # Запись в файлы подписок
    with open("white_subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: Белый список (Казахстан)\n" + "\n".join(kz_alive[:5]))
        
    with open("black_subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: Черный список (Казахстан)\n" + "\n".join(kz_alive[5:10] if len(kz_alive) >= 10 else kz_alive[:5]))
        
    print(f"[+] Сгенерировано. Белых KZ: {len(kz_alive[:5])}, Черных KZ: {len(kz_alive[5:10] if len(kz_alive) >= 10 else kz_alive[:5])}.")

if __name__ == "__main__":
    main()
