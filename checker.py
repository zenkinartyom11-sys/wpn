import ssl, json, random, socket, requests, time, os
from urllib.parse import urlparse, parse_qs, urlunparse

# === ТВОИ ССЫЛКИ НА ИСТОЧНИКИ (МОЖНО ДОБАВЛЯТЬ СКОЛЬКО УГОДНО) ===
# Для Белого списка сделали 4 источника. Вставь в кавычки свои 3-ю и 4-ю ссылки.
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

# Пул из 60 финтех-доменов, которые РКН не сможет зажать на ТСПУ
TRUSTED_SNIS = [
    "stripe.com", "paypal.com", "checkout.com", "adyen.com", "braintreepayments.com",
    "worldpay.com", "skrill.com", "neteller.com", "payoneer.com", "authorize.net",
    "sagepay.co.uk", "klarna.com", "squareupsandbox.com", "shopify.com", "swift.com",
    "revolut.com", "wise.com", "westernunion.com", "moneygram.com", "n26.com",
    "paystat.com", "plaid.com", "finastra.com", "visa.com", "mastercard.com",
    "americanexpress.com", "discover.com", "jcbco.jp", "unionpayintl.com", "visaeurope.com",
    "mastercardconnect.com", "hsbc.com", "jpmorganchase.com", "chase.com", "goldmansachs.com",
    "morganstanley.com", "citibank.com", "citi.com", "bankofamerica.com", "bofa.com",
    "barclays.com", "db.com", "bnpparibas.com", "ubs.com", "credit-suisse.com",
    "binance.com", "coinbase.com", "kraken.com", "bitstamp.net", "blockchain.info",
    "etherscan.io", "tronscan.org", "tether.to", "circle.com", "paxos.com",
    "bitpay.com", "coingecko.com", "coinmarketcap.com", "ledger.com", "trezor.io"
]

VALID_PROTOCOLS = ("vless://", "vmess://", "hysteria2://", "hy2://")

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
    "217.23.", "217.66.", "217.73.", "217.107.", "217.114.", "217.118.", "217.150.", "217.174."
]

def is_russian_ip(ip_or_domain):
    if not ip_or_domain: return False
    target_ip = ip_or_domain
    if not ip_or_domain.replace('.', '').isdigit():
        try: target_ip = socket.gethostbyname(ip_or_domain)
        except: return True
    if any(target_ip.startswith(p) for p in RUSSIAN_PREFIXES): return True
    try:
        parts = target_ip.split('.')
        if len(parts) >= 4:
            first_octet = int(parts[0])
            if 91 <= first_octet <= 95 or first_octet in (176, 178, 185, 188, 212, 213) or 193 <= first_octet <= 195: return True
            if first_octet == 128 and 68 <= int(parts[1]) <= 75: return True
    except: pass
    return target_ip.endswith(".ru") or target_ip.endswith(".su") or target_ip.endswith(".by")

def get_stability_score(link):
    try:
        parsed = urlparse(link)
        sni_list = parse_qs(parsed.query).get("sni", [""])
        sni = sni_list[0].lower() if sni_list else ""
        if any(t in sni for t in TRUSTED_SNIS): return 0
    except: pass
    return 1

def parse_source_text(text, used_uuids, is_white_list=False):
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
                
                sni_list = parse_qs(parsed.query).get("sni", [""])
                sni = sni_list[0].lower() if sni_list else ""
                
                if is_white_list and any(trusted in sni for trusted in TRUSTED_SNIS):
                    pass
                else:
                    if is_russian_ip(ip): continue
                
                used_uuids.add(username)
                used_ips.add(ip)
                candidates.append(line_clean)
                count += 1
                if count >= 150: break  # Увеличили лимит до 150 для обработки 4-х файлов
            except: continue
    return candidates

def main():
    print("[*] Экстренный боевой запуск парсера под белые списки РКН...")
    raw_white_text, raw_black_text = "", ""
    
    # Спокойный цикл, который скачивает ВСЕ прописанные ссылки вайтлиста (хоть 4, хоть 10)
    for url in URLS_WHITE:
        if not url or "СЮДА_" in url: continue
        try: raw_white_text += "\n" + requests.get(url, timeout=10).text
        except: pass
        
    for url in URLS_BLACK:
        if not url or "СЮДА_" in url: continue
        try: raw_black_text += "\n" + requests.get(url, timeout=10).text
        except: pass

    used_uuids = set()
    white_c = parse_source_text(raw_white_text, used_uuids, is_white_list=True)
    black_c = parse_source_text(raw_black_text, used_uuids, is_white_list=False)
    
    white_c.sort(key=get_stability_score)
    black_c.sort(key=get_stability_score)
    
    # Отбор серверов под защиту ИТ-гигантов
    super_white = []
    for link in white_c:
        try:
            parsed = urlparse(link)
            sni_list = parse_qs(parsed.query).get("sni", [""])
            sni = sni_list[0].lower() if sni_list else ""
            if any(trusted in sni for trusted in TRUSTED_SNIS):
                super_white.append(link)
        except: continue

    if len(super_white) < 5:
        ws_servers = [l for l in white_c if "type=ws" in l or "type=grpc" in l]
        super_white.extend([s for s in ws_servers if s not in super_white])

    final_white = super_white[:5] if super_white else white_c[:5]
    final_black = black_c[:5]

    with open("white_subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: Белый список (РКН)\n" + "\n".join(final_white))
        
    with open("black_subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: Черный список (РКН)\n" + "\n".join(final_black))
        
    print(f"[+] Экстренное боевое обновление завершено. Скачано из всех источников. Записано Белых: {len(final_white)}, Черных: {len(final_black)}.")

if __name__ == "__main__":
    main()
