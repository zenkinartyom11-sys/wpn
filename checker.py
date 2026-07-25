import ssl, json, random, socket, requests, time, os
from urllib.parse import urlparse, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

FILE_PATH = "subscription.txt"

# === ТВОИ 2 ССЫЛКИ НА ИСТОЧНИКИ ===
URL_WHITE = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"
URL_BLACK = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"

WHITE_ASNS = [13335, 15169, 8075, 20940, 16509, 29404]  # Cloudflare, Google, MS, Akamai, AWS, Apple
RUSSIAN_IP_PREFIXES = ["84.201.", "51.250.", "178.154.", "91.242.", "185.12.", "185.129.", "185.22.", "188.225."]

def is_russian_ip(ip):
    return any(ip.startswith(p) for p in RUSSIAN_IP_PREFIXES) if ip else False

def get_asn_info(ip):
    try:
        res = requests.get(f"https://ripe.net{ip}", timeout=3).json()
        asn_num, country = 0, ""
        if "remarks" in res:
            for r in res["remarks"]:
                for d in r.get("description", []):
                    if "AS" in d: asn_num = int(''.join(filter(str.isdigit, d)))
        if "country" in res: country = str(res["country"]).upper()
        if not country or asn_num == 0:
            res_alt = requests.get(f"https://ipapi.co{ip}/json/", timeout=2).json()
            country = res_alt.get("country_code", "").upper()
            as_text = res_alt.get("org", "")
            if "AS" in as_text: asn_num = int(as_text.split()[0].replace("AS", ""))
        return country == "RU", asn_num in WHITE_ASNS, asn_num
    except: return False, False, 0

def inject_marker_to_link(link, marker_text):
    try: return urlunparse(urlparse(link)._replace(fragment=marker_text))
    except: return f"{link}#{marker_text}"

def test_link(link):
    try:
        parsed = urlparse(link)
        ip, port = parsed.hostname, int(parsed.port)
        with socket.create_connection((ip, port), timeout=3) as sock:
            with ssl._create_unverified_context().wrap_socket(sock, server_hostname=parse_qs(parsed.query).get("sni", [ip])[0]) as ssock:
                return True
    except: return False

def parse_and_classify_lists(text_white, text_black, used_uuids):
    white_cand, black_cand = [], []
    for idx, line in enumerate(text_white.splitlines() + text_black.splitlines()):
        if line.startswith("vless://"):
            try:
                link = line.strip()
                parsed = urlparse(link)
                if parsed.hostname in used_uuids or is_russian_ip(parsed.hostname): continue
                if idx % 5 == 0: time.sleep(0.1)
                is_ru, is_white, asn = get_asn_info(parsed.hostname)
                if is_ru: continue
                used_uuids.add(parsed.username)
                if is_white: white_cand.append(link)
                else: black_cand.append(link)
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
    black_w, white_w = [], []

    with ThreadPoolExecutor(max_workers=30) as ex:
        if black_c:
            f = {ex.submit(thread_worker, l): l for l in black_c}
            for fut in as_completed(f):
                link, alive = fut.result()
                if alive:
                    black_w.append(inject_marker_to_link(link, f"AUTO-BLACK-{len(black_w)+1}"))
                    if len(black_w) >= 5: break
        if white_c:
            f = {ex.submit(thread_worker, l): l for l in white_c}
            for fut in as_completed(f):
                link, alive = fut.result()
                if alive:
                    white_w.append(inject_marker_to_link(link, f"AUTO-WHITE-{len(white_w)+1}"))
                    if len(white_w) >= 5: break

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(white_w[:5] + black_w[:5]))
    print(f"[+] Сгенерировано: {len(white_w[:5])} Белых и {len(black_w[:5])} Черных серверов.")

if __name__ == "__main__": main()
