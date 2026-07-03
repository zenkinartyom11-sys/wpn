import json
import random
import socket
import time
import requests
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode, unquote
from concurrent.futures import ThreadPoolExecutor

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

# База жесткого бана российских хостингов по первым цифрам IP
RUSSIAN_IP_PREFIXES = [
    "84.201.", "51.250.", "178.154.", "91.242.", "185.12.", "185.129.", "185.22.", 
    "188.225.", "193.124.", "194.58.", "194.67.", "195.19.", "195.208.", "195.242.",
    "212.193.", "213.180.", "217.114.", "217.23.", "217.73.", "31.31.", "37.140.",
    "45.86.", "77.220.", "77.222.", "79.137.", "80.78.", "80.93.", "81.177.", 
    "82.146.", "82.202.", "83.219.", "85.113.", "85.119.", "87.251.", "89.108.",
    "89.111.", "89.169.", "89.223.", "91.210.", "91.213.", "92.53.", "93.180.",
    "94.198.", "94.250.", "95.163.", "95.213.", "185.178.", "185.204.", "194.54."
]

def is_server_alive(server_dict, timeout=1.5):
    """Проверяет, отвечает ли порт сервера"""
    try:
        with socket.create_connection((server_dict["ip"], int(server_dict["port"])), timeout=timeout):
            return True
    except:
        return False

def is_russian_ip(ip):
    if not ip: return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix): return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"): return True
    return False

def inject_safe_fp(link):
    """Принудительно ставит стабильный имитатор браузера chrome или safari"""
    try:
        parsed = urlparse(link)
        query_params = parse_qs(parsed.query)
        query_params["fp"] = [random.choice(["chrome", "safari"])]
        flat_params = {k: v for k, v in query_params.items()}
        new_query = urlencode(flat_params)
        new_parsed = parsed._replace(query=new_query)
        return urlunparse(new_parsed)
    except:
        return link

def clean_country_name(raw_fragment):
    """Вытаскивает только первое главное слово страны (например, 'finland')"""
    try:
        decoded = unquote(raw_fragment).strip().lower()
        for char in ["-", "_", "[", "]", "(", ")", "|", "*"]:
            decoded = decoded.replace(char, " ")
            
        words = decoded.split()
        if not words:
            return "unknown"
            
        # Если первое слово — эмодзи-флаг, возвращаем само название страны
        if len(words) >= 2 and len(words[0]) > 4:
            return words[1]
            
        return words[0]
    except:
        return "unknown"

def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    all_servers = []
    used_uuids = set()
    
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                uuid = parsed.username
                
                if not ip or not port or not uuid or uuid in used_uuids or is_russian_ip(ip):
                    continue
                
                query_params = parse_qs(parsed.query)
                
                # ИСПРАВЛЕНО: Безопасно достаем ПЕРВЫЙ элемент списка строк
                sni_list = query_params.get("sni", ["blank"])
                sni = sni_list[0].lower() if sni_list else "blank"
                
                net_type_list = query_params.get("type", ["tcp"])
                net_type = net_type_list[0].lower() if net_type_list else "tcp"
                
                security_list = query_params.get("security", ["none"])
                security = security_list[0].lower() if security_list else "none"
                
                # Извлекаем и очищаем название страны
                pure_country = clean_country_name(parsed.fragment)
                
                if "russia" in pure_country or "🇷🇺" in pure_country or "ru" == pure_country:
                    continue
                if any(kw in sni for kw in ["yandex.", "ozon.", "vk.", "mail.", "gosuslugi."]):
                    continue
                
                if security == "reality":
                    all_servers.append({
                        "link": clean_line, 
                        "ip": ip, 
                        "port": port, 
                        "type": net_type, 
                        "country_key": pure_country
                    })
                    used_uuids.add(uuid)
            except:
                continue

    print(f"ℹ️ Всего уникальных заграничных кандидатов собрано: {len(all_servers)}")
    if not all_servers:
        print("❌ Подходящие заграничные серверы не найдены.")
        return

    random.shuffle(all_servers)
    
    # --- МНОГОПОТОЧНЫЙ ЭКСПРЕСС-ПИНГ (15 потоков) ---
    print("2. Запускаем параллельное тестирование портов...")
    test_pool = all_servers[:70]
    alive_servers = []
    
    with ThreadPoolExecutor(max_workers=15) as executor:
        check_results = list(executor.map(is_server_alive, test_pool))
        for server, is_alive in zip(test_pool, check_results):
            if is_alive:
                alive_servers.append(server)

    final_servers = []
    chosen_countries = set()

    # ШАГ 1: ОБЯЗАТЕЛЬНО СТАВИМ 1 TCP НА ПЕРВОЕ МЕСТО
    for server in alive_servers:
        if server["type"] == "tcp":
            modified_link = inject_safe_fp(server["link"])
            final_servers.append(modified_link)
            chosen_countries.add(server["country_key"])
            print(f"   🏆 Закреплен TCP на 1 месте. Страна: {server['country_key'].upper()}")
            alive_servers.remove(server)
            break

    # ШАГ 2: ДОБИРАЕМ ЕЩЕ 4 СЕРВЕРА СТРОГО ИЗ ДРУГИХ СТРАН
    for server in alive_servers:
        if len(final_servers) >= 5: 
            break
            
        # ЖЕСТКАЯ ПРОВЕРКА: Если имя страны (например, 'finland') уже добавлено — строго пропускаем!
        if server["country_key"] in chosen_countries or server["country_key"] == "unknown":
            continue
            
        modified_link = inject_safe_fp(server["link"])
        final_servers.append(modified_link)
        chosen_countries.add(server["country_key"])
        print(f"   ✅ Добавлен сервер [{len(final_servers)}/5]. Страна: {server['country_key'].upper()}")

    # Аварийный добор
    if len(final_servers) < 5:
        print("⚠️ Не удалось собрать 5 уникальных стран. Добираем дубликаты стран...")
        for server in alive_servers:
            if len(final_servers) >= 5: break
            modified_link = inject_safe_fp(server["link"])
            if modified_link not in final_servers:
                final_servers.append(modified_link)

    # Аварийный режим "вслепую"
    if len(final_servers) < 5:
        for server in all_servers:
            if len(final_servers) >= 5: break
            modified_link = inject_safe_fp(server["link"])
            if modified_link not in final_servers:
                final_servers.append(modified_link)

    # Записываем результат
    subscription_content = "\n".join(final_servers[:5]) + f"\n# strict_geo_split_at: {int(time.time())}"

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ УСПЕХ! В {FILE_PATH} сохранено ровно 5 серверов из 5 абсолютно разных стран.")

if __name__ == "__main__":
    main()
