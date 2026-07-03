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
    """Находит параметр fp в ссылке и принудительно ставит chrome или safari"""
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

def extract_country(fragment):
    """Извлекает название страны или код из текстового фрагмента ссылки после знака #"""
    try:
        decoded = unquote(fragment).strip()
        # Проект barry-far в начале флага/названия часто использует эмодзи или текст
        # Берем первые несколько символов для определения уникальности локации
        words = decoded.split()
        if len(words) >= 2:
            # Если первый элемент эмодзи-флаг, то страна — это второе слово (например, "Germany")
            return words[1].lower()
        return decoded.lower() if decoded else "unknown"
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
                sni = str(query_params.get("sni", ["blank"])).lower()
                net_type = str(query_params.get("type", ["tcp"])).lower()
                security = str(query_params.get("security", ["none"])).lower()
                
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                # Достаем страну из названия
                country = extract_country(parsed.fragment)
                if "russia" in country or "ru" == country or "🇷🇺" in country:
                    continue
                
                if security == "reality":
                    all_servers.append({
                        "link": clean_line, "ip": ip, "port": port, 
                        "type": net_type, "uuid": uuid, "country": country
                    })
                    used_uuids.add(uuid)
            except:
                continue

    if not all_servers:
        print("❌ Заграничные уникальные серверы не найдены.")
        return

    print(f"ℹ Mini-анализ: Всего уникальных заграничных кандидатов в пуле: {len(all_servers)}")
    random.shuffle(all_servers)
    
    # --- МНОГОПОТОЧНЫЙ ЭКСПРЕСС-ПИНГ ---
    print("2. Запускаем параллельное тестирование портов...")
    # Берем первые 80 случайных серверов для быстрого теста
    test_pool = all_servers[:80]
    alive_servers = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        check_results = list(executor.map(is_server_alive, test_pool))
        for server, is_alive in zip(test_pool, check_results):
            if is_alive:
                alive_servers.append(server)

    final_servers = []
    used_countries = set()  # Корзина для отслеживания уникальности стран!

    # ШАГ 1: ОБЯЗАТЕЛЬНО ВЫТАСКИВАЕМ 1 ТСР НА ПЕРВОЕ МЕСТО
    for server in alive_servers:
        if server["type"] == "tcp":
            modified_link = inject_safe_fp(server["link"])
            final_servers.append(modified_link)
            used_countries.add(server["country"])
            print(f"   🏆 Закреплен TCP на 1 месте. Страна: {server['country'].upper()} | IP: {server['ip']}")
            alive_servers.remove(server)
            break

    # ШАГ 2: ДОБИРАЕМ ЕЩЕ 4 СЕРВЕРА СТРОГО ИЗ ДРУГИХ СТРАН
    for server in alive_servers:
        if len(final_servers) >= 5: 
            break
            
        # КРИТИЧЕСКАЯ ОПТИМИЗАЦИЯ: Если страна сервера уже есть в списке — полностью его пропускаем!
        if server["country"] in used_countries or server["country"] == "unknown":
            continue
            
        modified_link = inject_safe_fp(server["link"])
        final_servers.append(modified_link)
        used_countries.add(server["country"])
        print(f"   ✅ Добавлен сервер [{len(final_servers)}/5]. Страна: {server['country'].upper()} ({server['type']})")

    # Аварийный режим добора (если в базе не набралось 5 разных стран, добираем любые живые)
    if len(final_servers) < 5:
        print("⚠️ Не удалось собрать 5 абсолютно разных стран из живых портов. Добираем дублирующие страны...")
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

    # Записываем результат с принудительной меткой обновления
    subscription_content = "\n".join(final_servers[:5]) + f"\n# geo_split_optimized_at: {int(time.time())}"

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ УСПЕХ! В {FILE_PATH} сохранено 5 уникальных серверов из 5 разных стран.")

if __name__ == "__main__":
    main()
