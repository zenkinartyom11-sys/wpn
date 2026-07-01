import socket
import requests
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

# На этот домен робот будет заменять проблемные SNI для обхода ТСПУ
GOOD_SNI = "speedtest.net"

# Если в ссылке есть эти слова, домен гарантированно заблокируют вместе с VPN
BAD_SNI_KEYWORDS = ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]

def is_server_alive(ip, port, timeout=3):
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def check_hosting_provider(ip):
    try:
        # Используем резервный сервис для проверки страны
        response = requests.get(f"https://ipapi.co{ip}/json/", timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data.get("country_code", "UNKNOWN"), str(data.get("org", "")).lower()
    except:
        pass
    return "UNKNOWN", "UNKNOWN"

def main():
    print("1. Скачиваем свежие ключи от igareck...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    chosen_link = None
    
    print("2. Фильтруем и чиним ссылки...")
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            if "type=grpc" in line or "type=ws" in line:
                continue
            
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                
                if not ip or not port:
                    continue
                
                # Жёсткий бан русских подсетей
                if ip.startswith("84.201.") or ip.startswith("51.250.") or ip.startswith("178.154."):
                    continue
                
                # Извлекаем параметры запроса
                query_params = parse_qs(parsed.query)
                original_sni = query_params.get("sni", [""])[0].lower()
                
                # ПРОВЕРКА И ПОДМЕНА SNI ДЛЯ ОБХОДА ТСПУ
                has_bad_sni = any(kw in original_sni for kw in BAD_SNI_KEYWORDS)
                if has_bad_sni or not original_sni:
                    print(f"⚙️ Нашли заблокированный SNI ({original_sni}) на сервере {ip}. Меняем на {GOOD_SNI}...")
                    query_params["sni"] = [GOOD_SNI]
                
                # Пересобираем query-строку обратно
                # Выпрямляем параметры из списков parse_qs
                flat_params = {k: v[0] for k, v in query_params.items()}
                new_query = urlencode(flat_params)
                
                # Собираем модифицированную VLESS ссылку
                new_parsed = parsed._replace(query=new_query)
                modified_link = urlunparse(new_parsed)
                
                print(f"🔎 Тестируем доступность IP: {ip}...")
                if not is_server_alive(ip, port):
                    print("   ❌ Порт закрыт.")
                    continue
                
                country, org = check_hosting_provider(ip)
                if country == "RU" or "yandex" in org or "selectel" in org:
                    print("   ❌ Это российский хостинг.")
                    continue
                
                print(f"   🚀 НАЙДЕН РАБОЧИЙ СЕРВЕР! Страна: {country}. Ссылка успешно модифицирована!")
                chosen_link = modified_link
                break
                
            except Exception as e:
                continue

    if not chosen_link:
        print("❌ Не удалось найти подходящий сервер.")
        return

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(chosen_link)
    print(f"✅ Исправленная ссылка сохранена в {FILE_PATH}.")

if __name__ == "__main__":
    main()
