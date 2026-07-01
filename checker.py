import json
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

# Список запрещенных в РФ подсетей хостингов, куда часто пихают "поддельные" зарубежные сервера
BAN_ISP_KEYWORDS = ["yandex", "selectel", "vdsina", "ru-center", "gcore", "mironet", "serverspace", "as208222"]

def is_server_alive(ip, port, timeout=3):
    """Проверяет, отвечает ли порт сервера (TCP-пинг)"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def check_hosting_provider(ip):
    """
    Резервный метод: Проверяет имя провайдера через альтернативный 
    бесплатный сервис ip-api.com (у него лимит поштучный, а не на весь Гитхаб)
    """
    try:
        # Этот сервис выдает лимит на конкретную минуту, на гитхабе работает стабильнее
        response = requests.get(f"http://ip-api.com{ip}?fields=status,countryCode,org,as", timeout=3)
        if response.status_code == 200:
            res_data = response.json()
            if res_data.get("status") == "success":
                country = res_data.get("countryCode", "UNKNOWN")
                provider = str(res_data.get("org", "")).lower() + " " + str(res_data.get("as", "")).lower()
                return country, provider
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
    lines = res_keys.text.splitlines()
    
    print("2. Начинаем жесткую фильтрацию серверов...")
    for line in lines:
        if line.startswith("vless://"):
            # Пропускаем grpc и ws
            if "type=grpc" in line or "type=ws" in line:
                continue
            
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                
                if not ip or not port:
                    continue
                
                # КРИТИЧЕСКАЯ ФИЛЬТРАЦИЯ ПО ИЗВЕСТНЫМ IP ЯНДЕКСА
                # Адреса вида 84.201.х.х — это ВСЕГДА Москва (Яндекс.Облако)
                if ip.startswith("84.201.") or ip.startswith("51.250.") or ip.startswith("178.154."):
                    print(f"   ⚠️ Жесткий бан: {ip} гарантированно является сервером Яндекс.Облака (РФ). Пропуск.")
                    continue
                    
                print(f"🔎 Тестируем сервер: {ip}...")
                
                # Запрашиваем информацию о стране и провайдере
                country, provider = check_hosting_provider(ip)
                
                # Проверка 1: Запрет по коду страны
                if country == "RU":
                    print(f"   ❌ Бан: Сервер определен как Российский (RU).")
                    continue
                
                # Проверка 2: Запрет по имени провайдера (Если базы определили его криво как Польшу, но это Яндекс)
                is_banned_isp = any(keyword in provider for keyword in BAN_ISP_KEYWORDS)
                if is_banned_isp:
                    print(f"   ❌ Бан: Обнаружен русский хостинг-провайдер в логах ({provider}).")
                    continue
                
                # Проверка 3: Живой ли порт
                if not is_server_alive(ip, port):
                    print(f"   ❌ Пропуск: Сервер не отвечает на порту {port}.")
                    continue
                
                # Если все три сита пройдены:
                print(f"   🚀 НАЙДЕН НАСТОЯЩИЙ ЗАГРАНИЧНЫЙ СЕРВЕР! Страна: {country}, Провайдер: {provider}")
                chosen_link = clean_line
                break
                
            except:
                continue

    if not chosen_link:
        print("❌ Не удалось найти чистый зарубежный сервер без блокировок.")
        return

    # 3. Записываем результат
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(chosen_link)
    print(f"✅ Истинный зарубежный сервер сохранен в {FILE_PATH}.")

if __name__ == "__main__":
    main()
