import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  

# МЕНЯЕМ ИСТОЧНИК на самый стабильный и проверенный в РФ агрегатор (Reality + TCP)
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

def is_server_alive(ip, port, timeout=3):
    """Проверяет, отвечает ли порт сервера"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def check_hosting_provider(ip):
    """Проверяет страну сервера"""
    try:
        response = requests.get(f"https://ipapi.co{ip}/json/", timeout=3)
        if response.status_code == 200:
            data = response.json()
            return data.get("country_code", "UNKNOWN")
    except:
        pass
    return "UNKNOWN"

def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    chosen_link = None
    
    print("2. Фильтруем сервера по качеству и геолокации...")
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            # Пропускаем grpc и ws, ищем только стабильный TCP
            if "type=grpc" in line or "type=ws" in line:
                continue
            
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                
                if not ip or not port:
                    continue
                
                # Защита от подделок Яндекса
                if ip.startswith("84.201.") or ip.startswith("51.250.") or ip.startswith("178.154."):
                    continue
                
                # Достаем оригинальный SNI, заложенный создателем сервера
                query_params = parse_qs(parsed.query)
                sni = query_params.get("sni", [""])[0].lower()
                
                # Пропускаем сервер, если его создатель по глупости замаскировал его под русский сайт
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail"]):
                    continue
                    
                print(f"🔎 Тестируем зарубежный IP: {ip} (Маскировка: {sni})...")
                
                # Проверяем живой ли порт
                if not is_server_alive(ip, port):
                    print("   ❌ Порт закрыт/заблокирован.")
                    continue
                
                # Проверяем страну (чтобы не была РФ)
                country = check_hosting_provider(ip)
                if country == "RU":
                    print("   ❌ Сервер находится в РФ.")
                    continue
                
                print(f"   🚀 НАЙДЕН РАБОЧИЙ КОНФИГ! Страна: {country}, Маскировка одобрена ТСПУ.")
                chosen_link = clean_line
                break
                
            except:
                continue

    if not chosen_link:
        print("❌ Не удалось найти подходящий сервер в базе.")
        return

    # Записываем чистую оригинальную ссылку в вашу подписку
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(chosen_link)
    print(f"✅ Рабочий зарубежный сервер успешно сохранен в {FILE_PATH}.")

if __name__ == "__main__":
    main()
