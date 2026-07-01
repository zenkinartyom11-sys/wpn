import json
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

def is_server_alive(ip, port, timeout=3):
    """Проверяет, отвечает ли порт сервера (TCP-пинг)"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def get_server_country(ip):
    """Определяет страну IP-адреса через бесплатное API. Возвращает код страны (например, 'RU', 'PL')"""
    try:
        # Используем быстрое и бесплатное API без токенов
        response = requests.get(f"https://ipapi.co{ip}/json/", timeout=4)
        if response.status_code == 200:
            return response.json().get("country_code", "UNKNOWN")
    except:
        pass
    return "UNKNOWN"

def main():
    print("1. Скачиваем свежие ключи от igareck...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    chosen_link = None
    lines = res_keys.text.splitlines()
    
    print("2. Начинаем умную фильтрацию серверов...")
    for line in lines:
        if line.startswith("vless://"):
            # Отсекаем проблемные форматы сетей, которые часто ломаются
            if "type=grpc" in line or "type=ws" in line:
                continue
            
            # Разбираем ссылку, чтобы достать IP и порт для проверки
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                
                if not ip or not port:
                    continue
                    
                print(f"🔎 Проверяем кандидат-IP: {ip}...")
                
                # ТЕСТ 1: Проверка на геолокацию (Убираем Россию)
                country = get_server_country(ip)
                if country == "RU":
                    print(f"   ⚠️ Пропуск: Сервер находится в России ({country}).")
                    continue
                    
                # ТЕСТ 2: Проверка на доступность порта
                if not is_server_alive(ip, port):
                    print(f"   ❌ Пропуск: Сервер не отвечает на порту {port} (заблокирован или выключен).")
                    continue
                
                # Если все тесты пройдены успешно
                print(f"   🚀 ИДЕАЛЬНО! Страна: {country}, Порт {port} открыт. Записываем!")
                chosen_link = clean_line
                break
                
            except Exception as e:
                continue

    if not chosen_link:
        print("❌ К сожалению, во всем списке не нашлось живых зарубежных TCP-серверов.")
        return

    # 3. Сохраняем проверенную ссылку в файл подписки
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(chosen_link)
    print(f"✅ Проверенная зарубежная ссылка успешно записана в {FILE_PATH}.")

if __name__ == "__main__":
    main()
