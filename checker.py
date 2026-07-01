import socket
import requests
from urllib.parse import urlparse, parse_qs, unquote

FILE_PATH = "subscription.txt"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

def is_server_alive(ip, port, timeout=2):
    """Проверяет, отвечает ли порт сервера (TCP-пинг)"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    working_links = []
    print("2. Начинаем фильтрацию и экспресс-тест портов...")
    
    for line in res_keys.text.splitlines():
        # Нам нужно ровно 5 серверов
        if len(working_links) >= 5:
            break
            
        if line.startswith("vless://"):
            # Отсекаем мусорные типы сетей
            if "type=grpc" in line or "type=ws" in line:
                continue
            
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                
                if not ip or not port:
                    continue
                
                # 1. Жесткий бан русских подсетей (Яндекс, Селектел и т.д.)
                if ip.startswith("84.201.") or ip.startswith("51.250.") or ip.startswith("178.154."):
                    continue
                
                # 2. Проверяем маскировочный домен
                query_params = parse_qs(parsed.query)
                sni = query_params.get("sni", [""]).lower()
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                # 3. УМНОЕ ОПРЕДЕЛЕНИЕ СТРАНЫ БЕЗ API (читаем тег после знака #)
                # Декодируем ссылку (превращаем %F0%9F%87%B5 в обычные эмодзи и текст)
                decoded_fragment = unquote(parsed.fragment).lower()
                
                # Если в названии сервера есть упоминание России, пропускаем его
                if "russia" in decoded_fragment or "ru " in decoded_fragment or "🇷🇺" in decoded_fragment:
                    print(f"   ⚠️ Пропуск: Сервер помечен как российский ({decoded_fragment})")
                    continue
                
                # 4. Проверяем, живой ли порт
                if not is_server_alive(ip, port):
                    continue
                
                print(f"   🚀 Нашли рабочий зарубежный сервер! IP: {ip} | Локация: {parsed.fragment}")
                working_links.append(clean_line)
                
            except:
                continue

    if not working_links:
        print("❌ Не удалось собрать 5 живых заграничных серверов.")
        return

    # Собираем 5 ссылок через перенос строки
    subscription_content = "\n".join(working_links)

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ Успешно! В файл {FILE_PATH} сохранено ровно {len(working_links)} серверов.")

if __name__ == "__main__":
    main()
