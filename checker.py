import json
import random
import socket
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  

# ИСПРАВЛЕНО: Точные и актуальные ссылки на три мировых источника Reality
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"
]

# Жесткий бан российских подсетей и хостингов
RUSSIAN_IP_PREFIXES = [
    "84.201.", "51.250.", "178.154.", "91.242.", "185.12.", "185.129.", "185.22.", 
    "188.225.", "193.124.", "194.58.", "194.67.", "195.19.", "195.208.", "195.242.",
    "212.193.", "213.180.", "217.114.", "217.23.", "217.73.", "31.31.", "37.140.",
    "45.86.", "77.220.", "77.222.", "79.137.", "80.78.", "80.93.", "81.177.", 
    "82.146.", "82.202.", "83.219.", "85.113.", "85.119.", "87.251.", "89.108.",
    "89.111.", "89.169.", "89.223.", "91.210.", "91.213.", "92.53.", "93.180.",
    "94.198.", "94.250.", "95.163.", "95.213.", "185.178.", "185.204.", "194.54."
]

def is_server_alive(ip, port, timeout=1):
    """Проверяет, отвечает ли порт сервера (TCP-пинг)"""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except:
        return False

def is_russian_ip(ip):
    """Проверяет, принадлежит ли IP-адрес российскому хостингу"""
    if not ip: return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix): return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"): return True
    return False

def main():
    all_candidates = []
    
    print("1. Скачиваем базы данных со всех источников...")
    for idx, url in enumerate(SOURCES, 1):
        try:
            res = requests.get(url, timeout=5)
            if res.status_code != 200: 
                print(f"⚠️ Источник №{idx} вернул ошибку {res.status_code}. Пропускаем.")
                continue
                
            for line in res.text.splitlines():
                if line.startswith("vless://"):
                    try:
                        clean_line = line.strip()
                        parsed = urlparse(clean_line)
                        ip = parsed.hostname
                        port = parsed.port
                        
                        if not ip or not port or is_russian_ip(ip):
                            continue
                        
                        query_params = parse_qs(parsed.query)
                        
                        # БЕЗОПАСНОЕ извлечение SNI и Security (защита от падения, если ключей нет)
                        sni_list = query_params.get("sni", ["blank"])
                        sni = sni_list[0].lower() if sni_list else "blank"
                        
                        security_list = query_params.get("security", ["none"])
                        security = security_list[0].lower() if security_list else "none"
                        
                        # Фильтр русских доменов
                        if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                            continue
                        
                        # Оставляем только Reality и защищаем от дубликатов
                        if security == "reality" and clean_line not in all_candidates:
                            all_candidates.append(clean_line)
                    except:
                        continue
        except Exception as e:
            print(f"⚠️ Ошибка при обработке источника №{idx}: {e}")
            continue
            
    print(f"ℹ️ Всего уникальных заграничных кандидатов собрано: {len(all_candidates)}")

    if not all_candidates:
        print("❌ Серверы не найдены в базах источников.")
        return

    # Перемешиваем список, чтобы при каждом запуске порядок был случайным
    random.shuffle(all_candidates)
    
    working_links = []
    print("2. Запускаем массовое экспресс-тестирование портов...")
    
    # Тестируем собранные серверы
    for link in all_candidates:
        # Лимитируем до 50 штук, чтобы гитхаб успевал пропинговать за разумное время
        if len(working_links) >= 50:
            break
            
        try:
            parsed = urlparse(link)
            if is_server_alive(parsed.hostname, parsed.port):
                working_links.append(link)
                print(f"   🚀 [ЖИВОЙ] {parsed.hostname}")
        except:
            continue

    # Аварийный режим на случай, если Гитхаб заблокировал исходящий пинг
    if not working_links:
        print("⚠️ Ни один порт не ответил по пингу (возможно, блокировка исходящих соединений на GitHub).")
        print("   Сохраняем топ-30 серверов вслепую для обновления подписки...")
        working_links = all_candidates[:30]

    # Записываем абсолютно ВСЕ найденные живые ссылки
    subscription_content = "\n".join(working_links)

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"\n✅ БЕЗЛИМИТНЫЙ СБОР ЗАВЕРШЕН! В файл {FILE_PATH} сохранено {len(working_links)} серверов.")

if __name__ == "__main__":
    main()
