import json
import random
import socket
import requests
import ssl
import asyncio
from urllib.parse import urlparse, parse_qs

FILE_PATH = "subscription.txt"  
# Актуальная заграничная база без Яндекса
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

async def async_is_server_alive(link, timeout=3):
    """Асин официально проверяет сервер через TLS Handshake"""
    try:
        parsed = urlparse(link)
        ip = parsed.hostname
        port = parsed.port
        if not ip or not port:
            return False
            
        port = int(port)
        query_params = parse_qs(parsed.query)
        sni_list = query_params.get("sni", [None])
        sni = sni_list[0] if sni_list else None
        server_hostname = sni if sni else ip

        context = ssl._create_unverified_context()
        
        # Асинхронное подключение (TCP)
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        
        # Асинхронный TLS-Handshake
        transport = writer.transport
        loop = asyncio.get_running_loop() # Безопасный метод для asyncio
        
        # Оборачиваем соединение в TLS
        await asyncio.wait_for(
            loop.start_tls(transport, protocol=None, ssl_context=context, server_hostname=server_hostname),
            timeout=timeout
        )
        
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

def is_russian_ip(ip):
    """Проверяет, принадлежит ли IP-адрес российскому хостингу"""
    if not ip:
        return False
    for prefix in RUSSIAN_IP_PREFIXES:
        if ip.startswith(prefix):
            return True
    if ip.endswith(".ru") or ip.endswith(".su") or ip.endswith(".by"):
        return True
    return False

async def main():
    print("1. Скачиваем проверенную базу Reality-ключей...")
    # requests синхронный, но для одного запроса в начале это не критично
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    all_valid_candidates = []
    used_uuids = set()
    
    # Сбор кандидатов
    for line in res_keys.text.splitlines():
        if line.startswith("vless://"):
            try:
                clean_line = line.strip()
                parsed = urlparse(clean_line)
                ip = parsed.hostname
                port = parsed.port
                uuid = parsed.username
                
                if not ip or not port or not uuid:
                    continue
                
                if uuid in used_uuids:
                    continue
                
                if is_russian_ip(ip):
                    continue
                
                query_params = parse_qs(parsed.query)
                sni_list = query_params.get("sni", ["blank"])
                sni = sni_list[0].lower() if sni_list else "blank"
                
                if any(kw in sni for kw in ["yandex", "ozon", "ru", "vk", "mail", "gosuslugi"]):
                    continue
                
                used_uuids.add(uuid)
                all_valid_candidates.append(clean_line)
            except:
                continue

    print(f"ℹ️ Всего найдено УНИКАЛЬНЫХ заграничных кандидатов: {len(all_valid_candidates)}")

    if not all_valid_candidates:
        print("❌ Заграничные уникальные серверы не найдены. Выключаем запись во избежание попадания РФ.")
        return

    # Перемешиваем заграничные сервера
    random.shuffle(all_valid_candidates)
    
    working_links = []
    print(f"2. Асинхронно тестируем и отбираем 5 живых заграничных серверов...")

    # Проверяем порции (батчи) по 15 серверов одновременно, чтобы не спамить сеть слишком сильно
    batch_size = 15
    for i in range(0, len(all_valid_candidates), batch_size):
        if len(working_links) >= 5:
            break
            
        batch = all_valid_candidates[i:i+batch_size]
        
        # Создаем задачи на одновременную проверку всей пачки
        tasks = [async_is_server_alive(link) for link in batch]
        results = await asyncio.gather(*tasks)
        
        # Сопоставляем результаты с серверами
        for link, is_alive in zip(batch, results):
            if is_alive:
                parsed = urlparse(link)
                print(f"   🚀 Нашли рабочий зарубежный IP: {parsed.hostname}:{parsed.port}. Добавлено ({len(working_links) + 1}/5)")
                working_links.append(link)
                if len(working_links) >= 5:
                    break

    if not working_links:
        print("⚠️ Живые порты не ответили. Записываем 5 случайных заграничных серверов без проверки...")
        working_links = all_valid_candidates[:5]

    # Записываем итоговый файл подписки
    subscription_content = "\n".join(working_links)

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(subscription_content)
    print(f"✅ УСПЕХ! В файл {FILE_PATH} сохранено ровно {len(working_links)} уникальных чистых серверов.")

if __name__ == "__main__":
    # Точка входа для запуска асинхронного скрипта
    asyncio.run(main())
