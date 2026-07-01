import json
import requests
from urllib.parse import urlparse, parse_qs

# Имя файла, который лежит в вашем репозитории рядом со скриптом
FILE_PATH = "working_config.json"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

def parse_vless_link(link):
    """Разбирает vless:// ссылку на запчасти"""
    try:
        link = link.strip()
        if not link.startswith("vless://"): 
            return None
        parsed = urlparse(link)
        uuid = parsed.username
        ip = parsed.hostname
        port = parsed.port
        query_params = parse_qs(parsed.query)
        
        # Безопасно достаем SNI и Host (берём первый элемент из списка или None)
        sni = query_params.get("sni", [None])[0]
        host = query_params.get("host", [None])[0]
        
        if uuid and ip and port:
            return {"ip": ip, "port": port, "uuid": uuid, "sni": sni, "host": host}
    except:
        pass
    return None

def modify_config(json_data, new_data):
    """Обновляет ваш JSON, сохраняя структуру vless/ws/tls"""
    data = json.loads(json_data)
    
    proxy_outbound = next((o for o in data.get("outbounds", []) if o.get("tag") == "proxy"), None)
    if not proxy_outbound:
        print("❌ Ошибка: В файле не найден блок с тегом 'proxy'")
        return None

    # Меняем IP, порт и UUID
    vnext_list = proxy_outbound.get("settings", {}).get("vnext", [])
    if vnext_list:
        vnext = vnext_list[0]
        vnext["address"] = new_data["ip"]
        vnext["port"] = int(new_data["port"])
        
        users_list = vnext.get("users", [])
        if users_list:
            users_list[0]["id"] = new_data["uuid"]

    # Управление serverName (TLS)
    stream_settings = proxy_outbound.get("streamSettings", {})
    tls_settings = stream_settings.setdefault("tlsSettings", {})
    if new_data["sni"]:
        tls_settings["serverName"] = new_data["sni"]
    elif "serverName" in tls_settings:
        del tls_settings["serverName"]

    # Управление Host (headers)
    ws_settings = stream_settings.setdefault("wsSettings", {})
    headers = ws_settings.setdefault("headers", {})
    if new_data["host"]:
        headers["Host"] = new_data["host"]
    elif "Host" in headers:
        del headers["Host"]

    return json.dumps(data, indent=2, ensure_ascii=False)

def main():
    # 1. Скачиваем ключи от igareck
    print("1. Скачиваем свежие ключи от igareck...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    parsed_server = None
    for line in res_keys.text.splitlines():
        parsed_server = parse_vless_link(line)
        if parsed_server:
            print(f"-> Успешно нашли новый VLESS. IP: {parsed_server['ip']}")
            break

    if not parsed_server:
        print("❌ В списке от igareck не найдено VLESS ссылок.")
        return

    # 2. Читаем ваш локальный файл конфигурации, который GitHub Actions уже скачал для нас
    print(f"2. Читаем локальный файл {FILE_PATH}...")
    try:
        with open(FILE_PATH, "r", encoding="utf-8") as f:
            current_config = f.read()
    except FileNotFoundError:
        print(f"❌ Ошибка: Файл {FILE_PATH} не найден в репозитории.")
        return

    # 3. Вживляем новые данные
    print("3. Изменяем параметры внутри вашего JSON...")
    updated_json = modify_config(current_config, parsed_server)
    
    if not updated_json:
        return

    # 4. Перезаписываем локальный файл на диске
    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(updated_json)
    print("✅ Файл успешно изменен локально виртуальной машиной.")

if __name__ == "__main__":
    main()
