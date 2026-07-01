import json
import requests
from urllib.parse import urlparse, parse_qs

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
        
        flow = query_params.get("flow", [None])[0]
        security = query_params.get("security", ["none"])[0]
        net_type = query_params.get("type", ["tcp"])[0]
        pbk = query_params.get("pbk", [None])[0]
        path = query_params.get("path", ["/"])[0]
        sni = query_params.get("sni", [None])[0]
        host = query_params.get("host", [None])[0]
        
        # Для gRPC извлекаем serviceName
        service_name = query_params.get("serviceName", [""])[0]
        
        if uuid and ip and port:
            return {
                "ip": ip, "port": port, "uuid": uuid, "flow": flow, 
                "security": security, "type": net_type, "pbk": pbk, "path": path,
                "sni": sni, "host": host, "serviceName": service_name
            }
    except:
        pass
    return None

def modify_config(json_data, new_data):
    """Полностью перестраивает streamSettings во избежание конфликтов grpc/tcp"""
    data = json.loads(json_data)
    
    proxy_outbound = next((o for o in data.get("outbounds", []) if o.get("tag") == "proxy"), None)
    if not proxy_outbound:
        print("❌ Ошибка: В файле не найден блок с тегом 'proxy'")
        return None

    # 1. Меняем IP, порт и UUID
    vnext_list = proxy_outbound.get("settings", {}).get("vnext", [])
    if vnext_list and len(vnext_list) > 0:
        vnext = vnext_list[0]
        vnext["address"] = new_data["ip"]
        vnext["port"] = int(new_data["port"])
        
        # Настройка XTLS Flow (только для TCP Reality, для grpc удаляем)
        if new_data["security"] == "reality" and new_data["type"] == "tcp" and new_data["flow"]:
            vnext["users"][0]["flow"] = new_data["flow"]
        elif "flow" in vnext["users"][0]:
            del vnext["users"][0]["flow"]
            
        vnext["users"][0]["id"] = new_data["uuid"]

    # 2. СБРАСЫВАЕМ И СТРОИМ СНУЛЯ СЕТЕВОЙ СЛОЙ (streamSettings)
    # Это уберет застрявший "tcpSettings" при работе с grpc
    stream_settings = {
        "network": new_data["type"],
        "security": new_data["security"]
    }

    # Настройки безопасности (Reality или обычный TLS)
    # Берем оригинальный SNI из ссылки, иначе Reality не пропустит трафик!
    server_name_value = new_data["sni"] if new_data["sni"] else ""
    
    if new_data["security"] == "reality":
        stream_settings["realitySettings"] = {
            "show": False,
            "fingerprint": "chrome",
            "serverName": server_name_value,
            "publicKey": new_data["pbk"] if new_data["pbk"] else "",
            "shortId": "",
            "spiderX": ""
        }
    elif new_data["security"] == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": server_name_value,
            "allowInsecure": False
        }

    # Настройки транспорта (gRPC, WS или TCP)
    if new_data["type"] == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": new_data["serviceName"] if new_data["serviceName"] else "grpc"
        }
    elif new_data["type"] == "ws":
        stream_settings["wsSettings"] = {
            "path": new_data["path"],
            "headers": {
                "Host": new_data["host"] if new_data["host"] else server_name_value
            }
        }
    elif new_data["type"] == "tcp":
        stream_settings["tcpSettings"] = {}

    # Заменяем старый блок на новый чистый
    proxy_outbound["streamSettings"] = stream_settings
    return json.dumps(data, indent=2, ensure_ascii=False)

def main():
    print("1. Скачиваем свежие ключи от igareck...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    parsed_server = None
    for line in res_keys.text.splitlines():
        parsed_server = parse_vless_link(line)
        if parsed_server:
            print(f"-> Успешно нашли VLESS. Тип сети: {parsed_server['type']}, SNI: {parsed_server['sni']}")
            break

    if not parsed_server:
        print("❌ В списке от igareck не найдено VLESS ссылок.")
        return

    print(f"2. Читаем локальный файл {FILE_PATH}...")
    try:
        with open(FILE_PATH, "r", encoding="utf-8") as f:
            current_config = f.read()
    except FileNotFoundError:
        print(f"❌ Ошибка: Файл {FILE_PATH} не найден.")
        return

    print("3. Перестраиваем структуру JSON...")
    updated_json = modify_config(current_config, parsed_server)
    
    if not updated_json:
        return

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(updated_json)
    print("✅ Файл успешно перезаписан без конфликтов grpc/tcp.")

if __name__ == "__main__":
    main()
