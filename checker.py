import json
import random
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "working_config.json"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

def parse_vless_link(link):
    """Разбирает vless:// строку на запчасти"""
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
        
        # Настройка XTLS Flow (только для TCP Reality, для grpc/ws удаляем)
        if new_data["security"] == "reality" and new_data["type"] == "tcp" and new_data["flow"]:
            vnext["users"][0]["flow"] = new_data["flow"]
        elif "flow" in vnext["users"][0]:
            del vnext["users"][0]["flow"]
            
        vnext["users"][0]["id"] = new_data["uuid"]

    # 2. Перестраиваем сетевой слой (streamSettings) с нуля
    stream_settings = {
        "network": new_data["type"],
        "security": new_data["security"]
    }

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

    # Настройки транспорта
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

    proxy_outbound["streamSettings"] = stream_settings
    return json.dumps(data, indent=2, ensure_ascii=False)

def main():
    print("1. Скачиваем свежие ключи от igareck...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("❌ Ошибка скачивания базы ключей.")
        return

    # Собираем ВСЕ доступные VLESS ссылки без gRPC
    valid_links = []
    for line in res_keys.text.splitlines():
        if line.startswith("vless://") and "type=grpc" not in line:
            parsed = parse_vless_link(line)
            if parsed:
                valid_links.append(parsed)

    if not valid_links:
        print("ℹ️ Предупреждение: TCP/WS ссылки не найдены. Берем любую доступную рабочую ссылку...")
        # Если без gRPC вообще ничего нет, берем всё подряд
        for line in res_keys.text.splitlines():
            if line.startswith("vless://"):
                parsed = parse_vless_link(line)
                if parsed:
                    valid_links.append(parsed)

    if not valid_links:
        print("❌ В файле вообще не найдено VLESS конфигураций.")
        return

    # Случайным образом берем один из серверов, чтобы не перегружать один и тот же IP
    parsed_server = random.choice(valid_links)
    print(f"-> Выбран сервер. Тип сети: {parsed_server['type']}, IP: {parsed_server['ip']}, SNI: {parsed_server['sni']}")

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
    print("✅ Файл успешно перезаписан новыми рабочими параметрами.")

if __name__ == "__main__":
    main()
