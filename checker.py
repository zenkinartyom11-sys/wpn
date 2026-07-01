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
    """Оставляет в файле чистый, рабочий outbound для импорта в любой клиент"""
    # Создаем с нуля структуру чистого подключения без лишних системных портов
    proxy_outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": new_data["ip"],
                    "port": int(new_data["port"]),
                    "users": [
                        {
                            "id": new_data["uuid"],
                            "encryption": "none"
                        }
                    ]
                }
            ]
        },
        "streamSettings": {
            "network": new_data["type"],
            "security": new_data["security"]
        }
    }

    # Настройки Reality / TLS
    if new_data["security"] == "reality":
        proxy_outbound["streamSettings"]["realitySettings"] = {
            "show": False,
            "fingerprint": "chrome",
            "serverName": new_data["sni"] if new_data["sni"] else "",
            "publicKey": new_data["pbk"] if new_data["pbk"] else "",
            "shortId": "",
            "spiderX": ""
        }
        # Добавляем flow только если сеть TCP
        if new_data["type"] == "tcp" and new_data["flow"]:
            proxy_outbound["settings"]["vnext"][0]["users"][0]["flow"] = new_data["flow"]
            
    elif new_data["security"] == "tls":
        proxy_outbound["streamSettings"]["tlsSettings"] = {
            "serverName": new_data["sni"] if new_data["sni"] else "",
            "allowInsecure": False
        }

    # Настройки транспорта
    if new_data["type"] == "grpc":
        proxy_outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": new_data["serviceName"] if new_data["serviceName"] else "grpc"
        }
    elif new_data["type"] == "ws":
        proxy_outbound["streamSettings"]["wsSettings"] = {
            "path": new_data["path"],
            "headers": {
                "Host": new_data["host"] if new_data["host"] else (new_data["sni"] if new_data["sni"] else "")
            }
        }
    elif new_data["type"] == "tcp":
        proxy_outbound["streamSettings"]["tcpSettings"] = {}

    return json.dumps(proxy_outbound, indent=2, ensure_ascii=False)

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
