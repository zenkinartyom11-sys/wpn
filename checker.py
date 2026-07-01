import json
import requests
from urllib.parse import urlparse, parse_qs

FILE_PATH = "working_config.json"  
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

# РАБОЧИЙ ДОМЕН ДЛЯ ОБХОДА ТСПУ В РФ (Можно поменять на gosuslugi.ru или oooklo.ru)
BYPASS_DOMEN = "speedtest.net"

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
        
        # Считываем оригинальные настройки из ссылки
        flow = query_params.get("flow", [None])[0]
        security = query_params.get("security", ["none"])[0]
        net_type = query_params.get("type", ["tcp"])[0]
        pbk = query_params.get("pbk", [None])[0]
        path = query_params.get("path", ["/"])[0]
        
        if uuid and ip and port:
            return {
                "ip": ip, "port": port, "uuid": uuid, "flow": flow, 
                "security": security, "type": net_type, "pbk": pbk, "path": path
            }
    except:
        pass
    return None

def modify_config(json_data, new_data):
    """Динамически перестраивает структуру outbounds с подменой SNI для обхода ТСПУ"""
    data = json.loads(json_data)
    
    proxy_outbound = next((o for o in data.get("outbounds", []) if o.get("tag") == "proxy"), None)
    if not proxy_outbound:
        print("❌ Ошибка: В файле не найден блок с тегом 'proxy'")
        return None

    # 1. Меняем IP, порт и UUID
    vnext_list = proxy_outbound.get("settings", {}).get("vnext", [])
    if vnext_list:
        vnext = vnext_list[0]
        vnext["address"] = new_data["ip"]
        vnext["port"] = int(new_data["port"])
        
        # Для Reality flow должен быть xtls-rprx-vision, если он есть
        if new_data["flow"]:
            vnext["users"][0]["flow"] = new_data["flow"]
        elif "flow" in vnext["users"][0]:
            del vnext["users"][0]["flow"]
            
        vnext["users"][0]["id"] = new_data["uuid"]

    # 2. Перенастройка сетевого слоя под Reality или WS
    stream_settings = {
        "network": new_data["type"],
        "security": new_data["security"]
    }

    # Если это VLESS REALITY (подменяем serverName на незаблокированный speedtest.net)
    if new_data["security"] == "reality":
        stream_settings["realitySettings"] = {
            "show": False,
            "fingerprint": "chrome",
            "serverName": BYPASS_DOMEN,  # Принудительный обход блокировок ТСПУ
            "publicKey": new_data["pbk"] if new_data["pbk"] else "",
            "shortId": "",
            "spiderX": ""
        }
        stream_settings["tcpSettings"] = {}

    # Если это VLESS WS + TLS (синхронизируем Host и serverName рабочим доменом)
    elif new_data["security"] == "tls" and new_data["type"] == "ws":
        stream_settings["tlsSettings"] = {
            "serverName": BYPASS_DOMEN,  # Принудительный обход блокировок ТСПУ
            "allowInsecure": False
        }
        stream_settings["wsSettings"] = {
            "path": new_data["path"],
            "headers": {
                "Host": BYPASS_DOMEN   # Должен строго совпадать с serverName
            }
        }

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
            print(f"-> Успешно нашли новый VLESS. Тип: {parsed_server['security']}")
            print(f"   IP: {parsed_server['ip']} | Робот применит маскировку под: {BYPASS_DOMEN}")
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

    print("3. Перестраиваем JSON с защитой от блокировок...")
    updated_json = modify_config(current_config, parsed_server)
    
    if not updated_json:
        return

    with open(FILE_PATH, "w", encoding="utf-8") as f:
        f.write(updated_json)
    print("✅ Файл успешно перезаписан. Трафик защищен от ТСПУ.")

if __name__ == "__main__":
    main()
