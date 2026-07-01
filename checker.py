import json
import base64
import requests
from urllib.parse import urlparse, parse_qs

# --- НАСТРОЙКИ ---
# Вставьте ваш токен GitHub (с галочкой 'repo')
GITHUB_TOKEN = "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"

REPO_OWNER = "zenkinartyom11-sys"
REPO_NAME = "wpn"
FILE_PATH = "working_config.json"  # Имя должно точно совпадать с файлом в репозитории
BRANCH = "main"

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
        
        # Извлекаем sni и host (берем первый элемент списка параметров или None)
        sni = query_params.get("sni", [None])[0]
        host = query_params.get("host", [None])[0]
        
        if uuid and ip and port:
            return {"ip": ip, "port": port, "uuid": uuid, "sni": sni, "host": host}
    except:
        pass
    return None

def modify_config(json_data, new_data):
    """Обновляет ваш JSON из репозитория, сохраняя структуру vless/ws/tls"""
    data = json.loads(json_data)
    
    # Ищем outbound с тегом proxy
    proxy_outbound = next((o for o in data.get("outbounds", []) if o.get("tag") == "proxy"), None)
    if not proxy_outbound:
        print("❌ Ошибка: В вашем файле не найден блок с тегом 'proxy'")
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
    if GITHUB_TOKEN == "ВАШ_ГИТХАБ_ТОКЕН_СЮДА":
        print("❌ Ошибка: Вы забыли вставить ваш токен на строке 7!")
        return

    api_headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

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

    # 2. Скачиваем существующий рабочий файл из вашего репозитория через API
    print(f"2. Читаем существующий {FILE_PATH} из репозитория...")
    url = f"https://github.com{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
    res_file = requests.get(url, headers=api_headers)
    
    if res_file.status_code != 200:
        print(f"❌ GitHub API вернул ошибку {res_file.status_code}.")
        print("Проверьте, правильно ли указано имя репозитория и выдан ли токен.")
        return
        
    file_data = res_file.json()
    current_config = base64.b64decode(file_data["content"]).decode("utf-8")
    file_sha = file_data["sha"]  # Получаем обязательный маркер для перезаписи файла

    # 3. Вживляем новые данные
    print("3. Изменяем параметры внутри вашего JSON...")
    updated_json = modify_config(current_config, parsed_server)
    
    if not updated_json:
        return

    # 4. Отправляем обновленный JSON обратно
    print("4. Отправляем обновленную конфигурацию назад на GitHub...")
    put_url = f"https://github.com{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
    encoded_content = base64.b64encode(updated_json.encode("utf-8")).decode("utf-8")
    
    payload = {
        "message": "🤖 Авто-обновление параметров VLESS",
        "content": encoded_content,
        "sha": file_sha,  # Передаем маркер существующего файла
        "branch": BRANCH
    }
    
    res_put = requests.put(put_url, headers=api_headers, json=payload)
    
    if res_put.status_code == 200:
        print("🚀 [УСПЕХ] Робот обновил ваш файл прямо в репозитории!")
    else:
        print(f"❌ Ошибка отправки: {res_put.status_code}")
        print(res_put.text)

if __name__ == "__main__":
    main()
