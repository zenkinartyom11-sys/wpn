import json
import base64
import requests
from urllib.parse import urlparse, parse_qs

# --- НАСТРОЙКИ ---
# Вставьте сюда ваш токен, полученный на Шаге 1
GITHUB_TOKEN = "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"

# Данные вашего репозитория
REPO_OWNER = "zenkinartyom11-sys"
REPO_NAME = "wpn"
FILE_PATH = "working_config.json" # Имя файла в репозитории
BRANCH = "main"

# Ссылка, откуда робот парсит новые ключи
KEYS_LIST_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"

# --- ЛОГИКА ПАРСЕРА ---
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
        
        sni = query_params.get("sni", [None])[0]
        host = query_params.get("host", [None])[0]
        
        if uuid and ip and port:
            return {"ip": ip, "port": port, "uuid": uuid, "sni": sni, "host": host}
    except:
        pass
    return None

def modify_config(json_data, new_data):
    """Обновляет JSON новыми данными без изменения структуры vless/ws/tls"""
    data = json.loads(json_data)
    proxy_outbound = next((o for o in data.get("outbounds", []) if o.get("tag") == "proxy"), None)
    
    if not proxy_outbound:
        return None

    # Замена IP, порта, UUID
    vnext = proxy_outbound.get("settings", {}).get("vnext", [{}])[0]
    vnext["address"] = new_data["ip"]
    vnext["port"] = int(new_data["port"])
    if "users" in vnext and vnext["users"]:
        vnext["users"][0]["id"] = new_data["uuid"]

    # Управление SNI (serverName)
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

# --- РАБОТА С GITHUB API ---
def get_github_file(headers):
    """Скачивает файл и получает его SHA-хэш (нужен для перезаписи)"""
    url = f"https://github.com{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}?ref={BRANCH}"
    res = requests.get(url, headers=headers)
    if res.status_code == 200:
        file_data = res.json()
        # Декодируем содержимое из Base64, в котором его отдает GitHub API
        content = base64.b64decode(file_data["content"]).decode("utf-8")
        return content, file_data["sha"]
    return None, None

def update_github_file(headers, new_content, sha):
    """Загружает (пушит) обновленный файл обратно на GitHub"""
    url = f"https://github.com{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
    encoded_content = base64.b64encode(new_content.encode("utf-8")).decode("utf-8")
    
    payload = {
        "message": "🤖 Авто-апдейт конфигурации парсером",
        "content": encoded_content,
        "sha": sha,
        "branch": BRANCH
    }
    res = requests.put(url, headers=headers, json=payload)
    return res.status_code in [200, 201]

# --- ГЛАВНЫЙ СТАРТ ---
def main():
    api_headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }

    print("1. Заходим по ссылке проекта igareck...")
    res_keys = requests.get(KEYS_LIST_URL)
    if res_keys.status_code != 200:
        print("Ошибка скачивания базы ключей.")
        return

    parsed_server = None
    for line in res_keys.text.splitlines():
        parsed_server = parse_vless_link(line)
        if parsed_server:
            print(f"-> Найден актуальный VLESS сервер! IP: {parsed_server['ip']}")
            break

    if not parsed_server:
        print("В списке не найдено рабочих VLESS ссылок.")
        return

    print("2. Скачиваем текущий working_config.json через GitHub API...")
    current_config, file_sha = get_github_file(api_headers)
    if not current_config:
        print("Не удалось прочитать файл из вашего репозитория. Проверьте Токен и имя репо.")
        return

    print("3. Модифицируем файл новыми параметрами...")
    updated_json = modify_config(current_config, parsed_server)
    
    if updated_json:
        print("4. Отправляем обновленный файл обратно в ваш GitHub...")
        if update_github_file(api_headers, updated_json, file_sha):
            print("🚀 [УСПЕХ] Робот обновил файл! Новый конфиг уже на GitHub.")
        else:
            print("❌ Ошибка при отправке файла на GitHub.")

if __name__ == "__main__":
    main()
