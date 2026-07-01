import json
import requests
# Скачиваем ваш конфиг по ссылке
response = requests.get("https://raw.githubusercontent.com/zenkinartyom11-sys/wpn/refs/heads/main/working_config.json")
исходный_json = response.text

def modify_config(json_data, new_ip, new_port, new_uuid, server_name=None, host=None):
    # Загружаем JSON-строку в словарь Python
    data = json.loads(json_data)
    
    # Ищем outbound с тегом "proxy"
    proxy_outbound = None
    for outbound in data.get("outbounds", []):
        if outbound.get("tag") == "proxy":
            proxy_outbound = outbound
            break
            
    if not proxy_outbound:
        print("Ошибка: outbound с тегом 'proxy' не найден.")
        return json.dumps(data, indent=2, ensure_ascii=False)

    # 1. Изменяем IP, Порт и UUID
    vnext_list = proxy_outbound.get("settings", {}).get("vnext", [])
    if vnext_list:
        vnext = vnext_list[0]  # Берем первый элемент списка
        vnext["address"] = new_ip
        vnext["port"] = int(new_port)
        
        users_list = vnext.get("users", [])
        if users_list:
            users_list[0]["id"] = new_uuid

    # 2. Управление serverName (внутри tlsSettings)
    stream_settings = proxy_outbound.get("streamSettings", {})
    tls_settings = stream_settings.get("tlsSettings", {})
    
    if server_name:
        tls_settings["serverName"] = server_name
    elif "serverName" in tls_settings:
        del tls_settings["serverName"]  # Полностью удаляем ключ, если передан None

    # 3. Управление Host (внутри wsSettings -> headers)
    ws_settings = stream_settings.get("wsSettings", {})
    if "headers" not in ws_settings:
        ws_settings["headers"] = {}
        
    headers = ws_settings["headers"]
    
    if host:
        headers["Host"] = host
    elif "Host" in headers:
        del headers["Host"]  # Полностью удаляем ключ, если передан None

    # Возвращаем обновленный JSON в виде красивой строки
    return json.dumps(data, indent=2, ensure_ascii=False)


# --- ТЕСТ СКРИПТА ---

исходный_json = """{
  "log": { "loglevel": "warning" },
  "inbounds": [
    { "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": { "auth": "noauth", "udp": true } }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "85.155.98.34",
            "port": 443,
            "users": [ { "id": "0970324b-8c61-4ae7-8c3f-385a6f1e17e4", "encryption": "none" } ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": { "serverName": "vpn47.cc.cd", "allowInsecure": false },
        "wsSettings": { "path": "/", "headers": { "Host": "vpn47.cc.cd" } }
      }
    },
    { "tag": "direct", "protocol": "freedom", "settings": {} }
  ]
}"""

# ПРИМЕР 1: Меняем IP, UUID и SNI, но УДАЛЯЕМ Host (передаем None)
print("=== ТЕСТ 1 (Удаление Host) ===")
res1 = modify_config(
    json_data=исходный_json,
    new_ip="1.1.1.1",
    new_port=8443,
    new_uuid="новыи-uuid-1111",
    server_name="://server.com",
    host=None  # Ключ Host исчезнет из wsSettings.headers
)
print(res1)

# ПРИМЕР 2: Меняем всё и ДОБАВЛЯЕМ/ОБНОВЛЯЕМ и serverName, и Host
print("\n=== ТЕСТ 2 (Обновление всего) ===")
res2 = modify_config(
    json_data=исходный_json,
    new_ip="2.2.2.2",
    new_port=443,
    new_uuid="новыи-uuid-2222",
    server_name="://sni.com",
    host="://host.com"
)
print(res2)
