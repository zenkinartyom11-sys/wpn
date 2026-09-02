import ssl, json, socket, requests, time, os, base64, re
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# === НАСТРОЙКИ ===
TARGET_COUNT   = 10
CHECK_TIMEOUT  = 3
MAX_CHECK      = 80
FETCH_WORKERS  = 50
CHECK_WORKERS  = 40

# === ВСТАВЬ ВСЕ 400 ССЫЛОК СЮДА ===
ALL_SOURCES = [
    # ... вставь весь свой массив ссылок сюда ...
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/YasserDivaR/pr0xy/refs/heads/main/ShadowSocks2021.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vmess.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/trojan.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/refs/heads/main/sublinks/mix.txt",
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector_Py/refs/heads/main/sub/Mix/mix.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/mix",
    "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/All_Config.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/refs/heads/main/AzadNet.txt",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Vmess.txt",
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/feat/ai-crawler-v2/nodes/clashmeta.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/feat/ai-crawler-v2/nodes/clashnode.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/feat/ai-crawler-v2/nodes/clashstair.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/feat/ai-crawler-v2/nodes/freeclashnode.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/feat/ai-crawler-v2/nodes/nodev2ray.txt",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/feat/ai-crawler-v2/nodes/oneclash.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/refs/heads/main/server.txt",
    "https://github.com/mrvcoder/V2rayCollector/raw/refs/heads/main/vless_iran.txt",
    "https://github.com/vxiaov/free_proxies/raw/refs/heads/main/links.txt",
    "https://github.com/peasoft/NoMoreWalls/raw/refs/heads/master/list_raw.txt",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/refs/heads/main/v2ray/clashnodecc.txt",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/refs/heads/main/v2ray/naidounode.txt",
    "https://raw.githubusercontent.com/xiaoji235/airport-free/refs/heads/main/v2ray/v2rayshare.txt",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/refs/heads/master/list_raw.txt",
    "https://raw.githubusercontent.com/mehran1404/Sub_Link/refs/heads/main/V2RAY-Sub.txt",
    "https://github.com/nyeinkokoaung404/V2ray-Configs/raw/refs/heads/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vmess.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/trojan.txt",
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/ss.txt",
    "https://raw.githubusercontent.com/ninjastrikers/v2ray-configs/main/splitted/vmess.txt",
    "https://raw.githubusercontent.com/ninjastrikers/v2ray-configs/main/splitted/vless.txt",
    "https://raw.githubusercontent.com/ninjastrikers/v2ray-configs/main/splitted/trojan.txt",
    "https://raw.githubusercontent.com/ninjastrikers/v2ray-configs/main/splitted/ss.txt",
    "https://raw.githubusercontent.com/ninjastrikers/v2ray-configs/main/splitted/hysteria.txt",
    "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/refs/heads/main/Config_jo.txt",
    "https://raw.githubusercontent.com/rango-cfs/NewCollector/refs/heads/main/v2ray_links.txt",
    "https://raw.githubusercontent.com/aqayerez/MatnOfficial-VPN/refs/heads/main/MatnOfficial",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
    "https://raw.githubusercontent.com/nscl5/5/refs/heads/main/configs/at/all.txt",
    "https://raw.githubusercontent.com/HosseinKoofi/GO_V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/blacklist.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/1",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/Ai123999/1Mond/refs/heads/main/1Mond_Notorgamers",
    "https://raw.githubusercontent.com/Ai123999/2Tues/refs/heads/main/2Tues_Notorgamers",
    "https://raw.githubusercontent.com/Ai123999/3Wend/refs/heads/main/3Wend_Notorgamers",
    "https://raw.githubusercontent.com/Ai123999/4Thur/refs/heads/main/4Thur_Notorgamers",
    "https://raw.githubusercontent.com/Ai123999/5Frid/refs/heads/main/5Frid_Notorgamers",
    "https://raw.githubusercontent.com/Ai123999/6Satu/refs/heads/main/6Satu_Notorgamers",
    "https://raw.githubusercontent.com/Ai123999/7Sand/refs/heads/main/7Sand_Notorgamers",
    "https://raw.githubusercontent.com/Ai123999/WhiteeListSub/refs/heads/main/whitelistkeys",
    "https://raw.githubusercontent.com/Ai123999/WhiteKeys/refs/heads/main/WhiteKeys",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/koteey/Mr.Kerosin-VPN/refs/heads/main/proxies.txt",
    "https://raw.githubusercontent.com/koteey/Mr.Kerosin-VPN/refs/heads/main/work.proxies.txt",
    "https://raw.githubusercontent.com/KiryaScript/white-lists/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/KiryaScript/white-lists/refs/heads/main/githubmirror/27.txt",
    "https://raw.githubusercontent.com/KiryaScript/white-lists/refs/heads/main/githubmirror/28.txt",
    "https://alley.serv00.net/1",
    "https://alley.serv00.net/2",
    "https://cdn.jsdelivr.net/gh/EtoNeYaProject/EtoNeYaProject.github.io@refs/heads/main/1",
    "https://raw.githubusercontent.com/r3zarahimi/tg-v2ray-configs-every2h/main/Config_jo.txt",
    "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/main-sub.txt",
    "https://raw.githubusercontent.com/LimeHi/LimeVPN/refs/heads/main/LimeVPN.txt",
    "https://raw.githubusercontent.com/FalerChannel/FalerChannel/refs/heads/main/configs",
    "https://raw.githubusercontent.com/officialdakari/psychic-octo-tribble/refs/heads/main/subwl.txt",
    "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/1Mond",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/2Tues",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/3Wend",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/4Thur",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/5Frid",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/6Satu",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/7Sand",
    "https://raw.githubusercontent.com/terik21/HiddifySubs-VlessKeys/refs/heads/main/WhiteKeys",
    "https://raw.githubusercontent.com/gbwltg/gbwl/refs/heads/main/m2EsPqwmlc",
    "https://sub-001.dns-on-fire.net/api/sub/4z1ggudxMZ4Y8v6s",
    "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/BlackList.txt",
    "https://gbr.mydan.online/configs",
    "https://autosub-config.vercel.app/sub.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/1.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/2.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/3.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/4.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/5.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/6.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/7.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/8.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/9.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/10.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/11.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/12.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/13.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/14.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/15.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/16.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/17.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/18.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/19.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/20.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/21.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/22.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/23.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/24.txt",
    "https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/25.txt",
    "https://raw.githubusercontent.com/47AgEnT-47/vpn-configs/refs/heads/main/configs.txt",
    "https://stpcd.link/sub/1ccc074f-b7dc-4dd2-accd-c08653b0fa37#HelloWorld",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6.txt",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6BL.txt",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyaktestru.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part1.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part2.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part3.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/RU_Best/ru_white_part4.txt",
    "https://raw.githubusercontent.com/kort0881/vpn-checker-backend/main/checked/My_Euro/my_euro_part1.txt",
    "https://subrostunnel.vercel.app/gen.txt",
    "https://raw.githubusercontent.com/amindzlvess-boop/SlashVPN/refs/heads/main/vpn.txt",
    "https://raw.githubusercontent.com/prominbro/KfWL/refs/heads/main/KfWL.txt",
    "https://raw.githubusercontent.com/prominbro/KfWL/refs/heads/main/KfWLcheck.txt",
    "https://gitverse.ru/api/repos/kfwlru/base/raw/branch/main/KfWL.txt",
    "https://gitverse.ru/api/repos/kfwlru/base/raw/branch/main/KfWLcheck.txt",
    "https://gistpad.com/raw/greywebs-and-vless-vpn-tg-reverse-engineer-s-basement",
    "https://gistpad.com/raw/mia-vpn-tg-reverse-engineer-s-basement",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
    "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/merged.txt",
    "https://raw.githubusercontent.com/prominbro/sub/refs/heads/main/212.txt",
    "https://obwlsub.vercel.app/wwh",
    "https://cdn.jsdelivr.net/gh/AbikusSudo/RussiaVPN@main/docs/index.html",
    "https://alley.serv00.net/other",
    "https://alley.serv00.net/youtube",
    "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/main/subscriptions/FreeCFGHub1.txt",
    "https://gistpad.com/raw/lumar-vpn-all-tg-reverse-engineer-s-basement",
    "https://raw.githubusercontent.com/StealthNetVPN/StealthNet/refs/heads/main/StealthNetVPN",
    "https://raw.githubusercontent.com/Mihuil121/vpn-checker-backend-fox/main/checked/My_Euro/euro_black.txt",
    "https://raw.githubusercontent.com/ArtemAfonasyev/hentai-goida-subscription/refs/heads/main/subscription.txt",
    "https://raw.githubusercontent.com/ewecrow78-gif/whitelist1/main/list.txt",
    "https://raw.githubusercontent.com/Temnuk/naabuzil/refs/heads/main/wifi",
    "https://raw.githubusercontent.com/LimeHi/LimeVPN/refs/heads/main/LimeVPN.txt?v=1",
    "https://gitverse.ru/api/repos/ru-wbl/wl/raw/branch/master/OutlineVPN%2FOutlineVPN.txt",
    "https://raw.githubusercontent.com/ShadowException/VPN/refs/heads/main/configs/VPN-cat",
    "https://raw.githubusercontent.com/luxxuria/harvester/refs/heads/main/non_ru.txt",
    "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta7.txt",
    "https://raw.githubusercontent.com/opti4riponty-arch/VLESS-Co/refs/heads/main/VLESS%20%26%20Co",
    "https://gitverse.ru/api/repos/flaafix/AetrisVPN/raw/branch/master/AetrisVPN.txt",
    "https://storage.googleapis.com/fptn.org/index.html",
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/34.txt",
    "https://gl.gosapi.com/sub/s_j0kr2PjW0Eow95?providerid=ZOth3lct",
    "https://sub.new-meme-connet.ru/f088b6f27",
    "https://app.proxy-slon.shop/v1/service/sub/e754770b-a24c-4093-920a-a22d10b24f75",
    "https://www.dropbox.com/scl/fi/sk6i6etx9mmx5xm98xu36/VLESS.txt?rlkey=utvnt1nbv07ixxwax6icu7fca&raw=1",
    "https://translate.yandex.ru/translate?url=https://raw.githubusercontent.com/v0id9/vpn-configs/refs/heads/main/vpn.txt",
    "https://app.proxy-slon.shop/v1/service/sub/eb73dd50-2e6d-447b-baa9-ed6efc81940c",
    "https://raw.githubusercontent.com/seknei3/psychic-fiestas/refs/heads/main/vpn.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Protocol/hy2.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/refs/heads/main/Configs/VMESS-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/refs/heads/main/Configs/TROJAN-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/DukeMehdi/FreeList-V2ray-Configs/refs/heads/main/Configs/SS-DukeMehdi-Configs.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/Argh73/V2Ray-Vault/refs/heads/main/data/sub/all_configs.txt",
    "https://raw.githubusercontent.com/kingowow/Kingo-vpn/refs/heads/main/merged_config.txt",
    "https://raw.githubusercontent.com/redfree8/config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://gist.githubusercontent.com/pidarasuebisov-afk/e220b44264242d1a97c0908aba091edd/raw/PKN%20cocnyL",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
    "https://raw.githubusercontent.com/HenonBank/Russia_LTE/refs/heads/main/v2ray_sub.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/Eternity.txt",
    "https://gist.githubusercontent.com/shirinyannver31-ux/6b16a88d07db0830b49ab8b02536c3b6/raw/VedaVPN.txt",
    "https://github.com/Delta-Kronecker/V2ray-Config/blob/main/config/all_configs.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/sub.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Vless.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Vmess.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/ShadowSocks.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Trojan.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Tuic.txt",
    "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Hysteria2.txt",
    "https://raw.githubusercontent.com/flaafix/AetrisVPN-black-list/refs/heads/main/configs.txt",
    "https://cyb-portal.com/CP-001",
    "https://cyb-portal.com/CP-002",
    "https://cyb-portal.com/CP-003",
    "https://cyb-portal.com/CP-005",
    "https://cyb-portal.com/CP-009",
    "https://cyb-portal.com/CP-010",
    "https://cyb-portal.com/CP-012",
    "https://cyb-portal.com/CP-013",
    "https://cyb-portal.com/CP-014",
    "https://cyb-portal.com/CP-015",
    "https://cyb-portal.com/CP-016",
    "https://cyb-portal.com/CP-017",
    "https://cyb-portal.com/CP-018",
    "https://cyb-portal.com/CP-019",
    "https://cyb-portal.com/CP-020",
    "https://cyb-portal.com/CP-021",
    "https://cyb-portal.com/CP-022",
    "https://cyb-portal.com/CP-023",
    "https://cyb-portal.com/CP-024",
    "https://cyb-portal.com/CP-025",
    "https://cyb-portal.com/CP-026",
    "https://cyb-portal.com/CP-027",
    "https://cyb-portal.com/CP-028",
    "https://cyb-portal.com/CP-029",
    "https://cyb-portal.com/CP-030",
    "https://cyb-portal.com/CP-032",
    "https://cyb-portal.com/CP-033",
    "https://cyb-portal.com/CP-034",
    "https://cyb-portal.com/CP-036",
    "https://cyb-portal.com/CP-037",
    "https://cyb-portal.com/CP-039",
    "https://cyb-portal.com/CP-041",
    "https://cyb-portal.com/CP-043",
    "https://cyb-portal.com/CP-044",
]

# === Автоматическое распределение по URL ===
WHITE_KEYWORDS = ["white", "wl", "wbl", "whitelist", "whitelistkeys"]
BLACK_KEYWORDS = ["black", "bl", "blacklist", "non_ru", "euro"]

URLS_WHITE, URLS_BLACK, URLS_MIXED = [], [], []
for url in ALL_SOURCES:
    u = url.lower()
    is_white = any(k in u for k in WHITE_KEYWORDS)
    is_black = any(k in u for k in BLACK_KEYWORDS)
    if is_white and not is_black:
        URLS_WHITE.append(url)
    elif is_black and not is_white:
        URLS_BLACK.append(url)
    else:
        URLS_MIXED.append(url)

TRUSTED_SNIS = [
    "stripe.com", "paypal.com", "checkout.com", "adyen.com", "braintreepayments.com",
    "worldpay.com", "skrill.com", "neteller.com", "payoneer.com", "authorize.net",
    "sagepay.co.uk", "klarna.com", "squareupsandbox.com", "shopify.com", "swift.com",
    "revolut.com", "wise.com", "westernunion.com", "moneygram.com", "n26.com",
    "plaid.com", "finastra.com", "visa.com", "mastercard.com", "americanexpress.com",
    "hsbc.com", "jpmorganchase.com", "chase.com", "goldmansachs.com", "morganstanley.com",
    "citibank.com", "citi.com", "bankofamerica.com", "bofa.com", "barclays.com",
    "db.com", "bnpparibas.com", "ubs.com", "credit-suisse.com", "binance.com",
    "coinbase.com", "kraken.com", "bitstamp.net", "blockchain.info", "etherscan.io",
]

# Жёсткий фильтр: только vless и hy2
VALID_PROTOCOLS = ("vless://", "hysteria2://", "hy2://")

RUSSIAN_PREFIXES = [
    "5.42.", "5.43.", "5.101.", "5.130.", "5.143.", "5.187.", "5.188.", "31.28.", "31.31.", "31.40.",
    "31.43.", "31.134.", "31.162.", "31.173.", "37.18.", "37.29.", "37.110.", "37.140.", "37.143.",
    "37.192.", "37.235.", "45.8.", "45.9.", "45.12.", "45.66.", "45.67.", "45.81.", "45.86.",
    "45.89.", "45.90.", "45.95.", "45.130.", "45.132.", "45.135.", "45.141.", "45.142.", "45.145.",
    "45.155.", "45.156.", "46.3.", "46.8.", "46.17.", "46.38.", "46.39.", "46.146.", "46.147.",
    "46.148.", "46.161.", "46.182.", "46.242.", "51.124.", "51.250.", "62.33.", "62.76.", "62.109.",
    "62.117.", "62.148.", "62.152.", "62.213.", "77.37.", "77.41.", "77.51.", "77.72.", "77.73.",
    "77.74.", "77.82.", "77.108.", "77.220.", "77.222.", "77.232.", "77.242.", "77.244.", "78.25.",
    "78.29.", "78.36.", "78.37.", "78.46.", "78.47.", "78.81.", "78.85.", "78.108.", "78.109.",
    "78.140.", "79.104.", "79.111.", "79.120.", "79.133.", "79.134.", "79.137.", "79.143.", "79.174.",
    "80.64.", "80.68.", "80.78.", "80.80.", "80.82.", "80.83.", "80.87.", "80.92.", "80.93.",
]

_dns_cache = {}

def resolve(host):
    if host in _dns_cache: return _dns_cache[host]
    try: ip = socket.gethostbyname(host)
    except: ip = None
    _dns_cache[host] = ip
    return ip

def is_russian_ip(ip_or_domain):
    if not ip_or_domain: return False
    target_ip = ip_or_domain
    if not ip_or_domain.replace('.', '').isdigit():
        target_ip = resolve(ip_or_domain)
        if not target_ip: return True
    if any(target_ip.startswith(p) for p in RUSSIAN_PREFIXES): return True
    try:
        parts = target_ip.split('.')
        if len(parts) >= 4:
            first_octet = int(parts[0])
            if 91 <= first_octet <= 95 or first_octet in (176, 178, 185, 188, 212, 213) or 193 <= first_octet <= 195: return True
            if first_octet == 128 and 68 <= int(parts[1]) <= 75: return True
    except: pass
    return target_ip.endswith((".ru", ".su", ".by"))

def smart_decode(text):
    """Распаковывает base64 (включая двойной) и вытаскивает только vless/hy2."""
    result_lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line: continue
        if any(line.startswith(p) for p in VALID_PROTOCOLS):
            result_lines.append(line)
            continue
        t = line
        decoded = False
        for _ in range(3):
            try:
                pad = '=' * (-len(t) % 4)
                dec = base64.b64decode(t + pad).decode('utf-8', errors='ignore')
                if any(p in dec for p in VALID_PROTOCOLS):
                    result_lines.extend([l.strip() for l in dec.splitlines() if l.strip()])
                    decoded = True
                    break
                t = dec.strip()
                if not t: break
            except: break
        if not decoded and "://" in line:
            matches = re.findall(r'(vless://[^\s<>"\'`,]+|hysteria2://[^\s<>"\'`,]+|hy2://[^\s<>"\'`,]+)', line)
            result_lines.extend(matches)
    return "\n".join(result_lines)

def fetch_one(url):
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code == 200:
            return smart_decode(r.text.lstrip('\ufeff'))
    except: pass
    return ""

def extract_info(line):
    try:
        parsed = urlparse(line)
        host, port, user = parsed.hostname, parsed.port, parsed.username
        if not host or not port:
            tail = line.split('://', 1)[1]
            user = tail.split('@', 1)[0]
            hostport = tail.split('@', 1)[1].split('/', 1)[0].split('?', 1)[0]
            host, port = hostport.rsplit(':', 1)
            port = int(port)
        q = parse_qs(parsed.query)
        sni = (q.get('sni', ['']) or [''])[0].lower()
        security = (q.get('security', ['']) or [''])[0]
        return host, port, user, sni, security
    except: return None

def parse_source_text(text, used_keys, is_white_list=False):
    candidates, seen = [], set()
    for line in text.splitlines():
        line = line.strip().lstrip('\ufeff')
        if not any(line.startswith(p) for p in VALID_PROTOCOLS): continue
        info = extract_info(line)
        if not info: continue
        host, port, user, sni, security = info
        key = (user, host, port)
        if key in seen or key in used_keys: continue
        has_trusted = any(t in sni for t in TRUSTED_SNIS)
        if not (is_white_list and has_trusted):
            if is_russian_ip(host): continue
        seen.add(key)
        used_keys.add(key)
        candidates.append((line, has_trusted))
    return candidates

def test_server(item):
    line, has_trusted = item
    try:
        proto = line.split('://', 1)[0]
        info = extract_info(line)
        if not info: return None
        host, port, user, sni, security = info
        if not host or not port: return None
        sni = sni or host
        if proto in ('hysteria2', 'hy2'):
            if resolve(host) is None: return None
            return (line, 8.0, has_trusted)
        t0 = time.monotonic()
        sock = socket.create_connection((host, port), timeout=CHECK_TIMEOUT)
        tcp_time = time.monotonic() - t0
        score = tcp_time + 0.5
        if security in ('tls', 'reality', 'xtls'):
            ctx = ssl._create_unverified_context()
            try: ctx.set_ciphers('DEFAULT@SECLEVEL=0')
            except: pass
            try:
                sock.settimeout(CHECK_TIMEOUT)
                with ctx.wrap_socket(sock, server_hostname=sni):
                    score = time.monotonic() - t0
                sock = None
            except:
                if security != 'reality':
                    try: sock.close()
                    except: pass
                    return None
                score = tcp_time + 2.0
        if sock:
            try: sock.close()
            except: pass
        return (line, score, has_trusted)
    except: return None

def verify_candidates(candidates, need):
    alive = []
    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as ex:
        futures = [ex.submit(test_server, c) for c in candidates[:MAX_CHECK]]
        for f in as_completed(futures):
            res = f.result()
            if res:
                alive.append(res)
                if len(alive) >= need * 2: break
    return alive

def main():
    t_start = time.monotonic()
    print("[*] Парсер v6: vless+hy2, авто-base64, без кэша")
    print(f"[*] Источников: {len(URLS_WHITE)} белых, {len(URLS_BLACK)} чёрных, {len(URLS_MIXED)} смешанных")

    print("[*] Скачиваю источники...")
    white_urls = URLS_WHITE + URLS_MIXED
    black_urls = URLS_BLACK + URLS_MIXED

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        white_text = "\n".join(r for r in ex.map(fetch_one, white_urls) if r)
        black_text = "\n".join(r for r in ex.map(fetch_one, black_urls) if r)

    print(f"[*] Скачано байт: белых {len(white_text)}, чёрных {len(black_text)}")
    print("[*] Парсинг (только vless + hy2)...")
    used_keys = set()
    white_c = parse_source_text(white_text, used_keys, is_white_list=True)
    black_c = parse_source_text(black_text, used_keys, is_white_list=False)

    print(f"[*] Кандидатов: белых {len(white_c)}, чёрных {len(black_c)}")
    print("[*] Проверяю живость (TCP + TLS)...")

    white_alive = verify_candidates(white_c, TARGET_COUNT)
    black_alive = verify_candidates(black_c, TARGET_COUNT)

    print(f"[+] Живых: белых {len(white_alive)}, чёрных {len(black_alive)}")

    white_alive.sort(key=lambda x: (0 if x[2] else 1, x[1]))
    black_alive.sort(key=lambda x: x[1])

    final_white = [l for l, s, t in white_alive[:TARGET_COUNT]]
    final_black = [l for l, s, t in black_alive[:TARGET_COUNT]]

    if len(final_white) >= 1:
        with open("white_subscription.txt", "w", encoding="utf-8") as f:
            f.write("#profile-title: Белый список (РКН)\n" + "\n".join(final_white))
        print(f"[+] Белый список обновлён: {len(final_white)} серверов")
    else:
        print("[!] Белый список не обновлён — нет живых")

    if len(final_black) >= 1:
        with open("black_subscription.txt", "w", encoding="utf-8") as f:
            f.write("#profile-title: Чёрный список (РКН)\n" + "\n".join(final_black))
        print(f"[+] Чёрный список обновлён: {len(final_black)} серверов")
    else:
        print("[!] Чёрный список не обновлён — нет живых")

    print(f"[*] Время: {time.monotonic() - t_start:.1f} сек")

if __name__ == "__main__":
    main()
