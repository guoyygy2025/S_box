import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
from urllib.parse import urlparse, parse_qs

# ================== 基本参数 ==================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

RULE_PROXY = "https://gh-proxy.org/https://raw.githubusercontent.com"

MAX_KEEP_NODES = 40
CONNECT_TIMEOUT = 1.0
MAX_RTT = 800  # ms

# TikTok 强制解锁国家（SG / JP 二选一）
TIKTOK_OUTBOUND = "SG"

COUNTRY_KEYWORDS = {
    "US": ["us", "unitedstates"],
    "HK": ["hk", "hongkong"],
    "JP": ["jp", "japan"],
    "SG": ["sg", "singapore"],
}

# ================== 工具函数 ==================
def safe_decode(text):
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
    except:
        return text

def detect_country(text):
    t = text.lower()
    for c, keys in COUNTRY_KEYWORDS.items():
        if any(k in t for k in keys):
            return c
    return "US"

def speed_test(link):
    try:
        u = urlparse(link)
        host = u.hostname
        port = u.port or 443
        start = time.time()
        s = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        s.close()
        rtt = (time.time() - start) * 1000
        if rtt <= MAX_RTT:
            return link, rtt
    except:
        pass
    return None

# ================== 基础模板 ==================
def base_config():
    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "https://223.5.5.5/dns-query", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"},
                {"tag": "dns_fakeip", "address": "fakeip"}
            ],
            "rules": [
                {
                    "rule_set": ["geosite-ads", "adblock"],
                    "server": "dns_block",
                    "disable_cache": True
                },
                {
                    "domain_suffix": [
                        "youtube.com","googlevideo.com","ytimg.com","ggpht.com",
                        "tiktok.com","tiktokcdn.com","byteoversea.com","ibytedtos.com"
                    ],
                    "server": "dns_proxy"
                },
                {"rule_set": "geosite-cn", "server": "dns_local"},
                {"query_type": ["A","AAAA"], "server": "dns_fakeip"}
            ],
            "final": "dns_proxy",
            "fakeip": {"enabled": True}
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "inet4_address": ["172.19.0.1/30"],
            "auto_route": True,
            "strict_route": True,
            "sniff": True,
            "sniff_override_destination": True
        }],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"ip_is_private": True, "outbound": "direct"},

                {"domain_suffix": ["openai.com","chatgpt.com"], "outbound": "US"},
                {
                    "domain_suffix": [
                        "tiktok.com","tiktokcdn.com","byteoversea.com","ibytedtos.com"
                    ],
                    "outbound": TIKTOK_OUTBOUND
                },
                {"domain_suffix": ["youtube.com","googlevideo.com"], "outbound": "HK"},

                {"rule_set": ["geosite-ads","adblock"], "action": "reject"},
                {"rule_set": ["geoip-cn","geosite-cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "rule_set": [
                {
                    "tag": "adblock",
                    "type": "remote",
                    "format": "binary",
                    "url": f"{RULE_PROXY}/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
                },
                {
                    "tag": "geosite-ads",
                    "type": "remote",
                    "format": "binary",
                    "url": f"{RULE_PROXY}/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"
                },
                {
                    "tag": "geosite-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": f"{RULE_PROXY}/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
                },
                {
                    "tag": "geoip-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": f"{RULE_PROXY}/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
                }
            ]
        },
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto","US","HK","JP","SG"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
            {"type": "selector", "tag": "US", "outbounds": []},
            {"type": "selector", "tag": "HK", "outbounds": []},
            {"type": "selector", "tag": "JP", "outbounds": []},
            {"type": "selector", "tag": "SG", "outbounds": []},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block"}
        ]
    }

# ================== 主流程 ==================
def main():
    print("🚀 构建 sing-box 终极配置中...")

    raw_links = []
    for src in SOURCES:
        try:
            r = requests.get(src, timeout=6)
            text = r.text
            if "://" not in text:
                text = safe_decode(text)
            raw_links += re.findall(r"(vless|trojan)://[^\s#]+", text)
        except:
            pass

    raw_links = list(set(raw_links))

    with concurrent.futures.ThreadPoolExecutor(60) as ex:
        tested = [r for r in ex.map(speed_test, raw_links) if r]

    tested.sort(key=lambda x: x[1])
    fast_links = [x[0] for x in tested[:MAX_KEEP_NODES]]

    cfg = base_config()

    for link in fast_links:
        u = urlparse(link)
        q = parse_qs(u.query)
        country = detect_country(link)
        tag = f"{country}-{u.hostname}"

        node = {
            "type": u.scheme,
            "tag": tag,
            "server": u.hostname,
            "server_port": u.port or 443
        }

        if u.scheme == "vless":
            node.update({
                "uuid": u.username,
                "flow": "xtls-rprx-vision",
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", ["www.cloudflare.com"])[0],
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }
            })
            if "pbk" in q:
                node["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": q["pbk"][0],
                    "short_id": q.get("sid", [""])[0],
                    "handshake": {"server": "www.cloudflare.com", "server_port": 443}
                }

        if u.scheme == "trojan":
            node.update({
                "password": u.username,
                "tls": {"enabled": True, "server_name": q.get("sni",[u.hostname])[0]}
            })

        cfg["outbounds"].append(node)

        for o in cfg["outbounds"]:
            if o.get("tag") == country:
                o["outbounds"].append(tag)
            if o.get("tag") == "auto":
                o["outbounds"].append(tag)

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

    print("✅ config.json 生成完成（终极版）")

if __name__ == "__main__":
    main()
