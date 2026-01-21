import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
from urllib.parse import urlparse, parse_qs

# ================== 参数 ==================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

RULE_PROXY = "https://gh-proxy.org/https://raw.githubusercontent.com"

MAX_KEEP_NODES = 40
CONNECT_TIMEOUT = 3
MAX_RTT = 2000
TIKTOK_OUTBOUND = "JP"

COUNTRY_KEYWORDS = {
    "US": ["us", "united"],
    "HK": ["hk", "hong"],
    "JP": ["jp", "japan"],
    "SG": ["sg", "sing"],
}

# ================== 工具 ==================
def safe_decode(text):
    try:
        text = text.strip().replace("\n", "")
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
    except:
        return text

def detect_country(text):
    t = text.lower()
    for c, ks in COUNTRY_KEYWORDS.items():
        if any(k in t for k in ks):
            return c
    return "US"

def speed_test(link):
    try:
        u = urlparse(link)
        s = socket.create_connection((u.hostname, u.port or 443), timeout=CONNECT_TIMEOUT)
        s.close()
        return link, (time.time())
    except:
        return None

# ================== 模板 ==================
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
                {"rule_set": ["geosite-ads", "adblock"], "server": "dns_block"},
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
                {"domain_suffix": ["tiktok.com","tiktokcdn.com"], "outbound": TIKTOK_OUTBOUND},
                {"rule_set": ["geoip-cn","geosite-cn"], "outbound": "direct"},
                {"rule_set": ["geosite-ads","adblock"], "action": "reject"}
            ],
            "final": "proxy",
            "rule_set": [
                {"tag": "adblock", "type": "remote", "format": "binary",
                 "url": f"{RULE_PROXY}/217heidai/adblockfilters/main/rules/adblocksingbox.srs"},
                {"tag": "geosite-ads", "type": "remote", "format": "binary",
                 "url": f"{RULE_PROXY}/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"},
                {"tag": "geosite-cn", "type": "remote", "format": "binary",
                 "url": f"{RULE_PROXY}/SagerNet/sing-geosite/rule-set/geosite-cn.srs"},
                {"tag": "geoip-cn", "type": "remote", "format": "binary",
                 "url": f"{RULE_PROXY}/SagerNet/sing-geoip/rule-set/geoip-cn.srs"}
            ]
        },
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto","US","HK","JP","SG"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "https://www.gstatic.com/generate_204"},
            {"type": "selector", "tag": "US", "outbounds": []},
            {"type": "selector", "tag": "HK", "outbounds": []},
            {"type": "selector", "tag": "JP", "outbounds": []},
            {"type": "selector", "tag": "SG", "outbounds": []},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block"}
        ]
    }

# ================== 主逻辑 ==================
def main():
    print("🚀 生成 sing-box 终极配置")

    raw = []
    for s in SOURCES:
        try:
            t = requests.get(s, timeout=10).text
            d = safe_decode(t)
            raw += re.findall(r"(?:vless|trojan)://[^\s]+", d if "://" in d else t)
        except:
            pass

    raw = list(set(raw))

    with concurrent.futures.ThreadPoolExecutor(50) as ex:
        alive = [r[0] for r in ex.map(speed_test, raw) if r]

    alive = alive[:MAX_KEEP_NODES]
    cfg = base_config()

    tag_counter = {}

    for i, link in enumerate(alive):
        u = urlparse(link)
        q = parse_qs(u.query)
        country = detect_country(link)

        base = f"{country}-{u.hostname}"
        tag_counter[base] = tag_counter.get(base, 0) + 1
        tag = f"{base}-{tag_counter[base]:02d}"

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
                    "server_name": q.get("sni",[u.hostname])[0],
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }
            })
            if "pbk" in q:
                node["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": q["pbk"][0],
                    "short_id": q.get("sid", [""])[0]
                }

        if u.scheme == "trojan":
            node.update({
                "password": u.username,
                "tls": {"enabled": True}
            })

        cfg["outbounds"].append(node)

        for o in cfg["outbounds"]:
            if o.get("tag") in ("auto", country):
                o["outbounds"].append(tag)

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

    print(f"✅ 完成：有效节点 {len(alive)} 个")

if __name__ == "__main__":
    main()
