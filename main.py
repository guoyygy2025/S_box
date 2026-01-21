import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
from urllib.parse import urlparse, parse_qs

# ===================== 基础参数 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

RULE_CDN = [
    "https://cdn.jsdelivr.net/gh",
    "https://gh-proxy.com/https://raw.githubusercontent.com"
]

RULE_PATHS = {
    "adblock": "217heidai/adblockfilters/main/rules/adblocksingbox.srs",
    "geosite_ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite_cn": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip_cn": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_KEEP_NODES = 40
CONNECT_TIMEOUT = 1.2
MAX_RTT = 900
TIKTOK_SELECTOR = "JP"

COUNTRY_KEYWORDS = {
    "US": ["us", "united"],
    "HK": ["hk", "hongkong"],
    "JP": ["jp", "japan"],
    "SG": ["sg", "singapore"]
}

# ===================== 工具 =====================
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

def tcp_rtt(host, port):
    try:
        s = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        s.close()
        return 100
    except:
        return None

def pick_rule_url(path):
    for cdn in RULE_CDN:
        url = f"{cdn}/{path}"
        try:
            r = requests.head(url, timeout=5)
            if r.status_code == 200:
                return url
        except:
            pass
    raise RuntimeError(f"规则不可用: {path}")

# ===================== 基础配置 =====================
def base_config(rule_urls):
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
                    "domain_suffix": [
                        "tiktok.com","tiktokcdn.com","byteoversea.com","ibytedtos.com",
                        "youtube.com","googlevideo.com"
                    ],
                    "server": "dns_proxy"
                },
                {"rule_set": ["adblock","geosite_ads"], "server": "dns_block"},
                {"rule_set": "geosite_cn", "server": "dns_local"},
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
            "sniff": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto","direct"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "https://www.gstatic.com/generate_204"},
            {"type": "selector", "tag": "US", "outbounds": ["auto","direct"]},
            {"type": "selector", "tag": "HK", "outbounds": ["auto","direct"]},
            {"type": "selector", "tag": "JP", "outbounds": ["auto","direct"]},
            {"type": "selector", "tag": "SG", "outbounds": ["auto","direct"]},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"ip_is_private": True, "outbound": "direct"},
                {
                    "domain_suffix": [
                        "tiktok.com","tiktokcdn.com","byteoversea.com","ibytedtos.com"
                    ],
                    "outbound": TIKTOK_SELECTOR
                },
                {"rule_set": ["adblock","geosite_ads"], "action": "reject"},
                {"rule_set": ["geoip_cn","geosite_cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "rule_set": [
                {"tag": "adblock", "type": "remote", "format": "binary", "url": rule_urls["adblock"]},
                {"tag": "geosite_ads", "type": "remote", "format": "binary", "url": rule_urls["geosite_ads"]},
                {"tag": "geosite_cn", "type": "remote", "format": "binary", "url": rule_urls["geosite_cn"]},
                {"tag": "geoip_cn", "type": "remote", "format": "binary", "url": rule_urls["geoip_cn"]}
            ]
        }
    }

# ===================== 主流程 =====================
def main():
    print("🚀 构建 sing-box 终极稳定配置（进阶 2 + 3）")

    rule_urls = {}
    for k, p in RULE_PATHS.items():
        rule_urls[k] = pick_rule_url(p)

    links = []
    for src in SOURCES:
        try:
            r = requests.get(src, timeout=8)
            text = r.text
            if "://" not in text:
                text = safe_decode(text)
            links += re.findall(r"(vless|trojan)://[^\s#]+", text)
        except:
            pass

    links = list(set(links))

    cfg = base_config(rule_urls)

    for i, link in enumerate(links):
        u = urlparse(link)
        q = parse_qs(u.query)
        if not u.hostname:
            continue

        if not tcp_rtt(u.hostname, u.port or 443):
            continue

        country = detect_country(link)
        tag = f"{country}-{i:02d}"

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
                    "server_name": q.get("sni", [u.hostname])[0],
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }
            })

            if "pbk" in q:
                node["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": q["pbk"][0],
                    "short_id": q.get("sid", [""])[0]
                }

        cfg["outbounds"].append(node)

        for o in cfg["outbounds"]:
            if o.get("tag") in ("auto", country):
                o["outbounds"].append(tag)

        if len(cfg["outbounds"]) >= MAX_KEEP_NODES + 10:
            break

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

    print("✅ config.json 已生成（进阶 2 + 3）")

if __name__ == "__main__":
    main()
