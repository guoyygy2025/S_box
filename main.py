import requests
import base64
import socket
import concurrent.futures
import json
import re
import platform
from urllib.parse import urlparse, parse_qs

# ========== 核心配置 ==========
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

AD_BLOCK_SRS = "https://gh-proxy.org/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"

MAX_KEEP_NODES = 100
TIMEOUT = 0.5
DOWNLOAD_DOMAINS = ["gh-proxy.org", "gh-proxy.com", "jsdelivr.net"]

ALLOW_SCHEMES = ("vless", "trojan")  # ✅ 只允许的协议

# ========== 工具函数 ==========
def get_system_stack():
    return "system" if platform.system().lower() in ("linux", "android") else "gvisor"

def safe_decode(data: str) -> str:
    try:
        data = data.strip().replace("\n", "").replace("\r", "")
        return base64.b64decode(data + "=" * (-len(data) % 4)).decode("utf-8", "ignore")
    except Exception:
        return data

def check_node(node):
    link, host, port = node
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return link
    except Exception:
        return None

# ========== sing-box 模板 ==========
def get_base_template():
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "inet4_address": ["172.19.0.1/30"],
            "inet6_address": ["fd00::1/126"],
            "auto_route": True,
            "strict_route": True,
            "stack": get_system_stack(),
            "mtu": 1280,
            "sniff": True,
            "sniff_override_destination": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "final": "proxy",
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": DOWNLOAD_DOMAINS, "outbound": "direct"},
                {
                    "domain_suffix": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com"],
                    "outbound": "proxy"
                },
                {"rule_set": ["geosite-ads"], "action": "reject"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
            ],
            "rule_set": [
                {"tag": "geosite-ads", "type": "remote", "format": "binary",
                 "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                 "download_detour": "direct"},
                {"tag": "geosite-cn", "type": "remote", "format": "binary",
                 "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                 "download_detour": "direct"},
                {"tag": "geoip-cn", "type": "remote", "format": "binary",
                 "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                 "download_detour": "direct"}
            ]
        }
    }

# ========== 主流程 ==========
def main():
    print("🔄 仅筛选 VLESS / Trojan，适配 sing-box 1.12.17")

    links = []
    for src in SOURCES:
        try:
            r = requests.get(src, timeout=6)
            text = r.text
            if "://" not in text:
                text = safe_decode(text)
            links.extend(re.findall(r"(vless|trojan)://[^\s#]+", text))
        except Exception:
            pass

    parsed = []
    for l in set(links):
        u = urlparse(l)
        if u.scheme in ALLOW_SCHEMES and u.hostname:
            parsed.append((l, u.hostname, u.port or 443))

    with concurrent.futures.ThreadPoolExecutor(40) as pool:
        alive = list(filter(None, pool.map(check_node, parsed)))[:MAX_KEEP_NODES]

    outbounds = []
    tags = []

    for idx, link in enumerate(alive):
        u = urlparse(link)
        q = parse_qs(u.query)
        tag = f"🚀Node-{idx:02d}"

        node = {
            "type": u.scheme,
            "tag": tag,
            "server": u.hostname,
            "server_port": u.port or 443
        }

        if u.scheme == "vless":
            node.update({
                "uuid": u.username,
                "flow": q.get("flow", ["xtls-rprx-vision"])[0],
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

            if q.get("type", [""])[0] == "ws":
                node["transport"] = {
                    "type": "ws",
                    "path": q.get("path", ["/"])[0],
                    "headers": {"Host": q.get("host", [u.hostname])[0]}
                }

        elif u.scheme == "trojan":
            node.update({
                "password": u.username,
                "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0]}
            })

        outbounds.append(node)
        tags.append(tag)

    config = get_base_template()
    config["outbounds"].extend(outbounds)
    config["outbounds"][0]["outbounds"] = ["auto"] + tags + ["direct"]
    config["outbounds"][1]["outbounds"] = tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print(f"✅ 完成：有效节点 {len(tags)} 个（VLESS / Trojan）")

if __name__ == "__main__":
    main()
