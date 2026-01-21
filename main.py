import requests
import base64
import json
import re
import platform
from urllib.parse import urlparse, parse_qs

# ================= 配置区 =================

SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

MAX_KEEP_NODES = 50
ALLOW_SCHEME = ("vless", "trojan")

# ================= 工具函数 =================

def safe_b64decode(text: str) -> str:
    try:
        text = text.strip().replace("\n", "").replace("\r", "")
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
    except Exception:
        return text

def get_stack():
    sys = platform.system().lower()
    return "system" if sys in ("linux", "android") else "gvisor"

# ================= sing-box 基础模板 =================

def base_config():
    return {
        "log": {"level": "warn"},
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "inet4_address": ["172.19.0.1/30"],
                "inet6_address": ["fd00::1/126"],
                "auto_route": True,
                "strict_route": True,
                "stack": get_stack(),
                "mtu": 1280,
                "sniff": True,
                "sniff_override_destination": True
            }
        ],
        "outbounds": [
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["auto"]
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": [],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "10m",
                "tolerance": 50
            },
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
                        "youtube.com", "googlevideo.com",
                        "ytimg.com", "ggpht.com"
                    ],
                    "outbound": "proxy"
                },
                {
                    "rule_set": ["geoip-cn", "geosite-cn"],
                    "outbound": "direct"
                }
            ],
            "final": "proxy",
            "rule_set": [
                {
                    "tag": "geosite-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
                },
                {
                    "tag": "geoip-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
                }
            ]
        }
    }

# ================= 主逻辑 =================

def main():
    print("🔄 生成 sing-box 1.12.17 最终形态配置中…")

    raw_links = []

    for src in SOURCES:
        try:
            r = requests.get(src, timeout=8)
            text = r.text
            if "://" not in text:
                text = safe_b64decode(text)
            raw_links.extend(re.findall(r"(?:vless|trojan)://[^\s#]+", text))
        except Exception:
            continue

    print(f"📥 抓取到原始链接：{len(raw_links)}")

    links = []
    for link in set(raw_links):
        u = urlparse(link)
        if (
            u.scheme in ALLOW_SCHEME
            and u.hostname
            and u.username
        ):
            links.append(link)

    links = links[:MAX_KEEP_NODES]
    print(f"🧹 结构合法节点：{len(links)}")

    outbounds = []
    tags = []

    for idx, link in enumerate(links):
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
                    "utls": {
                        "enabled": True,
                        "fingerprint": "chrome"
                    }
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
                    "headers": {
                        "Host": q.get("host", [u.hostname])[0]
                    }
                }

        elif u.scheme == "trojan":
            node.update({
                "password": u.username,
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0]
                }
            })

        outbounds.append(node)
        tags.append(tag)

    cfg = base_config()
    cfg["outbounds"].extend(outbounds)
    cfg["outbounds"][0]["outbounds"] = ["auto"] + tags + ["direct"]
    cfg["outbounds"][1]["outbounds"] = tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

    print("✅ 完成")
    print(f"📦 输出节点：{len(tags)}")
    print("👉 实际可用节点由 sing-box urltest 自动筛选")

if __name__ == "__main__":
    main()
