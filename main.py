import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import hashlib
from urllib.parse import urlparse, parse_qs, unquote

# ===================== 核心配置 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

# ✅ 修正1: 使用正确的 CDN 域名
CDN_HOST = "gh-proxy.com"
GH_RAW_BASE = "https://raw.githubusercontent.com"
RULE_CDN_PREFIX = f"https://{CDN_HOST}/{GH_RAW_BASE}"

RULE_PATHS = {
    "geosite-category-ads-all": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite-cn": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 100
MAX_KEEP_NODES = 100
TIMEOUT = 5.0
# ✅ 修正2: ALIDNS 应为纯 IP (Do53)
ALIDNS = "223.5.5.5"

dns_cache = {}

# ===================== 工具函数 =====================
# ... (保持不变) ...

def get_tls_config(u, q):
    raw_sni = q.get("sni", [None])[0] or q.get("host", [None])[0] or u.hostname
    final_sni = unquote(str(raw_sni)).split("/")[0].split(":")[0].strip()
    return {
        "enabled": True,
        "server_name": final_sni,
        "insecure": True,  # ✅ 添加此字段提高兼容性
        "utls": {"enabled": True, "fingerprint": "chrome"}
    }

# ... (check_node, resolve_hostname 等保持不变) ...

# ===================== 主构建程序 =====================
def main():
    print(f"🚀 正在处理节点并构建稳定配置...")
    all_text = "\n".join([get_content(s) for s in SOURCES])
    links = list(set(re.findall(r'((?:vless|trojan)://[^\s#]+)', all_text)))
    
    tested_nodes = []
    seen_fps = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node, links))
        for res in results:
            if res and res["fp"] not in seen_fps:
                tested_nodes.append(res); seen_fps.add(res["fp"])

    tested_nodes.sort(key=lambda x: x['latency'])
    top_nodes = tested_nodes[:MAX_KEEP_NODES]

    # 构建基础模板 (✅ 移除 FakeIP，确保稳定性)
    cfg = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": ALIDNS, "detour": "direct"},  # ✅ 现在是有效的 Do53
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                {"rule_set": "geosite-category-ads-all", "server": "dns_block"},
                {"rule_set": "geosite-cn", "server": "dns_local"}
            ],
            "final": "dns_proxy",
            "strategy": "ipv4_only"
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "inet4_address": "172.19.0.1/30",
            "mtu": 1400,
            "auto_route": True,
            "strict_route": True,
            # ✅ 修正3: 使用 system 栈，兼容性更好
            "stack": "system",
            "sniff": True,
            "sniff_override_destination": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "http://cp.cloudflare.com/generate_204", "interval": "3m"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "rule_set": [
                {
                    "type": "remote", "tag": k, "format": "binary", 
                    "url": f"{RULE_CDN_PREFIX}/{v}", "download_detour": "direct"
                } for k, v in RULE_PATHS.items()
            ],
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"rule_set": "geosite-category-ads-all", "outbound": "block"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True
        }
    }

    # 填充节点逻辑
    valid_count = 0
    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        country = get_ip_country(u.hostname)
        tag = f"{country} {unquote(u.fragment or f'Node-{i+1}')} | {item['latency']}ms"
        
        if u.scheme == "vless":
            if not u.username: continue
            node = {
                "type": "vless",
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port or 443),
                "uuid": u.username,
                "packet_encoding": "xudp",
                "tls": get_tls_config(u, q)
            }
            flow_val = q.get("flow", [""])[0]
            if "vision" in flow_val:
                node["flow"] = "xtls-rprx-vision"
                
        elif u.scheme == "trojan":
            if not u.username: continue
            node = {
                "type": "trojan",
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port or 443),
                "password": u.username,
                "tls": get_tls_config(u, q)
            }
        else:
            continue

        # Reality 支持
        if q.get("security", [""])[0] == "reality":
            pbk = q.get("pbk", [""])[0]
            if not pbk: continue
            node["tls"]["reality"] = {
                "enabled": True,
                "public_key": pbk,
                "short_id": q.get("sid", [""])[0]
            }
            if q.get("spx"):
                node["tls"]["reality"]["spider_x"] = q.get("spx")[0]

        cfg["outbounds"].append(node)
        cfg["outbounds"][0]["outbounds"].append(tag)
        cfg["outbounds"][1]["outbounds"].append(tag)
        valid_count += 1

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"🎉 成功! config.json 已生成，包含 {valid_count} 个有效节点。")
    print("💡 现在你可以运行: sing-box run -c config.json")

if __name__ == "__main__":
    main()
