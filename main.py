import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import hashlib
from urllib.parse import urlparse, parse_qs, unquote

# ===================== 配置参数 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

RULE_URLS = {
    "geosite-ads": "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite-cn": "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn": "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

ALIDNS = "223.5.5.5"
LATENCY_THRESHOLD = 500
MAX_KEEP_NODES = 50

# ===================== 工具函数 =====================

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        text = resp.text.strip()
        if "://" not in text[:50]:
            try:
                padding = len(text) % 4
                if padding: text += '=' * (4 - padding)
                return base64.b64decode(text).decode('utf-8', 'ignore')
            except: return text
        return text
    except: return ""

def check_node(link):
    if not link.startswith("vless://"): return None
    try:
        u = urlparse(link)
        ip = socket.gethostbyname(u.hostname)
        start = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0)
            s.connect((ip, u.port or 443))
            latency = int((time.time() - start) * 1000)
        if latency >= LATENCY_THRESHOLD: return None
        fp = hashlib.md5(f"{u.username}{u.hostname}{u.port}".encode()).hexdigest()
        return {"link": link, "u": u, "latency": latency, "fp": fp}
    except: return None

# ===================== 主程序 =====================

def main():
    print(f"🚀 正在生成 sing-box 1.12.17 兼容配置 (修复 DNS 字段)...")
    all_text = "\n".join([get_content(s) for s in SOURCES])
    links = list(set(re.findall(r'vless://[^\s#]+(?:#[^\s]*)?', all_text)))
    
    valid_nodes = []
    seen_fps = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(check_node, links))
        for res in results:
            if res and res["fp"] not in seen_fps:
                valid_nodes.append(res); seen_fps.add(res["fp"])

    valid_nodes.sort(key=lambda x: x['latency'])
    top_nodes = valid_nodes[:MAX_KEEP_NODES]

    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": ALIDNS, "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"},
                {"tag": "fakeip_server", "address": "fakeip"}
            ],
            "rules": [
                # 优先处理规则下载域名，防止其进入 fakeip 逻辑
                {"domain": ["gh-proxy.com"], "action": "route", "server": "dns_local"},
                {"rule_set": "geosite-ads", "action": "route", "server": "dns_block"},
                {"rule_set": "geosite-cn", "action": "route", "server": "dns_local"},
                {"query_type": ["A", "AAAA"], "action": "route", "server": "fakeip_server"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"},
            "hosts": {
                # ✅ 彻底解决环路的核心：静态解析
                "gh-proxy.com": ["104.21.64.137", "172.67.183.248"]
            }
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "inet4_address": "172.19.0.1/30",
            "auto_route": True,
            "strict_route": True,
            "stack": "system",
            "sniff": True
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
                {"type": "remote", "tag": "geosite-ads", "format": "binary", "url": RULE_URLS["geosite-ads"], "download_detour": "direct"},
                {"type": "remote", "tag": "geosite-cn", "format": "binary", "url": RULE_URLS["geosite-cn"], "download_detour": "direct"},
                {"type": "remote", "tag": "geoip-cn", "format": "binary", "url": RULE_URLS["geoip-cn"], "download_detour": "direct"}
            ],
            "rules": [
                {"protocol": "dns", "action": "route", "outbound": "dns-out"},
                # ✅ 路由层面的防环路：强制 direct
                {"domain": ["gh-proxy.com"], "action": "route", "outbound": "direct"},
                {"rule_set": "geosite-ads", "action": "reject"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "action": "route", "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True
        }
    }

    # 填充节点
    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        tag = f"{unquote(u.fragment or f'Node-{i+1}')} | {item['latency']}ms"
        node = {
            "type": "vless", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
            "uuid": u.username, "packet_encoding": "xudp",
            "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}
        }
        if "vision" in q.get("flow", [""])[0]: node["flow"] = "xtls-rprx-vision"
        if q.get("security", [""])[0] == "reality":
            node["tls"]["reality"] = {"enabled": True, "public_key": q.get("pbk", [""])[0], "short_id": q.get("sid", [""])[0]}
        
        cfg["outbounds"].append(node)
        cfg["outbounds"][0]["outbounds"].append(tag)
        cfg["outbounds"][1]["outbounds"].append(tag)

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print(f"🎉 适配完成！已移除错误字段，config.json 可直接运行。")

if __name__ == "__main__":
    main()
