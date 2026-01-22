import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
from urllib.parse import urlparse, parse_qs, unquote

# ===================== 核心配置 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

# 规则集下载地址
RULE_CDN_DOMAIN = "gh-proxy.com"
RULE_CDN = f"https://{RULE_CDN_DOMAIN}/https://raw.githubusercontent.com"
RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 50
MAX_KEEP_NODES = 60
CONNECT_TIMEOUT = 2.5

# ===================== 核心工具 =====================
def get_content(url):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        text = resp.text.strip()
        if any(proto in text for proto in ["vless://", "trojan://", "hy2://"]):
            return text
        try:
            text_fixed = text.replace('-', '+').replace('_', '/')
            text_fixed += '=' * (-len(text_fixed) % 4)
            decoded = base64.b64decode(text_fixed).decode('utf-8', 'ignore')
            if "://" in decoded: return decoded
        except: pass
        return text
    except: return ""

def extract_links(content):
    links = []
    for line in content.splitlines():
        match = re.search(r'(vless|trojan|hysteria2|hy2)://[^\s#]+', line.strip())
        if match: links.append(match.group(0))
    return list(set(links))

def check_node(link):
    try:
        u = urlparse(link)
        if not u.hostname: return None
        start = time.time()
        with socket.create_connection((u.hostname, u.port or 443), timeout=CONNECT_TIMEOUT):
            return {"link": link, "u": u, "latency": int((time.time() - start) * 1000)}
    except: return None

# ===================== 解析逻辑 =====================
def parse_vless(u, q, tag):
    raw_flow = q.get("flow", [""])[0]
    clean_flow = "xtls-rprx-vision" if "xtls-rprx-vision" in raw_flow else ""
    node = {
        "type": "vless", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "uuid": u.username, "flow": clean_flow, "packet_encoding": "xudp",
        "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}
    }
    if q.get("security", [""])[0] == "reality":
        node["tls"]["reality"] = {"enabled": True, "public_key": q.get("pbk", [""])[0], "short_id": q.get("sid", [""])[0]}
    return node

def parse_hysteria2(u, q, tag):
    return {
        "type": "hysteria2", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "password": u.username, "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0]}
    }

def parse_trojan(u, q, tag):
    return {
        "type": "trojan", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "password": u.username, "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0]}
    }

# ===================== 主程序 =====================
def main():
    print("🚀 Sing-box V5.1 (SRS 直连下载优化版)")
    
    raw_links = []
    for src in SOURCES:
        content = get_content(src)
        links = extract_links(content)
        raw_links.extend(links)

    unique_links = list(set(raw_links))
    valid_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(check_node, l) for l in unique_links]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: valid_nodes.append(res)
    
    valid_nodes.sort(key=lambda x: x['latency'])

    # 核心配置生成
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://8.8.8.8/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                {"domain": [RULE_CDN_DOMAIN, "github.com", "raw.githubusercontent.com"], "server": "dns_local"}, # 确保下载域名的解析走直连
                {"rule_set": "ads", "server": "dns_block"},
                {"rule_set": "cn_site", "server": "dns_local"}
            ],
            "final": "dns_proxy"
        },
        "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True, "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "http://cp.cloudflare.com", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"domain": [RULE_CDN_DOMAIN, "github.com"], "outbound": "direct"}, # 确保下载流量走直连
                {"ip_is_private": True, "outbound": "direct"},
                {"rule_set": ["cn_site", "cn_ip"], "outbound": "direct"}
            ],
            "rule_set": [
                {
                    "tag": k,
                    "type": "remote",
                    "format": "binary",
                    "url": f"{RULE_CDN}/{v}",
                    "download_detour": "direct"  # 🟢 关键修改：设置为直连
                } for k, v in RULE_PATHS.items()
            ],
            "final": "proxy"
        }
    }

    for i, item in enumerate(valid_nodes[:MAX_KEEP_NODES]):
        u, q = item['u'], parse_qs(item['u'].query)
        tag = f"{unquote(u.fragment) or f'Node-{i+1}'} | {item['latency']}ms"
        try:
            node = None
            if u.scheme == "vless": node = parse_vless(u, q, tag)
            elif u.scheme in ["hy2", "hysteria2"]: node = parse_hysteria2(u, q, tag)
            elif u.scheme == "trojan": node = parse_trojan(u, q, tag)
            if node:
                cfg["outbounds"].append(node)
                cfg["outbounds"][0]["outbounds"].append(tag)
                cfg["outbounds"][1]["outbounds"].append(tag)
        except: continue

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print(f"✅ 生成完毕！.srs 规则集已设为通过 {RULE_CDN_DOMAIN} 直连下载。")

if __name__ == "__main__":
    main()
