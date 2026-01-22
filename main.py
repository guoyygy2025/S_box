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
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

# 🔴 优化点 1：使用直连更稳定的高速镜像站 (可根据需求更换)
# 备选：https://mirror.ghproxy.com , https://github.moeyy.xyz
RULE_CDN_HOST = "gh-proxy.org/"
RULE_CDN = f"https://{RULE_CDN_HOST}/https://raw.githubusercontent.com"

RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 50
MAX_KEEP_NODES = 50
SAMPLE_COUNT = 2

# ===================== 工具逻辑 (省略重复解析函数以保持简洁) =====================
# ... [get_node_fingerprint, get_ip_country, get_content, check_node 保持不变] ...
def get_node_fingerprint(u):
    raw_str = f"{u.scheme}|{u.hostname}|{u.port}|{u.username}"
    return hashlib.md5(raw_str.encode()).hexdigest()

def get_ip_country(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return f"[{resp.get('countryCode')}]" if resp.get("status") == "success" else "[UN]"
    except: return "[UN]"

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        text = resp.text.strip()
        if "://" not in text:
            try:
                text_fixed = text.replace('-', '+').replace('_', '/') + '=' * (-len(text) % 4)
                return base64.b64decode(text_fixed).decode('utf-8', 'ignore')
            except: pass
        return text
    except: return ""

def check_node(link):
    try:
        u = urlparse(link)
        if not u.hostname: return None
        family = socket.AF_INET6 if ":" in u.hostname and "[" not in u.hostname else socket.AF_INET
        latencies = []
        for _ in range(SAMPLE_COUNT):
            start = time.time()
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                s.connect((u.hostname, u.port or 443))
                latencies.append(int((time.time() - start) * 1000))
        return {"link": link, "u": u, "latency": sum(latencies) // len(latencies), "fp": get_node_fingerprint(u)}
    except: return None

def get_tls_config(u, q):
    sni = q.get("sni", [u.hostname])[0].lower()
    insecure = q.get("allowInsecure", ["0"])[0] == "1" or q.get("insecure", ["0"])[0] == "1"
    return {"enabled": True, "server_name": sni, "insecure": insecure, "utls": {"enabled": True, "fingerprint": "chrome"}}

def parse_vless(u, q, tag):
    node = {"type": "vless", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443), "uuid": u.username, "packet_encoding": "xudp", "tls": get_tls_config(u, q)}
    if q.get("security", [""])[0] == "reality":
        reality_cfg = {"enabled": True, "public_key": q.get("pbk", [""])[0], "short_id": q.get("sid", [""])[0]}
        spx = q.get("spx", [""])[0]
        if spx: reality_cfg["spider_host"] = spx
        node["tls"]["reality"] = reality_cfg
    if "vision" in q.get("flow", [""])[0]: node["flow"] = "xtls-rprx-vision"
    return node

def parse_hy2(u, q, tag):
    node = {"type": "hysteria2", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443), "password": u.username, "tls": get_tls_config(u, q)}
    if q.get("obfs"): node["obfs"] = {"type": q.get("obfs")[0], "password": q.get("obfs-password", [""])[0]}
    return node

def parse_trojan(u, q, tag):
    return {"type": "trojan", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443), "password": u.username, "tls": get_tls_config(u, q)}

# ===================== 主程序 =====================
def main():
    print(f"🚀 正在使用镜像 {RULE_CDN_HOST} 优化直连配置...")
    
    raw_links = []
    for s in SOURCES:
        content = get_content(s)
        links = re.findall(r'((?:vless|trojan|hysteria2|hy2)://[^\s#]+)', content)
        raw_links.extend(links)

    unique_links = list(set(raw_links))
    tested_nodes = []
    seen_fps = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node, unique_links))
        for res in results:
            if res and res["fp"] not in seen_fps:
                tested_nodes.append(res)
                seen_fps.add(res["fp"])

    tested_nodes.sort(key=lambda x: x['latency'])
    top_nodes = tested_nodes[:MAX_KEEP_NODES]

    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                {"rule_set": "ads", "server": "dns_block"},
                # 🔴 优化点 2：强制镜像站域名使用本地 DNS 解析，确保直连
                {"domain": [RULE_CDN_HOST], "server": "dns_local"},
                {"rule_set": "cn_site", "server": "dns_local"}
            ],
            "final": "dns_proxy"
        },
        "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True, "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "3m0s"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "dns_block"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"rule_set": "ads", "outbound": "dns_block"},
                # 🔴 优化点 3：镜像站流量强制走 direct 出站
                {"domain": [RULE_CDN_HOST], "outbound": "direct"},
                {"rule_set": ["cn_site", "cn_ip"], "outbound": "direct"}
            ],
            "rule_set": [
                {
                    "tag": k, "type": "remote", "format": "binary", 
                    "url": f"{RULE_CDN}/{v}", 
                    "download_detour": "direct" # 🔴 坚持直连下载
                } for k, v in RULE_PATHS.items()
            ],
            "final": "proxy"
        }
    }

    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        country = get_ip_country(u.hostname)
        tag = f"{country} {unquote(u.fragment) or f'Node-{i}'} | {item['latency']}ms"
        node = None
        if u.scheme == "vless": node = parse_vless(u, q, tag)
        elif u.scheme in ["hy2", "hysteria2"]: node = parse_hy2(u, q, tag)
        elif u.scheme == "trojan": node = parse_trojan(u, q, tag)
        if node:
            cfg["outbounds"].append(node)
            cfg["outbounds"][0]["outbounds"].append(tag)
            cfg["outbounds"][1]["outbounds"].append(tag)

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 成功! 写入 {len(top_nodes)} 个节点。规则下载通过 {RULE_CDN_HOST} 直连。")

if __name__ == "__main__":
    main()
