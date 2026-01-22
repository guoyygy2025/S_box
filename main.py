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

RULE_CDN = "https://gh-proxy.com/https://raw.githubusercontent.com"
RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 50
MAX_KEEP_NODES = 50
SAMPLE_COUNT = 2

# ===================== 核心工具 =====================
def get_node_fingerprint(u):
    """生成节点核心指纹：方案+地址+端口+用户标识"""
    # 忽略节点名称(fragment)，只针对核心连接参数去重
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
            text_fixed = text.replace('-', '+').replace('_', '/') + '=' * (-len(text) % 4)
            return base64.b64decode(text_fixed).decode('utf-8', 'ignore')
        return text
    except: return ""

def check_node(link):
    try:
        u = urlparse(link)
        if not u.hostname: return None
        
        # IPv6 检测
        family = socket.AF_INET6 if ":" in u.hostname and "[" not in u.hostname else socket.AF_INET
        
        latencies = []
        for _ in range(SAMPLE_COUNT):
            start = time.time()
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                s.connect((u.hostname, u.port or 443))
                latencies.append(int((time.time() - start) * 1000))
        
        return {
            "link": link, "u": u, 
            "latency": sum(latencies) // len(latencies),
            "fp": get_node_fingerprint(u)
        }
    except: return None

# ===================== 解析逻辑 (含安全跳过) =====================
def get_tls_config(u, q):
    """通用 TLS 解析逻辑"""
    sni = q.get("sni", [u.hostname])[0].lower()
    # 🔴 处理 allowInsecure 参数
    insecure = q.get("allowInsecure", ["0"])[0] == "1" or q.get("insecure", ["0"])[0] == "1"
    
    return {
        "enabled": True,
        "server_name": sni,
        "insecure": insecure,
        "utls": {"enabled": True, "fingerprint": "chrome"}
    }

def parse_vless(u, q, tag):
    node = {
        "type": "vless", "tag": tag,
        "server": u.hostname, "server_port": int(u.port or 443),
        "uuid": u.username, "packet_encoding": "xudp",
        "tls": get_tls_config(u, q)
    }
    if q.get("security", [""])[0] == "reality":
        node["tls"]["reality"] = {
            "enabled": True,
            "public_key": q.get("pbk", [""])[0],
            "short_id": q.get("sid", [""])[0],
            "spider_x": q.get("spx", ["/"])[0]
        }
    if "vision" in q.get("flow", [""])[0]:
        node["flow"] = "xtls-rprx-vision"
    return node

def parse_hy2(u, q, tag):
    node = {
        "type": "hysteria2", "tag": tag,
        "server": u.hostname, "server_port": int(u.port or 443),
        "password": u.username,
        "tls": get_tls_config(u, q)
    }
    # Hysteria2 特有的 Obfs
    if q.get("obfs"):
        node["obfs"] = {"type": q.get("obfs")[0], "password": q.get("obfs-password", [""])[0]}
    return node

def parse_trojan(u, q, tag):
    return {
        "type": "trojan", "tag": tag,
        "server": u.hostname, "server_port": int(u.port or 443),
        "password": u.username,
        "tls": get_tls_config(u, q)
    }

# ===================== 主程序 =====================
def main():
    print("🚀 启动 Sing-box 优化脚本 (指纹去重 & 跳过证书校验)...")
    
    raw_links = []
    for s in SOURCES:
        content = get_content(s)
        links = re.findall(r'((?:vless|trojan|hysteria2|hy2)://[^\s#]+)', content)
        raw_links.extend(links)

    # 1. 测速与指纹去重
    unique_links = list(set(raw_links))
    tested_nodes = []
    seen_fingerprints = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node, unique_links))
        for res in results:
            # 🔴 如果指纹已存在，则跳过该节点
            if res and res["fp"] not in seen_fingerprints:
                tested_nodes.append(res)
                seen_fingerprints.add(res["fp"])

    tested_nodes.sort(key=lambda x: x['latency'])
    top_nodes = tested_nodes[:MAX_KEEP_NODES]

    # 2. 构建基础配置
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://8.8.8.8/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                {"rule_set": "ads", "server": "dns_block"},
                {"rule_set": "cn_site", "server": "dns_local"}
            ],
            "final": "dns_proxy"
        },
        "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": []},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "rule_set": [
                {"tag": k, "type": "remote", "format": "binary", "url": f"{RULE_CDN}/{v}", "download_detour": "direct"}
                for k, v in RULE_PATHS.items()
            ],
            "rules": [{"protocol": "dns", "outbound": "dns-out"}, {"rule_set": ["cn_site", "cn_ip"], "outbound": "direct"}],
            "final": "proxy"
        }
    }

    # 3. 填充节点并解析地理位置
    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        country = get_ip_country(u.hostname)
        raw_name = unquote(u.fragment) if u.fragment else f"Node-{i}"
        tag = f"{country} {raw_name} | {item['latency']}ms"
        
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
    
    print(f"✅ 任务完成！去重后保留 {len(top_nodes)} 个唯一节点。")

if __name__ == "__main__":
    main()
