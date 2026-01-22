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

# 远程规则地址 (使用 gh-proxy.org 加速)
RULE_URLS = {
    "geosite-category-ads-all": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite-cn": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

# ✅ 优化：仅使用纯 IP 223.5.5.5，不使用 DOH
ALIDNS = "223.5.5.5"
LATENCY_THRESHOLD = 500  # 仅保留 < 500ms 的节点
MAX_THREADS = 100
MAX_KEEP_NODES = 50
TIMEOUT = 4.0

dns_cache = {}

# ===================== 工具函数 =====================

def resolve_hostname(hostname):
    if hostname in dns_cache: return dns_cache[hostname]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname): return hostname
    try:
        ip = socket.gethostbyname(hostname)
        dns_cache[hostname] = ip
        return ip
    except: return None

def get_ip_country(hostname):
    try:
        ip = resolve_hostname(hostname)
        if not ip: return "[UN]"
        # 使用本地 IP 解析服务获取国家简称
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        return f"[{resp.get('countryCode', 'UN')}]" if resp.get("status") == "success" else "[UN]"
    except: return "[UN]"

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        text = resp.text.strip()
        if "://" not in text[:50]:
            try:
                missing_padding = len(text) % 4
                if missing_padding: text += '=' * (4 - missing_padding)
                return base64.b64decode(text).decode('utf-8', 'ignore')
            except: return text
        return text
    except: return ""

def check_node(link):
    if not link.startswith("vless://"): return None
    try:
        u = urlparse(link)
        if not u.hostname or not u.username: return None
        ip = resolve_hostname(u.hostname)
        if not ip: return None
        
        start = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, u.port or 443))
            latency = int((time.time() - start) * 1000)
            
        if latency >= LATENCY_THRESHOLD: return None
            
        fp = hashlib.md5(f"{u.username}{u.hostname}{u.port}".encode()).hexdigest()
        return {"link": link, "u": u, "latency": latency, "fp": fp}
    except: return None

# ===================== 主程序 =====================

def main():
    print(f"🚀 开始提取节点并筛选延迟 < {LATENCY_THRESHOLD}ms 的 VLESS...")
    all_text = "\n".join([get_content(s) for s in SOURCES])
    # 提取 VLESS 链接
    links = list(set(re.findall(r'vless://[^\s#]+(?:#[^\s]*)?', all_text)))
    
    valid_nodes = []
    seen_fps = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node, links))
        for res in results:
            if res and res["fp"] not in seen_fps:
                valid_nodes.append(res); seen_fps.add(res["fp"])

    valid_nodes.sort(key=lambda x: x['latency'])
    top_nodes = valid_nodes[:MAX_KEEP_NODES]

    # 基于您的模板构建 JSON 结构
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
                {"rule_set": "geosite-category-ads-all", "action": "route", "server": "dns_block"},
                {"rule_set": "geosite-cn", "action": "route", "server": "dns_local"},
                {"query_type": ["A", "AAAA"], "action": "route", "server": "fakeip_server"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "inet4_address": ["172.19.0.1/30"],
            "inet6_address": ["fd00::1/126"], "mtu": 1280, "auto_route": True,
            "strict_route": True, "stack": "gvisor", "sniff": True, "sniff_override_destination": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "http://cp.cloudflare.com/generate_204", "interval": "3m"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "default_domain_resolver": "dns_local",
            "rule_set": [
                {"type": "remote", "tag": "geosite-category-ads-all", "format": "binary", "url": RULE_URLS["geosite-category-ads-all"], "download_detour": "direct"},
                {"type": "remote", "tag": "geosite-cn", "format": "binary", "url": RULE_URLS["geosite-cn"], "download_detour": "direct"},
                {"type": "remote", "tag": "geoip-cn", "format": "binary", "url": RULE_URLS["geoip-cn"], "download_detour": "direct"}
            ],
            "rules": [
                {"protocol": "dns", "action": "route", "outbound": "dns-out"},
                {"rule_set": "geosite-category-ads-all", "action": "reject"},
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
        country = get_ip_country(u.hostname)
        # 格式化 Tag: [国家] 节点名 | 延迟ms
        tag = f"{country} {unquote(u.fragment or f'VLESS-{i+1}')} | {item['latency']}ms"
        
        node = {
            "type": "vless",
            "tag": tag,
            "server": u.hostname,
            "server_port": int(u.port or 443),
            "uuid": u.username,
            "packet_encoding": "xudp",
            "tls": {
                "enabled": True,
                "server_name": q.get("sni", [u.hostname])[0],
                "utls": {"enabled": True, "fingerprint": "chrome"}
            }
        }

        # 处理 Vision 和 Reality
        if "vision" in q.get("flow", [""])[0]:
            node["flow"] = "xtls-rprx-vision"
        
        if q.get("security", [""])[0] == "reality":
            node["tls"]["reality"] = {
                "enabled": True,
                "public_key": q.get("pbk", [""])[0],
                "short_id": q.get("sid", [""])[0]
            }

        cfg["outbounds"].append(node)
        cfg["outbounds"][0]["outbounds"].append(tag)
        cfg["outbounds"][1]["outbounds"].append(tag)

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"🎉 成功! config.json 已生成，共插入 {len(top_nodes)} 个节点。")

if __name__ == "__main__":
    main()
