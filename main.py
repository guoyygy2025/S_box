import requests
import base64
import socket
import concurrent.futures
import json
import time
import re
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置区 ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", 
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

MAX_KEEP_NODES = 50 
TIMEOUT = 0.5       
MAX_WORKERS = 100    

DOWNLOAD_DOMAINS = ["gh-proxy.com", "githubusercontent.com", "github.com", "jsdelivr.net"]
AD_RULES_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
GEOIP_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
GEOSITE_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"

DNS_CACHE = {}
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

def get_114_clean_template():
    """彻底适配 Sing-box v1.14.0+，移除 Clash API"""
    return {
        "log": {"level": "info", "timestamp": True},
        "cache_file": {
            "enabled": True,
            "path": "cache.db",
            "store_fakeip": True,
            "store_rdrc": True
        },
        "dns": {
            "servers": [
                {"tag": "dns_remote", "address": "https://1.1.1.1/dns-query", "address_resolver": "dns_local", "detour": "proxy"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "dns_fakeip", "address": "fakeip"}
            ],
            "rules": [
                {"outbound": "any", "server": "dns_local"},
                {"domain_suffix": DOWNLOAD_DOMAINS, "server": "dns_local"},
                {"rule_set": "geosite-cn", "server": "dns_local"},
                {"query_type": ["A", "AAAA"], "server": "dns_fakeip"}
            ],
            "fakeip": {
                "enabled": True,
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            },
            "strategy": "prefer_ipv4",
            "independent_cache": True
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed",
                "sniffing": {
                    "enabled": True,
                    "dest_override": ["http", "tls", "quic"]
                }
            }
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"], "interrupt_exist_connections": True},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block-out"}
        ],
        "route": {
            "default_domain_resolver": "dns_local",
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"domain_suffix": DOWNLOAD_DOMAINS, "outbound": "direct"},
                {"rule_set": "ad-rules", "action": "reject"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"},
                {"ip_is_private": True, "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "rule_set": [
                {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": GEOIP_CN_URL, "download_detour": "direct"},
                {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": GEOSITE_CN_URL, "download_detour": "direct"},
                {"tag": "ad-rules", "type": "remote", "format": "binary", "url": AD_RULES_URL, "download_detour": "direct"}
            ]
        }
    }

def safe_decode(data):
    try:
        data = data.strip().replace('\n', '').replace('\r', '').replace(' ', '').replace('-', '+').replace('_', '/')
        return base64.b64decode(data + '=' * (-len(data) % 4)).decode('utf-8', 'ignore')
    except: return ""

def parse_ss_url(link):
    try:
        body = link[5:]
        tag = unquote(body.split('#')[1]) if '#' in body else ""
        body = body.split('#')[0]
        if '@' in body:
            userinfo, hostinfo = body.split('@', 1)
            if ':' not in userinfo: userinfo = safe_decode(userinfo)
            method, password = userinfo.split(':', 1)
            server, port = hostinfo.split(':', 1)
        else:
            decoded = safe_decode(body)
            userinfo, hostinfo = decoded.split('@', 1)
            method, password = userinfo.split(':', 1)
            server, port = hostinfo.split(':', 1)
        return {"type": "shadowsocks", "server": server, "server_port": int(port), "method": method, "password": password, "tag_info": tag}
    except: return None

def resolve_with_1111(domain):
    if not domain or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain): return domain
    if domain in DNS_CACHE: return DNS_CACHE[domain]
    try:
        r = requests.get("https://1.1.1.1/dns-query", params={"name": domain, "type": "A"}, headers={"accept": "application/dns-json", **HEADERS}, timeout=3.0)
        ans = r.json().get("Answer", [])
        for a in ans:
            if a["type"] == 1:
                DNS_CACHE[domain] = a["data"]
                return a["data"]
    except: pass
    return None

def check_node(node_info):
    link, ip, port = node_info
    try:
        start = time.time()
        with socket.create_connection((ip, int(port)), timeout=TIMEOUT):
            return (link, ip, port, time.time() - start)
    except: return None

def extract_region(tag):
    regions = ["香港", "日本", "美国", "韩国", "新加坡", "台湾", "德国", "英国", "HK", "JP", "US", "KR", "SG", "TW", "CN", "MO", "UK", "RU"]
    for r in regions:
        if r.lower() in tag.lower(): return r.upper()
    return "其它"

def main():
    print("--- 步骤1: 抓取与初步筛选 ---")
    raw_links = []
    regex = re.compile(r"(?:vless|trojan|hysteria2|hy2|ss)://[^\s]+")
    for url in SOURCES:
        try:
            r = requests.get(url, headers=HEADERS, timeout=10)
            text = r.text if "://" in r.text else safe_decode(r.text)
            found = regex.findall(text)
            raw_links.extend(found)
            print(f"  √ {url[:30]}... 找到 {len(found)} 个")
        except: pass

    unique_links = list(set(raw_links))
    nodes_to_test = []
    for link in unique_links:
        try:
            scheme = link.split("://")[0]
            if scheme == "ss":
                info = parse_ss_url(link)
                if info: 
                    ip = resolve_with_1111(info['server'])
                    if ip: nodes_to_test.append((link, ip, info['server_port']))
            else:
                u = urlparse(link)
                ip = resolve_with_1111(u.hostname)
                if ip: nodes_to_test.append((link, ip, u.port or 443))
        except: pass

    print(f"--- 步骤2: 多轮压力测速 (目标: {MAX_KEEP_NODES}个) ---")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = [res for res in ex.map(check_node, nodes_to_test) if res]
    
    results.sort(key=lambda x: x[3])
    final_list = results[:MAX_KEEP_NODES]

    final_outbounds, final_tags = [], []
    for link, ip, port, lat in final_list:
        try:
            scheme = link.split("://")[0]
            node = {}
            raw_tag = ""
            
            if scheme == "ss":
                info = parse_ss_url(link)
                node = {"type": "shadowsocks", "server": ip, "server_port": info['server_port'], "method": info['method'], "password": info['password']}
                raw_tag = info['tag_info']
            elif scheme == "trojan":
                u = urlparse(link); q = parse_qs(u.query); raw_tag = unquote(u.fragment)
                node = {"type": "trojan", "server": ip, "server_port": int(port), "password": u.username}
                node["tls"] = {"enabled": True, "server_name": q.get('sni', [u.hostname])[0]}
            elif scheme in ["vless", "hysteria2", "hy2"]:
                u = urlparse(link); q = parse_qs(u.query); raw_tag = unquote(u.fragment)
                p_type = "hysteria2" if "hy" in scheme else "vless"
                node = {"type": p_type, "server": ip, "server_port": int(port), "password" if p_type == "hysteria2" else "uuid": u.username}
                if p_type == "hysteria2" or "tls" in link or "reality" in str(q):
                    node["tls"] = {"enabled": True, "server_name": q.get('sni', [u.hostname])[0]}
                    if 'pbk' in q: node["tls"]["reality"] = {"enabled": True, "public_key": q['pbk'][0], "short_id": q.get('sid', [''])[0]}
                if q.get('type', [''])[0] == 'ws':
                    node["transport"] = {"type": "ws", "path": q.get('path', ['/'])[0], "headers": {"Host": q.get('host', [u.hostname])[0]}}

            tag = f"{extract_region(raw_tag)}|{int(lat*1000)}ms"
            count = 1
            unique_tag = tag
            while unique_tag in final_tags:
                unique_tag = f"{tag}_{count}"; count += 1
            
            node["tag"] = unique_tag
            final_outbounds.append(node)
            final_tags.append(unique_tag)
        except: continue

    config = get_114_clean_template()
    config['outbounds'].extend(final_outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + final_tags + ["direct"]
    config['outbounds'][1]['outbounds'] = final_tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✅ 成功！生成 {len(final_outbounds)} 个优质节点。适配 Sing-box v1.14+ (无 API 版)。")

if __name__ == "__main__":
    main()
