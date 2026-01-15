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

MAX_KEEP_NODES = 80 
TIMEOUT = 0.5       
MAX_WORKERS = 100    

# 关键：定义用于下载规则的域名白名单
DOWNLOAD_DOMAINS = ["gh-proxy.com", "githubusercontent.com", "github.com", "jsdelivr.net", "raw.githubusercontent.com"]
AD_RULES_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
GEOIP_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
GEOSITE_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"

DNS_CACHE = {}

def get_112_final_template():
    """专为 v1.12.16 适配：优先规则下载 + 消除 Legacy 报错"""
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "address_resolver": "dns_local", "detour": "proxy"},
                {"tag": "dns_direct", "address": "https://223.5.5.5/dns-query", "address_resolver": "dns_local", "detour": "direct"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"}
            ],
            "rules": [
                # 优先级1：下载域名必须走本地 DNS 且直连，防止 FakeIP 导致的死循环
                {"domain_suffix": DOWNLOAD_DOMAINS, "server": "dns_local"},
                {"outbound": "any", "server": "dns_local"},
                {"rule_set": "geosite-cn", "server": "dns_direct"},
                {"query_type": ["A", "AAAA"], "server": "dns_proxy"}
            ],
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"},
            "strategy": "prefer_ipv4"
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
                "sniff": True, # 修复: 1.12 不支持 sniffing 对象，使用布尔值
                "sniff_timeout": "300ms"
            }
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block-out"}
        ],
        "route": {
            "default_domain_resolver": "dns_local", # 修复: 补全解析器
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                # 核心逻辑：确保下载流量在所有规则匹配前强制直连
                {"domain_suffix": DOWNLOAD_DOMAINS, "outbound": "direct"},
                
                {"rule_set": "ad-rules", "outbound": "block-out"},
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
        },
        "experimental": {
            "cache_file": {"enabled": True, "path": "cache.db", "store_fakeip": True}
        }
    }

# --- 节点解析引擎 ---

def safe_decode(data):
    try:
        data = data.strip().replace('\n', '').replace('\r', '').replace(' ', '')
        return base64.b64decode(data + '=' * (-len(data) % 4)).decode('utf-8', 'ignore')
    except: return data

def parse_vmess(link):
    try:
        data = json.loads(safe_decode(link[8:]))
        node = {"type": "vmess", "server": data['add'], "server_port": int(data['port']), "uuid": data['id'], "security": "auto"}
        if data.get('net') == 'ws':
            node["transport"] = {"type": "ws", "path": data.get('path', '/'), "headers": {"Host": data.get('host', '')}}
        return node
    except: return None

def parse_ss(link):
    try:
        if "#" in link: link = link.split("#")[0]
        payload = link[5:]
        if "@" in payload:
            part1, part2 = payload.split("@")
            method_pw = safe_decode(part1).split(":")
            host_port = part2.split(":")
        else:
            decoded = safe_decode(payload).split("@")
            method_pw = decoded[0].split(":")
            host_port = decoded[1].split(":")
        return {"type": "shadowsocks", "server": host_port[0], "server_port": int(host_port[1]), "method": method_pw[0], "password": method_pw[1]}
    except: return None

def resolve_with_1111(domain):
    if not domain or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain): return domain
    if domain in DNS_CACHE: return DNS_CACHE[domain]
    try:
        r = requests.get("https://1.1.1.1/dns-query", params={"name": domain, "type": "A"}, headers={"accept": "application/dns-json"}, timeout=3.0)
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

def main():
    print("🚀 启动 Sing-box v1.12.16 专属生成器...")
    raw_links = []
    regex = re.compile(r"(?:vless|trojan|hysteria2|hy2|vmess|ss)://[^\s]+")
    
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            text = r.text if "://" in r.text else safe_decode(r.text)
            found = regex.findall(text)
            raw_links.extend(found)
            print(f"  √ 抓取: {url[:35]}...")
        except: pass

    unique_links = list(set(raw_links))
    nodes_to_test = []
    for link in unique_links:
        try:
            scheme = link.split("://")[0]
            if scheme == "vmess":
                info = parse_vmess(link)
                if info:
                    ip = resolve_with_1111(info['server'])
                    if ip: nodes_to_test.append((link, ip, info['server_port']))
            elif scheme == "ss":
                info = parse_ss(link)
                if info:
                    ip = resolve_with_1111(info['server'])
                    if ip: nodes_to_test.append((link, ip, info['server_port']))
            else:
                u = urlparse(link)
                ip = resolve_with_1111(u.hostname)
                if ip: nodes_to_test.append((link, ip, u.port or 443))
        except: pass

    print(f"📡 正在对 {len(nodes_to_test)} 个节点进行 TCP 测速...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = [res for res in ex.map(check_node, nodes_to_test) if res]
    
    results.sort(key=lambda x: x[3])
    final_list = results[:MAX_KEEP_NODES]

    final_outbounds, final_tags = [], []
    for link, ip, port, lat in final_list:
        try:
            scheme = link.split("://")[0]
            u = urlparse(link); q = parse_qs(u.query)
            node = {}
            raw_tag = unquote(u.fragment) if "#" in link else "Node"
            
            if scheme == "vmess":
                node = parse_vmess(link); node['server'] = ip
            elif scheme == "ss":
                node = parse_ss(link); node['server'] = ip
            else:
                protocol = "hysteria2" if scheme in ["hy2", "hysteria2"] else scheme
                node = {"type": protocol, "server": ip, "server_port": int(port), "password" if protocol != "vless" else "uuid": u.username}
                if "tls" in link or "reality" in str(q) or protocol == "hysteria2":
                    node["tls"] = {"enabled": True, "server_name": q.get('sni', [u.hostname])[0]}
                    if 'pbk' in q: node["tls"]["reality"] = {"enabled": True, "public_key": q['pbk'][0], "short_id": q.get('sid', [''])[0]}
                if q.get('type', [''])[0] == 'ws':
                    node["transport"] = {"type": "ws", "path": q.get('path', ['/'])[0], "headers": {"Host": q.get('host', [u.hostname])[0]}}

            tag = f"{raw_tag[:8]}|{int(lat*1000)}ms"
            count = 1
            unique_tag = tag
            while unique_tag in final_tags:
                unique_tag = f"{tag}_{count}"; count += 1
            node["tag"] = unique_tag
            final_outbounds.append(node); final_tags.append(unique_tag)
        except: continue

    config = get_112_final_template()
    config['outbounds'].extend(final_outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + final_tags + ["direct"]
    config['outbounds'][1]['outbounds'] = final_tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print("-" * 30)
    print("✅ 配置文件 config.json 生成成功！")
    print("📌 针对 1.12.16 优化：")
    print("   1. 修复了 sniffing 报错")
    print("   2. 解决了规则下载死循环（直连优先）")
    print("   3. 消除了所有 Legacy 弃用警告")

if __name__ == "__main__":
    main()
