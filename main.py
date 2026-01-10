import requests
import base64
import socket
import concurrent.futures
import json
import re
import dns.resolver
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置区 (确保为 Raw 原始链接) ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

TIMEOUT = 3
MAX_WORKERS = 50
ALI_DNS = "223.5.5.5"

# --- sing-box 1.12.x 现代配置模板 ---
SB_TEMPLATE = {
    "log": {"level": "info", "timestamp": True},
    "dns": {
        "servers": [
            {"tag": "dns_proxy", "address": "https://8.8.8.8/dns-query", "address_resolver": "dns_direct", "detour": "proxy"},
            {"tag": "dns_direct", "address": "223.5.5.5", "detour": "direct"},
            {"tag": "dns_fakeip", "address": "fakeip"}
        ],
        "rules": [
            {"outbound": "any", "server": "dns_direct"},
            {"rule_set": "geosite-cn", "server": "dns_direct"},
            {"query_type": ["A", "AAAA"], "server": "dns_proxy"}
        ],
        "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"}
    },
    "inbounds": [{
        "type": "tun",
        "inet4_address": "172.19.0.1/30",
        "auto_route": True,
        "strict_route": True,
        "sniff": True
    }],
    "outbounds": [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto-test"]},
        {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
        {"type": "direct", "tag": "direct"},
        {"type": "dns", "tag": "dns-out"}
    ],
    "route": {
        "rules": [
            {"protocol": "dns", "outbound": "dns-out"},
            {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
        ],
        "rule_set": [
            {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "proxy"},
            {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "proxy"}
        ],
        "auto_detect_interface": True
    }
}

def decode_base64(data):
    try:
        data = data.replace('-', '+').replace('_', '/')
        missing_padding = len(data) % 4
        if missing_padding: data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except: return ""

def check_node(node_link):
    try:
        if "vmess://" in node_link:
            data = json.loads(base64.b64decode(node_link[8:]).decode())
            host, port = data['add'], int(data['port'])
        else:
            u = urlparse(node_link)
            host, port = u.hostname, u.port
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            resolver = dns.resolver.Resolver(); resolver.nameservers = [ALI_DNS]
            resolver.resolve(host, 'A')
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return node_link
    except: return None

def parse_to_outbound(link):
    """适配 sing-box 1.12.x 的出站配置格式"""
    try:
        if link.startswith("vmess://"):
            data = json.loads(base64.b64decode(link[8:]).decode())
            node = {
                "type": "vmess",
                "tag": data.get('ps', 'Node'),
                "server": data['add'],
                "server_port": int(data['port']),
                "uuid": data['id'],
                "security": "auto",
                "alter_id": 0
            }
            # 1.12.x 现代传输配置
            if data.get('net') and data['net'] != "tcp":
                node["transport"] = {"type": data['net']}
            if data.get('tls') == "tls":
                node["tls"] = {"enabled": True, "server_name": data.get('sni', data['add'])}
            return node
            
        elif link.startswith(("vless://", "trojan://")):
            u = urlparse(link); q = parse_qs(u.query)
            protocol = u.scheme
            node = {
                "type": protocol,
                "tag": unquote(u.fragment) or "Node",
                "server": u.hostname,
                "server_port": int(u.port),
            }
            if protocol == "vless": node["uuid"] = u.username
            else: node["password"] = u.username
            
            # 1.12.x 现代 TLS 配置
            if "tls" in link or q.get('security', [''])[0] == 'tls':
                node["tls"] = {
                    "enabled": True, 
                    "server_name": q.get('sni', [u.hostname])[0],
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }
            return node
    except: return None

def main():
    nodes = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
    for url in SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                content = r.text.strip()
                decoded = decode_base64(content) or content
                nodes.extend([l.strip() for l in decoded.splitlines() if "://" in l])
        except: continue
        
    nodes = list(set(nodes))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        alive = [r for r in list(ex.map(check_node, nodes)) if r]

    outbounds, tags = [], []
    for l in alive:
        o = parse_to_outbound(l)
        if o:
            t = o['tag']; i = 1
            while t in tags: t = f"{o['tag']} {i}"; i += 1
            o['tag'] = t
            outbounds.append(o)
            tags.append(t)

    config = SB_TEMPLATE.copy()
    config['outbounds'].extend(outbounds)
    config['outbounds'][0]['outbounds'].extend(tags)
    config['outbounds'][1]['outbounds'].extend(tags)

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()
