import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import dns.resolver
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置区 ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

# 资源与 DNS 配置
AD_RULES_URL = "https://v6.gh-proxy.org/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
ALI_DOH = "https://dns.alidns.com/dns-query" 
ALI_IP = "223.5.5.5" 

# 测速配置 (已调整为 500ms 严选模式)
TIMEOUT = 0.5        # 建立连接的超时时间 (秒)
MAX_LATENCY = 500    # 允许的最大延迟 (毫秒)，超过此值的节点将被丢弃
MAX_WORKERS = 60     # 并发线程数

# 地区过滤正则表达式 (仅保留美、日、韩)
REGION_RE = re.compile(r"日本|JP|Japan|韩国|KR|Korea|美国|US|United States", re.I)

# --- sing-box 1.12.x 现代配置模板 ---
SB_TEMPLATE = {
    "log": {"level": "info", "timestamp": True},
    "dns": {
        "servers": [
            {"tag": "dns_proxy", "address": ALI_DOH, "address_resolver": "dns_direct", "detour": "proxy"},
            {"tag": "dns_direct", "address": ALI_IP, "detour": "direct"},
            {"tag": "dns_fakeip", "address": "fakeip"}
        ],
        "rules": [
            {"outbound": "any", "server": "dns_direct"},
            {"rule_set": "geosite-cn", "server": "dns_direct"},
            {"rule_set": "ad-rules", "server": "dns_direct", "action": "reject"},
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
        {"type": "dns", "tag": "dns-out"},
        {"type": "block", "tag": "block-out"}
    ],
    "route": {
        "rules": [
            {"protocol": "dns", "outbound": "dns-out"},
            {"rule_set": "ad-rules", "outbound": "block-out"},
            {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
        ],
        "rule_set": [
            {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "proxy"},
            {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "proxy"},
            {"tag": "ad-rules", "type": "remote", "format": "binary", "url": AD_RULES_URL, "download_detour": "proxy"}
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
    """使用阿里 DNS 解析并严格测量 TCP 延迟"""
    try:
        if "vmess://" in node_link:
            data = json.loads(base64.b64decode(node_link[8:]).decode())
            host, port = data['add'], int(data['port'])
        else:
            u = urlparse(node_link)
            host, port = u.hostname, u.port

        # 1. 使用阿里 DNS 解析
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ALI_IP]
            answer = resolver.resolve(host, 'A')
            ip = str(answer[0])
        else:
            ip = host

        # 2. 测量握手延迟
        start_time = time.time()
        with socket.create_connection((ip, port), timeout=TIMEOUT):
            latency = (time.time() - start_time) * 1000
            
        # 3. 500ms 阈值判断
        if latency <= MAX_LATENCY:
            return node_link
    except:
        return None
    return None

def parse_to_outbound(link):
    try:
        if link.startswith("vmess://"):
            data = json.loads(base64.b64decode(link[8:]).decode())
            tag = data.get('ps', 'Node')
        else:
            u = urlparse(link)
            tag = unquote(u.fragment) or "Node"
        
        if not REGION_RE.search(tag): return None

        if link.startswith("vmess://"):
            data = json.loads(base64.b64decode(link[8:]).decode())
            node = {
                "type": "vmess", "tag": tag, "server": data['add'], "server_port": int(data['port']),
                "uuid": data['id'], "security": "auto", "alter_id": 0
            }
            if data.get('net') and data['net'] != "tcp": node["transport"] = {"type": data['net']}
            if data.get('tls') == "tls": node["tls"] = {"enabled": True, "server_name": data.get('sni', data['add'])}
            return node
            
        elif link.startswith(("vless://", "trojan://")):
            u = urlparse(link); q = parse_qs(u.query)
            protocol = u.scheme
            node = {"type": protocol, "tag": tag, "server": u.hostname, "server_port": int(u.port)}
            if protocol == "vless": node["uuid"] = u.username
            else: node["password"] = u.username
            if "tls" in link or q.get('security', [''])[0] == 'tls':
                node["tls"] = {"enabled": True, "server_name": q.get('sni', [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}
            return node
    except: return None

def main():
    all_nodes = []
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'}
    
    for url in SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                content = r.text.strip()
                decoded = decode_base64(content) or content
                all_nodes.extend([l.strip() for l in decoded.splitlines() if "://" in l])
        except: continue
        
    all_nodes = list(set(all_nodes))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        alive = [r for r in list(ex.map(check_node, all_nodes)) if r]

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
    print(f"筛选完成！已保留延迟低于 500ms 的 {len(tags)} 个美/日/韩节点。")

if __name__ == "__main__":
    main()
