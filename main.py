import requests
import base64
import socket
import concurrent.futures
import json
import re
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

TIMEOUT = 3
MAX_WORKERS = 50
ALI_DNS = "223.5.5.5"

# 地区过滤关键词 (正则模式)
REGION_RE = re.compile(r"香港|HK|Hong Kong|日本|JP|Japan|韩国|KR|Korea|美国|US|United States", re.I)

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
            {"rule_set": "ad-rules", "server": "dns_direct", "action": "reject"}, # DNS 层面拦截广告
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
        {"type": "block", "tag": "block-out"} # 拦截出站
    ],
    "route": {
        "rules": [
            {"protocol": "dns", "outbound": "dns-out"},
            {"rule_set": "ad-rules", "outbound": "block-out"}, # 流量层面拦截广告
            {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
        ],
        "rule_set": [
            {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "proxy"},
            {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "proxy"},
            {"tag": "ad-rules", "type": "remote", "format": "binary", "url": "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs", "download_detour": "proxy"}
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
    """节点存活及域名解析检查"""
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
    """解析节点并执行地区过滤"""
    try:
        if link.startswith("vmess://"):
            data = json.loads(base64.b64decode(link[8:]).decode())
            tag = data.get('ps', 'Node')
            if not REGION_RE.search(tag): return None # 地区过滤
            
            node = {
                "type": "vmess",
                "tag": tag,
                "server": data['add'],
                "server_port": int(data['port']),
                "uuid": data['id'],
                "security": "auto",
                "alter_id": 0
            }
            if data.get('net') and data['net'] != "tcp":
                node["transport"] = {"type": data['net']}
            if data.get('tls') == "tls":
                node["tls"] = {"enabled": True, "server_name": data.get('sni', data['add'])}
            return node
            
        elif link.startswith(("vless://", "trojan://")):
            u = urlparse(link); q = parse_qs(u.query)
            tag = unquote(u.fragment) or "Node"
            if not REGION_RE.search(tag): return None # 地区过滤
            
            protocol = u.scheme
            node = {
                "type": protocol,
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port),
            }
            if protocol == "vless": node["uuid"] = u.username
            else: node["password"] = u.username
            
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
    
    # 1. 抓取并合并源
    for url in SOURCES:
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200:
                content = r.text.strip()
                decoded = decode_base64(content) or content
                nodes.extend([l.strip() for l in decoded.splitlines() if "://" in l])
        except: continue
    
    # 2. 去重与测速/存活检查
    nodes = list(set(nodes))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        alive = [r for r in list(ex.map(check_node, nodes)) if r]

    # 3. 转换格式并进行标签唯一化处理
    outbounds, tags = [], []
    for l in alive:
        o = parse_to_outbound(l)
        if o:
            t = o['tag']; i = 1
            while t in tags: t = f"{o['tag']} {i}"; i += 1
            o['tag'] = t
            outbounds.append(o)
            tags.append(t)

    # 4. 构建完整配置
    config = SB_TEMPLATE.copy()
    config['outbounds'].extend(outbounds)
    config['outbounds'][0]['outbounds'].extend(tags) # selector 加入节点
    config['outbounds'][1]['outbounds'].extend(tags) # urltest 加入节点

    # 5. 写入文件
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"成功更新！保存了 {len(tags)} 个 {REGION_RE.pattern} 节点。")

if __name__ == "__main__":
    main()
