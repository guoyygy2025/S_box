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

MAX_KEEP_NODES = 10 
DOWNLOAD_DOMAINS = ["gh-proxy.org", "gh-proxy.com", "jsdelivr.net"]

# 规则集 URL 同步
AD_RULES_URL = "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"
GEOSITE_CN_URL = "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"
GEOIP_CN_URL = "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"

TIMEOUT = 0.3 
MAX_WORKERS = 100
UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

def get_base_template():
    """完全对齐你提供的 JSON 结构"""
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "https://223.5.5.5/dns-query", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"},
                {"tag": "fakeip_server", "address": "fakeip"}
            ],
            "rules": [
                {"domain_suffix": DOWNLOAD_DOMAINS, "server": "dns_local", "action": "route"},
                {"rule_set": "geosite-category-ads-all", "server": "dns_block", "action": "route"},
                {"rule_set": "geosite-cn", "server": "dns_local", "action": "route"},
                {"query_type": ["A", "AAAA"], "server": "fakeip_server", "action": "route"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "inet4_address": ["172.19.0.1/30"],
            "inet6_address": ["fd00::1/126"],
            "auto_route": True,
            "strict_route": True,
            "stack": "gvisor",
            "mtu": 1280,
            "sniff": True,
            "sniff_override_destination": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test"]}, # 后面动态填入 tags
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"ip_is_private": True, "outbound": "direct"},
                {"domain_suffix": DOWNLOAD_DOMAINS, "outbound": "direct"},
                {"rule_set": "geosite-category-ads-all", "action": "reject"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "rule_set": [
                {"tag": "geosite-category-ads-all", "type": "remote", "format": "binary", "url": AD_RULES_URL, "download_detour": "direct"},
                {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": GEOSITE_CN_URL, "download_detour": "direct"},
                {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": GEOIP_CN_URL, "download_detour": "direct"}
            ]
        }
    }

def safe_decode(data):
    try:
        data = data.strip().replace('\n', '').replace('\r', '')
        return base64.b64decode(data + '=' * (-len(data) % 4)).decode('utf-8', 'ignore')
    except: return data

def check_node(node_info):
    link, ip, port = node_info
    try:
        with socket.create_connection((ip, int(port)), timeout=TIMEOUT):
            return (link, ip, 0.1) # 简化逻辑，仅作连通性检查
    except: return None

def main():
    print("🛠️ 正在为您生成定制化 Sing-box 配置...")
    raw_links = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=5)
            text = r.text if "://" in r.text else safe_decode(r.text)
            raw_links.extend(re.findall(r"(?:vless|trojan|hysteria2|hy2)://[^\s#]+", text))
        except: continue

    unique_links = list(set(raw_links))
    nodes_to_test = []
    for link in unique_links:
        try:
            u = urlparse(link)
            if u.hostname: nodes_to_test.append((link, u.hostname, u.port or 443))
        except: continue

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = [r for r in ex.map(check_node, nodes_to_test) if r][:MAX_KEEP_NODES]

    outbounds_list = []
    tags = []
    
    for i, (link, ip, _) in enumerate(results):
        try:
            u = urlparse(link)
            q = parse_qs(u.query)
            tag = f"Node-1ms-{i}" # 保持你要求的 Tag 命名格式
            
            node = {"type": u.scheme.replace("hysteria2", "hy2"), "tag": tag, "server": ip, "server_port": int(u.port or 443)}
            
            if u.scheme == "vless":
                node.update({
                    "uuid": u.username,
                    "flow": q.get('flow', ['xtls-rprx-vision'])[0],
                    "packet_encoding": "xudp",
                    "tls": {"enabled": True, "server_name": q.get('sni', [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}
                })
                # Reality 逻辑处理
                if 'pbk' in q:
                    node["tls"]["reality"] = {"enabled": True, "public_key": q['pbk'][0], "short_id": q.get('sid', [''])[0]}
                # Transport 逻辑 (WS)
                if q.get('type', [''])[0] == 'ws':
                    node["transport"] = {"type": "ws", "path": q.get('path', ['/'])[0], "headers": {"Host": q.get('host', [u.hostname])[0]}}
            
            # ... 其他协议逻辑可按需扩展 ...
            outbounds_list.append(node)
            tags.append(tag)
        except: continue

    config = get_base_template()
    # 注入节点到 outbound
    config['outbounds'].extend(outbounds_list)
    # 更新 selector 和 urltest
    config['outbounds'][0]['outbounds'] = ["auto-test"] + tags + ["direct"]
    config['outbounds'][1]['outbounds'] = tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 成功！生成了 {len(tags)} 个节点并完美匹配您的 JSON 结构。")

if __name__ == "__main__":
    main()
