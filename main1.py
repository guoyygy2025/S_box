import requests
import base64
import socket
import concurrent.futures
import json
import re
import platform
from urllib.parse import urlparse, parse_qs

# --- 核心配置 ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", 
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

# SRS 广告规则
AD_BLOCK_SRS = "https://gh-proxy.org/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"

MAX_KEEP_NODES = 50
TIMEOUT = 0.5 
DOWNLOAD_DOMAINS = ["gh-proxy.org", "gh-proxy.com", "jsdelivr.net"]

def get_system_stack():
    system = platform.system().lower()
    return "system" if ("android" in system or "linux" in system) else "gvisor"

def get_base_template():
    stack_type = get_system_stack()
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
                # 【修复关键 1】YouTube 专用 DNS 规则，放在拦截之前
                {"domain_suffix": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com"], "server": "dns_proxy", "action": "route"},
                # 广告拦截
                {"rule_set": ["geosite-ads", "adblock-extra"], "server": "dns_block", "action": "route"},
                {"rule_set": "geosite-cn", "server": "dns_local", "action": "route"},
                {"query_type": ["A", "AAAA"], "server": "fakeip_server", "action": "route"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "inet4_address": ["172.19.0.1/30"],
            "inet6_address": ["fd00::1/126"], "auto_route": True, "strict_route": True,
            "stack": stack_type, "mtu": 1280, "sniff": True, "sniff_override_destination": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test"]}, 
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
                # 【修复关键 2】YouTube 路由规则，放在拦截之前，强制走代理
                {"domain_suffix": ["youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com"], "outbound": "proxy"},
                # 广告拦截
                {"rule_set": ["geosite-ads", "adblock-extra"], "action": "reject"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "rule_set": [
                {"tag": "adblock-extra", "type": "remote", "format": "binary", "url": AD_BLOCK_SRS, "download_detour": "direct"},
                {"tag": "geosite-ads", "type": "remote", "format": "binary", "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs", "download_detour": "direct"},
                {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "download_detour": "direct"},
                {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "download_detour": "direct"}
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
            return (link, ip)
    except: return None

def main():
    print("🔄 正在生成修复版配置（YouTube 白名单 + 增强广告过滤）...")
    raw_links = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=5)
            text = r.text if "://" in r.text else safe_decode(r.text)
            raw_links.extend(re.findall(r"(?:vless|trojan|hysteria2|hy2)://[^\s#]+", text))
        except: continue

    unique_links = list(set(raw_links))
    nodes_to_test = [(l, urlparse(l).hostname, urlparse(l).port or 443) for l in unique_links if urlparse(l).hostname]

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        valid_nodes = [r for r in ex.map(check_node, nodes_to_test) if r][:MAX_KEEP_NODES]

    outbounds_list, tags = [], []
    for i, (link, ip) in enumerate(valid_nodes):
        try:
            u, tag = urlparse(link), f"🚀Node-{i:02d}"
            q = parse_qs(u.query)
            node = {"type": u.scheme.replace("hysteria2", "hy2"), "tag": tag, "server": ip, "server_port": int(u.port or 443)}
            if u.scheme == "vless":
                node.update({"uuid": u.username, "flow": q.get('flow', ['xtls-rprx-vision'])[0], "packet_encoding": "xudp", "tls": {"enabled": True, "server_name": q.get('sni', [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}})
                if 'pbk' in q: node["tls"]["reality"] = {"enabled": True, "public_key": q['pbk'][0], "short_id": q.get('sid', [''])[0]}
                if q.get('type', [''])[0] == 'ws': node["transport"] = {"type": "ws", "path": q.get('path', ['/'])[0], "headers": {"Host": q.get('host', [u.hostname])[0]}}
            elif u.scheme == "trojan":
                node.update({"password": u.username, "tls": {"enabled": True, "server_name": q.get('sni', [u.hostname])[0]}})
            outbounds_list.append(node)
            tags.append(tag)
        except: continue

    config = get_base_template()
    config['outbounds'].extend(outbounds_list)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + tags + ["direct"]
    config['outbounds'][1]['outbounds'] = tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print("-" * 30)
    print(f"✅ 完成！YouTube 已设为白名单代理，广告过滤已生效。")

if __name__ == "__main__":
    main()
