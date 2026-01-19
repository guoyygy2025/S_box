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

MAX_KEEP_NODES = 12 
TIMEOUT = 0.8  # 稍微增加，防止漏掉高质量 Reality 节点
DOWNLOAD_DOMAINS = ["gh-proxy.org", "gh-proxy.com", "jsdelivr.net"]

def get_system_stack():
    """根据运行环境自动选择 TUN 堆栈"""
    system = platform.system().lower()
    # 在 Android Termux 下通常 platform.system() 返回 Linux
    # 但我们可以通过是否存在特定环境变量来二次确认
    if "android" in system or "linux" in system:
        print(f"📱 检测到移动端/Linux环境，使用 system 堆栈以节省能耗。")
        return "system"
    else:
        print(f"💻 检测到桌面端环境，使用 gvisor 堆栈。")
        return "gvisor"

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
                {"rule_set": "geosite-category-ads-all", "server": "dns_block", "action": "route"},
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
                {"rule_set": "geosite-category-ads-all", "action": "reject"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "rule_set": [
                {"tag": "geosite-category-ads-all", "type": "remote", "format": "binary", "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs", "download_detour": "direct"},
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
    print("🔄 开始抓取并生成 Sing-box 完美分流配置...")
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
            u, tag = urlparse(link), f"Node-1ms-{i}"
            q = parse_qs(u.query)
            node = {"type": u.scheme.replace("hysteria2", "hy2"), "tag": tag, "server": ip, "server_port": int(u.port or 443)}
            
            if u.scheme == "vless":
                node.update({
                    "uuid": u.username, "flow": q.get('flow', ['xtls-rprx-vision'])[0], "packet_encoding": "xudp",
                    "tls": {"enabled": True, "server_name": q.get('sni', [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}
                })
                if 'pbk' in q:
                    node["tls"]["reality"] = {"enabled": True, "public_key": q['pbk'][0], "short_id": q.get('sid', [''])[0]}
                if q.get('type', [''])[0] == 'ws':
                    node["transport"] = {"type": "ws", "path": q.get('path', ['/'])[0], "headers": {"Host": q.get('host', [u.hostname])[0]}}
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
    print(f"✅ 完成！已为您配置：\n- 自动 {config['inbounds'][0]['stack']} 堆栈\n- 规则强制直连\n- Vision/Reality 自动兼容")

if __name__ == "__main__":
    main()
