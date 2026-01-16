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

MAX_KEEP_NODES = 60 
DOWNLOAD_DOMAINS = ["gh-proxy.com", "githubusercontent.com", "github.com", "jsdelivr.net"]

# 规则集 (Sing-box v1.11+ 推荐使用 .srs)
AD_RULES_URL = "https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
GEOIP_CN_URL = "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-cn.srs"
GEOSITE_CN_URL = "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-cn.srs"

TIMEOUT = 0.6  # 稍微放宽以兼容更多地区
MAX_WORKERS = 100

def get_modern_template():
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_fakeip", "address": "fakeip"},
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "address_resolver": "dns_local", "detour": "proxy"},
                {"tag": "dns_direct", "address": "https://223.5.5.5/dns-query", "address_resolver": "dns_local", "detour": "direct"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"} 
            ],
            "rules": [
                {"domain_suffix": DOWNLOAD_DOMAINS, "server": "dns_direct"},
                {"rule_set": "ad-rules", "server": "dns_local", "action": "reject"},
                {"rule_set": "geosite-cn", "server": "dns_direct"},
                {"query_type": ["A", "AAAA"], "server": "dns_fakeip"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"}
        },
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True, "strict_route": True, "stack": "mixed", "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block-out"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"domain_suffix": DOWNLOAD_DOMAINS, "outbound": "direct"},
                {"rule_set": "ad-rules", "outbound": "block-out"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
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
        data = data.strip().replace('\n', '').replace('\r', '')
        return base64.b64decode(data + '=' * (-len(data) % 4)).decode('utf-8', 'ignore')
    except: return data

def extract_region(tag):
    mapping = {"香港": "HK", "HK": "HK", "日本": "JP", "JP": "JP", "美国": "US", "US": "US", "韩国": "KR", "KR": "KR", "新加坡": "SG", "SG": "SG", "台湾": "TW", "TW": "TW"}
    tag_upper = tag.upper()
    for k, v in mapping.items():
        if k in tag_upper: return v
    return "UN"

def check_node(node_info):
    link, ip, port = node_info
    try:
        start = time.time()
        with socket.create_connection((ip, int(port)), timeout=TIMEOUT):
            return (link, ip, time.time() - start)
    except: return None

def main():
    print("🚀 正在收集节点 (支持 VLESS/Trojan/SS/Hy2)...")
    raw_links = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            text = r.text if "://" in r.text else safe_decode(r.text)
            # 扩展正则：支持 ss://, trojan://, vless://, hy2://
            found = re.findall(r"(?:vless|trojan|ss|hysteria2|hy2)://[^\s#]+", text)
            raw_links.extend(found)
        except: continue

    unique_links = list(set(raw_links))
    nodes_to_test = []
    for link in unique_links:
        try:
            u = urlparse(link)
            if u.scheme == 'ss':
                # SS 可能在 netloc 里包含 base64 加密的 userInfo
                nodes_to_test.append((link, u.hostname, u.port or 443))
            else:
                nodes_to_test.append((link, u.hostname, u.port or 443))
        except: continue

    print(f"⚡ 正在对 {len(nodes_to_test)} 个节点进行 TCP 测速...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = [r for r in ex.map(check_node, nodes_to_test) if r]
    
    results.sort(key=lambda x: x[2])
    final_candidates = results[:MAX_KEEP_NODES]

    outbounds, tags = [], []
    for link, ip, lat in final_candidates:
        try:
            u = urlparse(link)
            q = parse_qs(u.query)
            protocol = u.scheme
            if protocol in ["hy2", "hysteria2"]: protocol = "hysteria2"
            
            # 提取地区并生成 Tag
            node_name = unquote(u.fragment) if u.fragment else ""
            region = extract_region(node_name)
            ms = int(lat * 1000)
            tag = f"{region}-{ms}ms"
            
            # 重名处理
            idx = 1
            while tag in tags:
                tag = f"{region}-{ms}ms-{idx}"
                idx += 1

            # 基础节点信息
            node = {"type": protocol, "tag": tag, "server": ip, "server_port": int(u.port or 443)}

            # --- 协议逻辑分发 ---
            if protocol == "vless":
                node.update({"uuid": u.username, "packet_encoding": "xray"})
            
            elif protocol == "trojan":
                node.update({"password": u.username})
            
            elif protocol == "ss":
                # 处理 ss://base64(method:password)@host:port
                if ":" not in u.username:
                    user_info = safe_decode(u.username)
                    method, password = user_info.split(":", 1)
                else:
                    method, password = u.username, u.password
                node.update({"method": method, "password": password})
            
            elif protocol == "hysteria2":
                node.update({"password": u.username})

            # --- TLS/Reality 现代化配置 ---
            if protocol in ["vless", "trojan", "hysteria2"]:
                # 默认开启 TLS，除非明确定义
                node["tls"] = {"enabled": True, "server_name": q.get('sni', [u.hostname])[0]}
                
                # Reality 处理
                if 'pbk' in q:
                    node["tls"]["reality"] = {
                        "enabled": True, 
                        "public_key": q['pbk'][0], 
                        "short_id": q.get('sid', [''])[0]
                    }
                
                # uTLS (Hy2 不支持 utls)
                if protocol != "hysteria2":
                    node["tls"]["utls"] = {"enabled": True, "fingerprint": "chrome"}

            # --- 传输层 (WS) ---
            if q.get('type', [''])[0] == 'ws':
                node["transport"] = {
                    "type": "ws",
                    "path": q.get('path', ['/'])[0],
                    "headers": {"Host": q.get('host', [u.hostname])[0]}
                }

            outbounds.append(node)
            tags.append(tag)
        except Exception as e:
            continue

    # 写入模板
    config = get_modern_template()
    config['outbounds'].extend(outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + tags + ["direct"]
    config['outbounds'][1]['outbounds'] = tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ 处理完成！")
    print(f"📊 获得有效节点: {len(outbounds)} 个")
    print(f"📂 配置文件已保存至: config.json")

if __name__ == "__main__":
    main()
