import requests
import base64
import socket
import concurrent.futures
import json
import time
import re
import sys
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置区 ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", 
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

MAX_KEEP_NODES = 800 
AD_RULES_URL = "https://gh-proxy.org/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
GEOIP_CN_URL = "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
GEOSITE_CN_URL = "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"

TIMEOUT = 2       
MAX_WORKERS = 100   
DNS_CACHE = {}

def get_modern_template():
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_fakeip", "address": "fakeip"},
                # 国外 DNS：走代理，通过 dns_local 解析服务器域名
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "address_resolver": "dns_local", "detour": "proxy"},
                # 国内 DNS：直连
                {"tag": "dns_direct", "address": "https://223.5.5.5/dns-query", "address_resolver": "dns_local", "detour": "direct"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"}
            ],
            "rules": [
                {"rule_set": "ad-rules", "server": "dns_local", "action": "reject"},
                {"rule_set": "geosite-cn", "server": "dns_direct"},
                {"query_type": ["A", "AAAA"], "server": "dns_fakeip"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"}
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30"],
                "auto_route": True,
                "strict_route": True,
                "stack": "mixed", # 修复：mixed 兼容性更好
                "sniff": True
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
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
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

def resolve_with_1111(domain):
    if not domain or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain): return domain
    if domain in DNS_CACHE: return DNS_CACHE[domain]
    try:
        r = requests.get("https://1.1.1.1/dns-query", params={"name": domain, "type": "A"}, headers={"accept": "application/dns-json"}, timeout=3.0)
        data = r.json()
        if "Answer" in data:
            for ans in data["Answer"]:
                if ans["type"] == 1:
                    DNS_CACHE[domain] = ans["data"]
                    return ans["data"]
    except: pass
    return None

def extract_region(tag):
    regions = ["香港", "日本", "美国", "韩国", "新加坡", "台湾", "德国", "英国", "HK", "JP", "US", "KR", "SG", "TW", "CN", "MO", "UK", "FR", "RU"]
    for r in regions:
        if r.lower() in tag.lower(): return r.upper()
    return "其它"

def check_node_ali(node_info):
    link, target_ip, port = node_info
    try:
        start_time = time.time()
        with socket.create_connection((target_ip, int(port)), timeout=TIMEOUT):
            return (link, target_ip, time.time() - start_time)
    except: return None

def main():
    print(f"--- 步骤1: 抓取订阅源 ---", flush=True)
    raw_links = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                text = r.text
                if "://" not in text: text = safe_decode(text)
                found = re.findall(r"(?:vless|trojan|hysteria2|hy2)://[^\s]+", text)
                raw_links.extend(found)
                print(f"  √ 已抓取: {url[:40]}... ({len(found)} 个)")
        except: pass

    unique_links = list(set(raw_links))
    print(f"--- 步骤2: 解析域名 ---", flush=True)
    nodes_to_test = []
    for link in unique_links:
        try:
            u = urlparse(link)
            ip = resolve_with_1111(u.hostname)
            if ip: nodes_to_test.append((link, ip, u.port or 443))
        except: pass

    print(f"--- 步骤3: 测速筛选 ---", flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        r1 = [res for res in ex.map(check_node_ali, nodes_to_test) if res]
    
    r1.sort(key=lambda x: x[2])
    final_list = r1[:MAX_KEEP_NODES]

    final_outbounds, final_tags = [], []
    for link, ip, lat in final_list:
        try:
            u = urlparse(link)
            q = parse_qs(u.query)
            protocol = "hysteria2" if u.scheme in ["hy2", "hysteria2"] else u.scheme
            region = extract_region(unquote(u.fragment) or "")
            ms = int(lat * 1000)
            node_tag = f"{region}|{ms}ms"
            
            counter = 1
            unique_tag = node_tag
            while unique_tag in final_tags:
                unique_tag = f"{node_tag}_{counter}"
                counter += 1
            
            node = {
                "type": protocol,
                "tag": unique_tag,
                "server": ip,
                "server_port": int(u.port or 443),
                "password" if protocol != "vless" else "uuid": u.username
            }

            if "tls" in link or "reality" in str(q) or protocol == "hysteria2":
                node["tls"] = {"enabled": True, "server_name": q.get('sni', [u.hostname])[0]}
                if 'pbk' in q:
                    node["tls"]["reality"] = {"enabled": True, "public_key": q['pbk'][0], "short_id": q.get('sid', [''])[0]}
                # 修复：非 Hy2 强制启用 uTLS
                if protocol != "hysteria2":
                    node["tls"]["utls"] = {"enabled": True, "fingerprint": "chrome"}
            
            if q.get('type', [''])[0] == 'ws':
                node["transport"] = {"type": "ws", "path": q.get('path', ['/'])[0], "headers": {"Host": q.get('host', [u.hostname])[0]}}

            final_outbounds.append(node)
            final_tags.append(unique_tag)
        except: continue

    config = get_modern_template()
    config['outbounds'].extend(final_outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + final_tags + ["direct"]
    config['outbounds'][1]['outbounds'] = final_tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✅ 完成！已保存 {len(final_outbounds)} 个节点。")

if __name__ == "__main__":
    main()
