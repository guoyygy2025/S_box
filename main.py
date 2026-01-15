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

# 筛选阶段配置
ROUND1_KEEP = 300   # 第一轮保留数
MAX_KEEP_NODES = 50 # 最终保留数
TIMEOUT = 0.5       
MAX_WORKERS = 100    

DOWNLOAD_DOMAINS = ["gh-proxy.com", "githubusercontent.com", "github.com", "jsdelivr.net"]
AD_RULES_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
GEOIP_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
GEOSITE_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"

DNS_CACHE = {}

def get_modern_template():
    """
    针对 Sing-box v1.9/v1.10+ 的最新配置模板
    修复 legacy DNS 和 missing domain_resolver 错误
    """
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                # 1. 远程 DNS (走代理)
                {"tag": "dns_remote", "address": "https://1.1.1.1/dns-query", "address_resolver": "dns_local", "detour": "proxy"},
                # 2. 本地 DNS (直连) - 用于解析国内域名和 DoH 域名
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                # 3. FakeIP 占位
                {"tag": "dns_fakeip", "address": "fakeip"}
            ],
            "rules": [
                {"outbound": "any", "server": "dns_local"}, # 必须：防止死循环
                {"clash_mode": "direct", "server": "dns_local"},
                {"clash_mode": "global", "server": "dns_remote"},
                
                # 特定域名走直连 DNS
                {"domain_suffix": DOWNLOAD_DOMAINS, "server": "dns_local"},
                {"rule_set": "geosite-cn", "server": "dns_local"},
                
                # 其余走 FakeIP (配合 Tun)
                {"query_type": ["A", "AAAA"], "server": "dns_fakeip"}
            ],
            # FakeIP 设置块
            "fakeip": {
                "enabled": True,
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            },
            "strategy": "prefer_ipv4",
            "independent_cache": True # 新版推荐
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
                "sniff": True
            }
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block-out"}
        ],
        "route": {
            # 关键修复：指定默认域名解析器，解决 dial fields 报错
            "default_domain_resolver": "dns_local",
            
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"domain_suffix": DOWNLOAD_DOMAINS, "outbound": "direct"},
                # 广告拦截改用 action: reject (更现代的写法，虽然 outbound: block-out 也兼容)
                {"rule_set": "ad-rules", "action": "reject"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"},
                # 兜底
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
            "cache_file": {
                "enabled": True,
                "path": "cache.db"
            }
        }
    }

def safe_decode(data):
    """通用 Base64 解码，自动补全 Padding"""
    if not data: return ""
    try:
        data = data.strip().replace('\n', '').replace('\r', '').replace(' ', '')
        data = data.replace('-', '+').replace('_', '/')
        padding = len(data) % 4
        if padding:
            data += '=' * (4 - padding)
        return base64.b64decode(data).decode('utf-8', 'ignore')
    except:
        return data

def parse_ss_url(link):
    """解析各种格式的 SS 链接"""
    try:
        body = link[5:]
        tag = ""
        if '#' in body:
            body, tag = body.split('#', 1)
            tag = unquote(tag)
        
        if '@' in body:
            userinfo, hostinfo = body.split('@', 1)
            if ':' not in userinfo:
                userinfo = safe_decode(userinfo)
            method, password = userinfo.split(':', 1)
            server, port = hostinfo.split(':', 1)
        else:
            decoded = safe_decode(body)
            if '@' in decoded:
                userinfo, hostinfo = decoded.split('@', 1)
                method, password = userinfo.split(':', 1)
                server, port = hostinfo.split(':', 1)
            else:
                return None 

        return {
            "type": "shadowsocks",
            "server": server,
            "server_port": int(port),
            "method": method,
            "password": password,
            "tag_info": tag
        }
    except:
        return None

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

def check_node(node_info):
    link, target_ip, port = node_info
    try:
        start_time = time.time()
        with socket.create_connection((target_ip, int(port)), timeout=TIMEOUT):
            return (link, target_ip, port, time.time() - start_time)
    except: return None

def extract_region(tag):
    regions = ["香港", "日本", "美国", "韩国", "新加坡", "台湾", "德国", "英国", "HK", "JP", "US", "KR", "SG", "TW", "CN", "MO", "UK", "FR", "RU", "DE", "NL", "CA", "AU"]
    for r in regions:
        if r.lower() in tag.lower(): return r.upper()
    return "其它"

def main():
    print(f"--- 步骤1: 抓取订阅源 ---", flush=True)
    raw_links = []
    link_regex = re.compile(r"(?:vless|trojan|hysteria2|hy2|ss)://[^\s]+")
    
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                text = r.text
                if "://" not in text: text = safe_decode(text)
                found = link_regex.findall(text)
                raw_links.extend(found)
                print(f"  √ 已抓取: {url[:40]}... ({len(found)} 个)")
        except: pass

    unique_links = list(set(raw_links))
    print(f"  总去重后节点数: {len(unique_links)}")
    
    print(f"--- 步骤2: 第一轮测速 (1.1.1.1 解析 -> 筛选前 {ROUND1_KEEP} 名) ---", flush=True)
    nodes_to_test = []
    
    for link in unique_links:
        try:
            scheme = link.split("://")[0]
            hostname = ""
            port = 443
            
            if scheme == "ss":
                info = parse_ss_url(link)
                if info:
                    hostname = info['server']
                    port = info['server_port']
            else:
                u = urlparse(link)
                hostname = u.hostname
                port = u.port or 443
            
            if hostname:
                ip = resolve_with_1111(hostname) 
                if ip: 
                    nodes_to_test.append((link, ip, port))
        except: pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        round1_results = [res for res in ex.map(check_node, nodes_to_test) if res]
    
    round1_results.sort(key=lambda x: x[3])
    survivors = round1_results[:ROUND1_KEEP]
    print(f"  > 第一轮完成，剩余 {len(survivors)} 个节点")

    print(f"--- 步骤3: 第二轮测速 (剔除不稳定节点) ---", flush=True)
    nodes_r2 = [(s[0], s[1], s[2]) for s in survivors]
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        round2_results = [res for res in ex.map(check_node, nodes_r2) if res]
    
    round2_results.sort(key=lambda x: x[3])
    survivors_r2 = round2_results 
    print(f"  > 第二轮完成，剩余 {len(survivors_r2)} 个节点")

    print(f"--- 步骤4: 第三轮测速 (精选前 {MAX_KEEP_NODES} 名) ---", flush=True)
    nodes_r3 = [(s[0], s[1], s[2]) for s in survivors_r2]
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        round3_results = [res for res in ex.map(check_node, nodes_r3) if res]
    
    round3_results.sort(key=lambda x: x[3])
    final_list = round3_results[:MAX_KEEP_NODES]
    print(f"  > 第三轮完成，最终保留 {len(final_list)} 个优质节点")

    # --- 生成配置部分 ---
    final_outbounds, final_tags = [], []
    for link, ip, port, lat in final_list:
        try:
            node = {}
            scheme = link.split("://")[0]
            origin_tag = ""
            
            if scheme == "ss":
                info = parse_ss_url(link)
                if not info: continue
                origin_tag = info['tag_info']
                node = {
                    "type": "shadowsocks",
                    "server": ip,
                    "server_port": info['server_port'],
                    "method": info['method'],
                    "password": info['password']
                }
            
            elif scheme == "trojan":
                u = urlparse(link)
                q = parse_qs(u.query)
                origin_tag = unquote(u.fragment)
                node = {
                    "type": "trojan",
                    "server": ip,
                    "server_port": int(port),
                    "password": u.username
                }
                sni = q.get('sni', [q.get('peer', [u.hostname])[0]])[0] 
                node["tls"] = {"enabled": True, "server_name": sni}
                if 'allowInsecure' in q and q['allowInsecure'][0] == '1':
                    node["tls"]["insecure"] = True

            elif scheme in ["vless", "hysteria2", "hy2"]:
                u = urlparse(link)
                q = parse_qs(u.query)
                origin_tag = unquote(u.fragment)
                protocol_type = "hysteria2" if scheme in ["hy2", "hysteria2"] else "vless"
                
                node = {
                    "type": protocol_type,
                    "server": ip,
                    "server_port": int(port),
                    "password" if protocol_type != "vless" else "uuid": u.username
                }
                
                if protocol_type == "hysteria2" or "tls" in link or "reality" in str(q):
                    sni = q.get('sni', [u.hostname])[0]
                    node["tls"] = {"enabled": True, "server_name": sni}
                    
                    if 'pbk' in q: 
                        node["tls"]["reality"] = {
                            "enabled": True, 
                            "public_key": q['pbk'][0], 
                            "short_id": q.get('sid', [''])[0]
                        }
                    elif protocol_type != "hysteria2": 
                        node["tls"]["utls"] = {"enabled": True, "fingerprint": "chrome"}
                
                if q.get('type', [''])[0] == 'ws':
                    node["transport"] = {
                        "type": "ws", 
                        "path": q.get('path', ['/'])[0], 
                        "headers": {"Host": q.get('host', [u.hostname])[0]}
                    }
                
                if protocol_type == "vless":
                     node["flow"] = q.get('flow', [''])[0] 

            region = extract_region(origin_tag or "")
            ms = int(lat * 1000)
            node_tag = f"{region}|{ms}ms"
            
            counter = 1
            unique_tag = node_tag
            while unique_tag in final_tags:
                unique_tag = f"{node_tag}_{counter}"
                counter += 1
            
            node["tag"] = unique_tag
            final_outbounds.append(node)
            final_tags.append(unique_tag)
            
        except: continue

    config = get_modern_template()
    config['outbounds'].extend(final_outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + final_tags + ["direct"]
    config['outbounds'][1]['outbounds'] = final_tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✅ 完成！已保存 {len(final_outbounds)} 个精选节点 (v1.9+ 兼容格式)。")

if __name__ == "__main__":
    main()
