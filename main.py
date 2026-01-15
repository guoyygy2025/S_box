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

# 添加 UA 避免被 GitHub 拒绝
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def get_114_template():
    """
    Sing-box 1.14+ 标准配置模板
    - cache_file 移至根目录
    - sniffing 对象化
    - 移除弃用的 DNS 选项
    """
    return {
        "log": {"level": "info", "timestamp": True},
        # 1.14+ 缓存文件标准写法
        "cache_file": {
            "enabled": True,
            "path": "cache.db",
            "store_fakeip": True,
            "store_rdrc": True
        },
        "dns": {
            "servers": [
                # 远程 DNS (走代理)
                {"tag": "dns_remote", "address": "https://1.1.1.1/dns-query", "address_resolver": "dns_local", "detour": "proxy"},
                # 本地 DNS (直连)
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                # FakeIP
                {"tag": "dns_fakeip", "address": "fakeip"}
            ],
            "rules": [
                {"outbound": "any", "server": "dns_local"}, 
                {"clash_mode": "direct", "server": "dns_local"},
                {"clash_mode": "global", "server": "dns_remote"},
                
                # 特定域名解析
                {"domain_suffix": DOWNLOAD_DOMAINS, "server": "dns_local"},
                {"rule_set": "geosite-cn", "server": "dns_local"},
                
                # 剩余走 FakeIP
                {"query_type": ["A", "AAAA"], "server": "dns_fakeip"}
            ],
            "fakeip": {
                "enabled": True,
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            },
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
                # 1.14+ 推荐写法
                "sniffing": {
                    "enabled": True,
                    "dest_override": ["http", "tls", "quic"],
                    "metadata_only": False
                }
            }
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"], "interrupt_exist_connections": True},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m", "tolerance": 50},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block-out"}
        ],
        "route": {
            "default_domain_resolver": "dns_local",
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"domain_suffix": DOWNLOAD_DOMAINS, "outbound": "direct"},
                # 广告拦截 (reject)
                {"rule_set": "ad-rules", "action": "reject"},
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
        # 可选：Clash API 支持 (方便 UI 面板控制)
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "external_ui_download_url": "https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip",
                "external_ui_download_detour": "direct",
                "default_mode": "rule"
            }
        }
    }

def safe_decode(data):
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
        # 增加 headers 防止被屏蔽
        r = requests.get("https://1.1.1.1/dns-query", params={"name": domain, "type": "A"}, headers={"accept": "application/dns-json", **HEADERS}, timeout=3.0)
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
            r = requests.get(url, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                text = r.text
                if "://" not in text: text = safe_decode(text)
                found = link_regex.findall(text)
                raw_links.extend(found)
                print(f"  √ 已抓取: {url[:40]}... ({len(found)} 个)")
        except Exception as e:
            print(f"  x 抓取失败 {url[:20]}: {e}")

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
            
            # 过滤掉显然错误的端口
            if not isinstance(port, int) or port <= 0 or port > 65535: continue

            if hostname:
                ip = resolve_with_1111(hostname) 
                if ip: 
                    nodes_to_test.append((link, ip, port))
        except: pass

    # 使用线程池测速
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
                     # 1.14+ 推荐显式声明 flow (如有)
                     if 'flow' in q:
                        node["flow"] = q['flow'][0]

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

    config = get_114_template()
    config['outbounds'].extend(final_outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + final_tags + ["direct"]
    config['outbounds'][1]['outbounds'] = final_tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"✅ 完成！已保存 {len(final_outbounds)} 个节点 (Sing-box 1.14+ 专用格式)。")
    print("提示：此配置启用了 Clash API (9090端口)，可直接配合 Yacd/Metacubexd 面板使用。")

if __name__ == "__main__":
    main()
