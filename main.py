#!/usr/bin/env python3
"""
sing-box vless config generator
Optimized for sing-box 1.12.17 | DNS: 223.5.5.5 (Direct)
"""

import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import hashlib
import logging
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Optional, Set

# ===================== 配置参数 =====================

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

RULE_URLS = {
    "geosite-ads": "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite-cn": "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn": "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

ALIDNS = "223.5.5.5"
LATENCY_THRESHOLD_MS = 500
MAX_KEEP_NODES = 50
CONCURRENT_WORKERS = 100
GH_PROXY_HOSTS = ["gh-proxy.com", "mirror.ghproxy.com", "ghproxy.com"]

# ===================== 工具函数 =====================

def get_content(url: str) -> str:
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        resp.raise_for_status()
        text = resp.text.strip()
        # 自动识别并处理 Base64 订阅
        if not re.search(r'vless://', text, re.IGNORECASE):
            try:
                padding = len(text) % 4
                if padding: text += '=' * (4 - padding)
                return base64.b64decode(text).decode('utf-8', 'ignore')
            except: pass
        return text
    except Exception as e:
        logger.error(f"无法获取 {url}: {e}")
        return ""

def check_node(link: str) -> Optional[Dict]:
    if not link.lower().startswith("vless://"): return None
    try:
        u = urlparse(link)
        hostname, port = u.hostname, u.port or 443
        # TCP 握手测速
        ip = socket.gethostbyname(hostname)
        start_time = time.time()
        with socket.create_connection((ip, port), timeout=3.0):
            pass
        latency = int((time.time() - start_time) * 1000)
        
        if latency > LATENCY_THRESHOLD_MS: return None
        
        # 指纹去重 (UUID + Server + Port)
        fp = hashlib.md5(f"{u.username}{hostname}{port}".encode()).hexdigest()
        return {"link": link, "parsed": u, "latency": latency, "fingerprint": fp}
    except:
        return None

def generate_config(valid_nodes: List[Dict]) -> Dict:
    sorted_nodes = sorted(valid_nodes, key=lambda x: x['latency'])[:MAX_KEEP_NODES]
    
    # 构建静态 Hosts 以解决启动时的 DNS 环路
    hosts_map = {}
    for host in GH_PROXY_HOSTS:
        try:
            ips = list(set(socket.gethostbyname_ex(host)[2]))
            hosts_map[host] = ips
        except:
            if "gh-proxy.com" in host: hosts_map[host] = ["104.21.64.137", "172.67.183.248"]

    # 初始化出站列表
    outbounds = [
        {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
        {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "http://cp.cloudflare.com/generate_204", "interval": "3m"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "dns", "tag": "dns-out"}
    ]

    proxy_tags = []
    for i, item in enumerate(sorted_nodes):
        u, q = item['parsed'], parse_qs(item['parsed'].query)
        tag = f"{unquote(u.fragment or f'Node-{i+1}')} | {item['latency']}ms"
        
        node = {
            "type": "vless", "tag": tag,
            "server": u.hostname, "server_port": int(u.port or 443),
            "uuid": u.username, "packet_encoding": "xudp",
            "tls": {
                "enabled": True,
                "server_name": q.get("sni", [u.hostname])[0],
                "utls": {"enabled": True, "fingerprint": "chrome"}
            }
        }
        # 处理 Reality 和 Vision
        if "vision" in q.get("flow", [""])[0]: node["flow"] = "xtls-rprx-vision"
        if q.get("security", [""])[0] == "reality":
            node["tls"]["reality"] = {
                "enabled": True, 
                "public_key": q.get("pbk", [""])[0], 
                "short_id": q.get("sid", [""])[0]
            }
        outbounds.append(node)
        proxy_tags.append(tag)

    outbounds[0]["outbounds"].extend(proxy_tags)
    outbounds[1]["outbounds"].extend(proxy_tags)

    # 完整 1.12.17 配置结构
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": ALIDNS, "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"},
                {"tag": "fakeip_server", "address": "fakeip"}
            ],
            "rules": [
                {"domain": GH_PROXY_HOSTS, "action": "route", "server": "dns_local"},
                {"rule_set": "geosite-ads", "action": "route", "server": "dns_block"},
                {"rule_set": "geosite-cn", "action": "route", "server": "dns_local"},
                {"query_type": ["A", "AAAA"], "action": "route", "server": "fakeip_server"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4",
            "hosts": hosts_map,
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"}
        },
        "inbounds": [{
            "type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30",
            "auto_route": True, "strict_route": True, "stack": "system", "sniff": True
        }],
        "outbounds": outbounds,
        "route": {
            "rule_set": [
                {"type": "remote", "tag": "geosite-ads", "format": "binary", "url": RULE_URLS["geosite-ads"], "download_detour": "direct"},
                {"type": "remote", "tag": "geosite-cn", "format": "binary", "url": RULE_URLS["geosite-cn"], "download_detour": "direct"},
                {"type": "remote", "tag": "geoip-cn", "format": "binary", "url": RULE_URLS["geoip-cn"], "download_detour": "direct"}
            ],
            "rules": [
                {"protocol": "dns", "action": "route", "outbound": "dns-out"},
                {"domain": GH_PROXY_HOSTS, "action": "route", "outbound": "direct"},
                {"rule_set": "geosite-ads", "action": "reject"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "action": "route", "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True
        }
    }

# ===================== 执行入口 =====================

def main():
    logger.info("🚀 开始生成 sing-box 1.12.17 配置...")
    
    # 1. 多线程获取内容
    all_texts = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(get_content, url): url for url in SOURCES}
        for f in concurrent.futures.as_completed(futures):
            all_texts.append(f.result())

    # 2. 提取并去重
    combined = "\n".join(all_texts)
    links = list(set(re.findall(r'vless://[^\s#]+(?:#[^\s]*)?', combined, re.I)))
    logger.info(f"提取到 {len(links)} 个唯一节点，开始测速...")

    # 3. 并发测速
    valid_nodes = []
    seen_fps = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        results = list(executor.map(check_node, links))
        for res in results:
            if res and res["fingerprint"] not in seen_fps:
                valid_nodes.append(res)
                seen_fps.add(res["fingerprint"])

    # 4. 生成文件
    config = generate_config(valid_nodes)
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    logger.info(f"🎉 成功生成 config.json! 包含 {len(config['outbounds'])-5} 个极速节点。")

if __name__ == "__main__":
    main()
