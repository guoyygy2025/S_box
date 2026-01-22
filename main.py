import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import hashlib
from urllib.parse import urlparse, parse_qs, unquote

# ===================== 配置参数 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

LATENCY_THRESHOLD = 500  # 仅保留延迟小于 500ms 的节点
MAX_THREADS = 100        # 测速并发数
TIMEOUT = 4.0            # 建立 TCP 连接的超时时间

# ===================== 工具函数 =====================

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        text = resp.text.strip()
        # 如果是 Base64 格式则解码
        if "://" not in text[:50]:
            try:
                missing_padding = len(text) % 4
                if missing_padding: text += '=' * (4 - missing_padding)
                return base64.b64decode(text).decode('utf-8', 'ignore')
            except: return text
        return text
    except: return ""

def check_node(link):
    """
    通过 TCP 握手简单测速并去重
    """
    if not link.startswith("vless://"): return None
    try:
        u = urlparse(link)
        if not u.hostname or not u.username: return None
        
        start = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((socket.gethostbyname(u.hostname), u.port or 443))
            latency = int((time.time() - start) * 1000)
            
        if latency >= LATENCY_THRESHOLD: return None
        
        # 节点唯一性指纹 (UUID + Server + Port)
        fp = hashlib.md5(f"{u.username}{u.hostname}{u.port}".encode()).hexdigest()
        return {"link": link, "u": u, "latency": latency, "fp": fp}
    except: return None

def parse_vless_to_outbound(item, index):
    u = item['u']
    q = parse_qs(u.query)
    tag = f"Proxy-{index+1} | {item['latency']}ms | {unquote(u.fragment or '')[:10]}"
    
    node = {
        "type": "vless",
        "tag": tag,
        "server": u.hostname,
        "server_port": int(u.port or 443),
        "uuid": u.username,
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", [u.hostname])[0],
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
    }
    
    # Reality 支持
    if q.get("security", [""])[0] == "reality":
        node["tls"]["reality"] = {
            "enabled": True,
            "public_key": q.get("pbk", [""])[0],
            "short_id": q.get("sid", [""])[0]
        }
    
    # Vision 支持
    flow = q.get("flow", [""])[0]
    if "vision" in flow:
        node["flow"] = "xtls-rprx-vision"
        
    return node

# ===================== 主程序 =====================

def main():
    print("📥 正在抓取节点链接...")
    raw_data = "\n".join([get_content(url) for url in SOURCES])
    links = list(set(re.findall(r'vless://[^\s#]+(?:#[^\s]*)?', raw_data)))
    print(f"🔍 提取到 {len(links)} 个初始链接，开始并发测速 (阈值 {LATENCY_THRESHOLD}ms)...")
    
    valid_nodes = []
    seen_fps = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node, links))
        for res in results:
            if res and res["fp"] not in seen_fps:
                valid_nodes.append(res)
                seen_fps.add(res["fp"])
                
    valid_nodes.sort(key=lambda x: x['latency'])
    print(f"✅ 筛选出 {len(valid_nodes)} 个可用节点。")

    # 构建完整的 config.json
    outbounds_list = []
    proxy_tags = []
    
    # 转换节点为 sing-box 格式
    for i, item in enumerate(valid_nodes):
        node = parse_vless_to_outbound(item, i)
        outbounds_list.append(node)
        proxy_tags.append(node["tag"])

    # 如果没有节点，为了防止报错添加一个 dummy
    if not proxy_tags:
        proxy_tags = ["direct"]

    # 您提供的模板结构
    config = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy_selector"},
                {"tag": "dns_local", "address": "https://223.5.5.5/dns-query", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"},
                {"tag": "fakeip_server", "address": "fakeip"}
            ],
            "rules": [
                {"rule_set": "geosite-category-ads-all", "action": "route", "server": "dns_block"},
                {"rule_set": "geosite-cn", "action": "route", "server": "dns_local"},
                {"query_type": ["A", "AAAA"], "action": "route", "server": "fakeip_server"}
            ],
            "final": "dns_proxy",
            "strategy": "prefer_ipv4",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "inet4_address": ["172.19.0.1/30"],
                "inet6_address": ["fd00::1/126"],
                "mtu": 1280,
                "auto_route": True,
                "strict_route": True,
                "stack": "gvisor",
                "sniff": True,
                "sniff_override_destination": True
            }
        ],
        "outbounds": [
            # 1. 代理选择器 (包含所有测速节点)
            {
                "type": "selector",
                "tag": "proxy_selector",
                "outbounds": proxy_tags + ["direct"]
            },
            # 2. 您的原始 proxy 占位符 (重命名为 proxy 以兼容 route.final)
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["proxy_selector"]
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"},
            # 3. 插入所有提取到的节点
            *outbounds_list
        ],
        "route": {
            "default_domain_resolver": "dns_local",
            "rule_set": [
                {
                    "type": "remote", "tag": "geosite-category-ads-all", "format": "binary",
                    "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
                    "download_detour": "direct"
                },
                {
                    "type": "remote", "tag": "geosite-cn", "format": "binary",
                    "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                    "download_detour": "direct"
                },
                {
                    "type": "remote", "tag": "geoip-cn", "format": "binary",
                    "url": "https://gh-proxy.org/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                    "download_detour": "direct"
                }
            ],
            "rules": [
                {"protocol": "dns", "action": "route", "outbound": "dns-out"},
                {"rule_set": "geosite-category-ads-all", "action": "reject"},
                {"ip_is_private": True, "action": "route", "outbound": "direct"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "action": "route", "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True
        }
    }

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"💾 完整的 config.json 已保存到当前目录。共插入 {len(proxy_tags)} 个节点。")

if __name__ == "__main__":
    main()
