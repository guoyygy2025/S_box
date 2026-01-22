import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
from urllib.parse import urlparse, parse_qs, unquote

# ===================== 核心配置 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

RULE_CDN_DOMAIN = "gh-proxy.com"
RULE_CDN = f"https://{RULE_CDN_DOMAIN}/https://raw.githubusercontent.com"
RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 50          
MAX_KEEP_NODES = 50       
CONNECT_TIMEOUT = 1.2     # 单次连接超时
LATENCY_THRESHOLD = 500   # 平均延迟阈值
SAMPLE_COUNT = 3          # 🔴 采样次数：每个节点测试3次，确保0丢包

# ===================== 核心工具 =====================
def get_content(url):
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        text = resp.text.strip()
        if any(proto in text for proto in ["vless://", "trojan://", "hy2://"]):
            return text
        try:
            text_fixed = text.replace('-', '+').replace('_', '/')
            text_fixed += '=' * (-len(text_fixed) % 4)
            decoded = base64.b64decode(text_fixed).decode('utf-8', 'ignore')
            if "://" in decoded: return decoded
        except: pass
        return text
    except: return ""

def extract_links(content):
    links = []
    for line in content.splitlines():
        match = re.search(r'(vless|trojan|hysteria2|hy2)://[^\s#]+', line.strip())
        if match: links.append(match.group(0))
    return list(set(links))

def check_node_stability(link):
    """稳定性测速：多轮采样，0丢包过滤"""
    try:
        u = urlparse(link)
        if not u.hostname: return None
        
        latencies = []
        for _ in range(SAMPLE_COUNT):
            start = time.time()
            try:
                # 尝试建立 TCP 连接
                s = socket.create_connection((u.hostname, u.port or 443), timeout=CONNECT_TIMEOUT)
                s.close()
                latencies.append(int((time.time() - start) * 1000))
            except:
                # 🔴 只要有一次连接失败，就判定为存在丢包，直接剔除
                return None
        
        # 计算平均延迟
        avg_latency = sum(latencies) // len(latencies)
        
        # 🔴 过滤掉平均延迟超过阈值的节点
        if avg_latency < LATENCY_THRESHOLD:
            return {"link": link, "u": u, "latency": avg_latency}
    except:
        pass
    return None

# ===================== 解析逻辑 =====================
def parse_vless(u, q, tag):
    raw_flow = q.get("flow", [""])[0]
    clean_flow = "xtls-rprx-vision" if "xtls-rprx-vision" in raw_flow else ""
    return {
        "type": "vless", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "uuid": u.username, "flow": clean_flow, "packet_encoding": "xudp",
        "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}
    }

def parse_hysteria2(u, q, tag):
    return {
        "type": "hysteria2", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "password": u.username, "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0]}
    }

def parse_trojan(u, q, tag):
    return {
        "type": "trojan", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "password": u.username, "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0]}
    }

# ===================== 主程序 =====================
def main():
    print(f"🚀 Sing-box V6.0 (稳定性增强版 | {SAMPLE_COUNT}次采样 | 0丢包)")
    
    raw_links = []
    for src in SOURCES:
        content = get_content(src)
        links = extract_links(content)
        raw_links.extend(links)
        print(f"📥 {src} -> 发现 {len(links)} 条原始链接")

    unique_links = list(set(raw_links))
    print(f"⚡ 开始对 {len(unique_links)} 个节点进行稳定性交叉测速...")
    
    valid_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(check_node_stability, l) for l in unique_links]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res:
                valid_nodes.append(res)

    valid_nodes.sort(key=lambda x: x['latency'])
    
    if not valid_nodes:
        print(f"❌ 警告：未找到满足 {SAMPLE_COUNT}次连续连接且平均延迟 < {LATENCY_THRESHOLD}ms 的节点。")
        return

    print(f"✅ 筛选出 {len(valid_nodes)} 个稳定节点 (平均延迟: {valid_nodes[0]['latency']}ms)")

    # 生成配置
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://8.8.8.8/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                {"domain": [RULE_CDN_DOMAIN, "github.com", "raw.githubusercontent.com"], "server": "dns_local"},
                {"rule_set": "ads", "server": "dns_block"},
                {"rule_set": "cn_site", "server": "dns_local"}
            ],
            "final": "dns_proxy"
        },
        "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True, "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "http://cp.cloudflare.com", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"domain": [RULE_CDN_DOMAIN, "github.com"], "outbound": "direct"},
                {"ip_is_private": True, "outbound": "direct"},
                {"rule_set": ["cn_site", "cn_ip"], "outbound": "direct"}
            ],
            "rule_set": [
                {
                    "tag": k, "type": "remote", "format": "binary", "url": f"{RULE_CDN}/{v}", "download_detour": "direct"
                } for k, v in RULE_PATHS.items()
            ],
            "final": "proxy"
        }
    }

    # 写入节点
    count = 0
    for i, item in enumerate(valid_nodes[:MAX_KEEP_NODES]):
        u, q = item['u'], parse_qs(item['u'].query)
        raw_name = unquote(u.fragment) if u.fragment else f"StableNode-{i+1}"
        tag = f"{raw_name} | {item['latency']}ms"
        
        try:
            node = None
            if u.scheme == "vless": node = parse_vless(u, q, tag)
            elif u.scheme in ["hy2", "hysteria2"]: node = parse_hysteria2(u, q, tag)
            elif u.scheme == "trojan": node = parse_trojan(u, q, tag)
            
            if node:
                cfg["outbounds"].append(node)
                cfg["outbounds"][0]["outbounds"].append(tag)
                cfg["outbounds"][1]["outbounds"].append(tag)
                count += 1
        except: continue

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print(f"💾 转换完成！已保存 {count} 个经过稳定性筛选的优质节点。")

if __name__ == "__main__":
    main()
