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
    # 可以在这里添加更多订阅源
]

# 使用国内加速镜像，防止下载规则超时
RULE_CDN = "https://gh-proxy.com/https://raw.githubusercontent.com"
RULE_PATHS = {
    "adblock": "217heidai/adblockfilters/main/rules/adblocksingbox.srs",
    "geosite_ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite_cn": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip_cn": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 80        # 提高并发数加快测速
MAX_KEEP_NODES = 100     # 保留节点数量
CONNECT_TIMEOUT = 1.5   # 连接超时时间(秒)

# ===================== 工具函数 =====================
def safe_decode(text):
    """鲁棒的 Base64 解码，处理各种填充错误"""
    text = text.strip().replace('-', '+').replace('_', '/')
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
    except:
        return text

def check_node(link):
    """TCP 握手测速，返回延迟"""
    try:
        u = urlparse(link)
        host = u.hostname
        port = u.port or 443
        if not host: return None

        start_time = time.time()
        # 建立 TCP 连接进行握手测试
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            latency = int((time.time() - start_time) * 1000)
            return {"link": link, "u": u, "latency": latency}
    except:
        return None

# ===================== 配置解析逻辑 =====================
def parse_vless(u, q, tag):
    node = {
        "type": "vless",
        "tag": tag,
        "server": u.hostname,
        "server_port": u.port or 443,
        "uuid": u.username,
        "flow": q.get("flow", [""])[0],
        "packet_encoding": "xudp",
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", [u.hostname])[0],
            "insecure": q.get("allowInsecure", ["false"])[0] == "1",
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
    }
    
    # 传输层处理 (WS / GRPC)
    net_type = q.get("type", ["tcp"])[0]
    if net_type == "ws":
        node["transport"] = {
            "type": "ws",
            "path": q.get("path", ["/"])[0],
            "headers": {"Host": q.get("host", [u.hostname])[0]}
        }
    elif net_type == "grpc":
        node["transport"] = {
            "type": "grpc",
            "service_name": q.get("serviceName", [""])[0]
        }

    # Reality 支持 (关键优化)
    if q.get("security", [""])[0] == "reality":
        node["tls"]["reality"] = {
            "enabled": True,
            "public_key": q.get("pbk", [""])[0],
            "short_id": q.get("sid", [""])[0]
        }
        # Reality通常不需要 server_name，指纹推荐 chrome
        node["tls"]["utls"]["fingerprint"] = "chrome"
    
    return node

def parse_hysteria2(u, q, tag):
    node = {
        "type": "hysteria2",
        "tag": tag,
        "server": u.hostname,
        "server_port": u.port or 443,
        "password": u.username,
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", [u.hostname])[0],
            "insecure": q.get("insecure", ["0"])[0] == "1",
            "alpn": ["h3"]
        }
    }
    # 混淆支持 (Obfs)
    if "obfs" in q:
        node["obfs"] = {
            "type": "salamander",
            "password": q.get("obfs-password", [""])[0]
        }
    return node

def parse_trojan(u, q, tag):
    node = {
        "type": "trojan",
        "tag": tag,
        "server": u.hostname,
        "server_port": u.port or 443,
        "password": u.username,
        "tls": {
            "enabled": True,
            "server_name": q.get("sni", [u.hostname])[0],
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
    }
    return node

# ===================== 主程序 =====================
def main():
    print("🚀 启动 Sing-box 终极配置生成器...")
    
    # 1. 获取订阅
    all_links = []
    print(f"📥 正在从 {len(SOURCES)} 个源获取订阅...")
    for src in SOURCES:
        try:
            r = requests.get(src, timeout=6)
            if r.status_code == 200:
                content = safe_decode(r.text) if "://" not in r.text[:50] else r.text
                found = re.findall(r"(vless|trojan|hysteria2|hy2)://[^\s#\r\n]+", content)
                all_links.extend(found)
                print(f"  - {src}: 获取到 {len(found)} 个节点")
        except Exception as e:
            print(f"  ⚠️ 获取失败 {src}: {e}")

    unique_links = list(set(all_links))
    if not unique_links:
        print("❌ 未找到任何有效节点，请检查网络或订阅源。")
        return

    print(f"⚡ 开始并发测速 {len(unique_links)} 个节点 (超时 {CONNECT_TIMEOUT}s)...")
    
    # 2. 并发测速
    valid_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_node, link): link for link in unique_links}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                valid_nodes.append(res)
    
    # 3. 按延迟排序
    valid_nodes.sort(key=lambda x: x['latency'])
    valid_nodes = valid_nodes[:MAX_KEEP_NODES]
    print(f"✅ 筛选出 {len(valid_nodes)} 个优质节点，最低延迟: {valid_nodes[0]['latency']}ms")

    # 4. 生成配置结构
    cfg = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://8.8.8.8/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                {"rule_set": "geosite_cn", "server": "dns_local"},
                {"rule_set": ["adblock", "geosite_ads"], "server": "dns_block"}
            ],
            "final": "dns_proxy"
        },
        "inbounds": [{
            "type": "tun", 
            "inet4_address": "172.19.0.1/30", 
            "auto_route": True, 
            "strict_route": True, 
            "sniff": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"ip_is_private": True, "outbound": "direct"},
                {"rule_set": ["geoip_cn", "geosite_cn"], "outbound": "direct"},
                {"rule_set": ["adblock", "geosite_ads"], "action": "reject"}
            ],
            "final": "proxy",
            "rule_set": [
                {"tag": k, "type": "remote", "format": "binary", "url": f"{RULE_CDN}/{v}"} 
                for k, v in RULE_PATHS.items()
            ]
        }
    }

    # 5. 节点转换
    for i, item in enumerate(valid_nodes):
        u = item['u']
        q = parse_qs(u.query)
        tag = f"{u.hostname[:15]}.. [{item['latency']}ms] {i+1}" # 简洁标签
        
        try:
            node = None
            if u.scheme == "vless":
                node = parse_vless(u, q, tag)
            elif u.scheme in ["hysteria2", "hy2"]:
                node = parse_hysteria2(u, q, tag)
            elif u.scheme == "trojan":
                node = parse_trojan(u, q, tag)
            
            if node:
                cfg["outbounds"].append(node)
                cfg["outbounds"][1]["outbounds"].append(tag) # 加到 auto 组
                cfg["outbounds"][0]["outbounds"].append(tag) # 加到 proxy 手选组
        except Exception as e:
            # 忽略解析错误的节点
            continue

    # 6. 保存文件
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"💾 配置文件 config.json 生成成功！包含 {len(cfg['outbounds'])-4} 个节点。")

if __name__ == "__main__":
    main()
