import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
from urllib.parse import urlparse, parse_qs

# ===================== 核心配置 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

RULE_CDN = "https://gh-proxy.com/https://raw.githubusercontent.com"
RULE_PATHS = {
    "adblock": "217heidai/adblockfilters/main/rules/adblocksingbox.srs",
    "geosite_ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite_cn": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip_cn": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 40        
MAX_KEEP_NODES = 50     
CONNECT_TIMEOUT = 3.0   # 🔴 修改：增加超时时间，防止云端运行全军覆没

# ===================== 工具函数 =====================
def safe_decode(text):
    """增强型解码，处理各种奇怪格式"""
    # 移除空白符
    text = text.replace(' ', '').replace('\n', '').replace('\r', '')
    # 补全 padding
    padding = len(text) % 4
    if padding:
        text += '=' * (4 - padding)
    try:
        return base64.b64decode(text).decode("utf-8", "ignore")
    except:
        return text

def check_node(link):
    """TCP 握手测速"""
    try:
        u = urlparse(link)
        host = u.hostname
        port = u.port or 443
        if not host: return None

        # 排除无效 IP
        if host.startswith('127.') or host == 'localhost': return None

        start_time = time.time()
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            latency = int((time.time() - start_time) * 1000)
            return {"link": link, "u": u, "latency": latency}
    except:
        return None

# ===================== 解析逻辑 =====================
def parse_vless(u, q, tag):
    node = {
        "type": "vless", "tag": tag, "server": u.hostname, "server_port": u.port or 443,
        "uuid": u.username, "flow": q.get("flow", [""])[0], "packet_encoding": "xudp",
        "tls": {
            "enabled": True, "server_name": q.get("sni", [u.hostname])[0],
            "insecure": q.get("allowInsecure", ["false"])[0] == "1",
            "utls": {"enabled": True, "fingerprint": "chrome"}
        }
    }
    if q.get("security", [""])[0] == "reality":
        node["tls"]["reality"] = {
            "enabled": True, "public_key": q.get("pbk", [""])[0], "short_id": q.get("sid", [""])[0]
        }
    return node

def parse_hysteria2(u, q, tag):
    node = {
        "type": "hysteria2", "tag": tag, "server": u.hostname, "server_port": u.port or 443,
        "password": u.username,
        "tls": {
            "enabled": True, "server_name": q.get("sni", [u.hostname])[0],
            "insecure": q.get("insecure", ["0"])[0] == "1",
            "alpn": ["h3"]
        }
    }
    if "obfs" in q:
        node["obfs"] = {"type": "salamander", "password": q.get("obfs-password", [""])[0]}
    return node

def parse_trojan(u, q, tag):
    return {
        "type": "trojan", "tag": tag, "server": u.hostname, "server_port": u.port or 443,
        "password": u.username,
        "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}
    }

# ===================== 主程序 =====================
def main():
    print("🚀 启动 Sing-box 配置生成器...")
    
    all_links = []
    for src in SOURCES:
        try:
            print(f"📥 下载: {src}")
            r = requests.get(src, timeout=10)
            if r.status_code == 200:
                # 尝试解码两次，防止二次 base64
                content = safe_decode(r.text)
                if "://" not in content[:100]: content = safe_decode(content)
                
                found = re.findall(r"(vless|trojan|hysteria2|hy2)://[a-zA-Z0-9%\-\._~:/?#\[\]@!$&'()*+,;=]+", content)
                all_links.extend(found)
                print(f"   -> 解析出 {len(found)} 个链接")
        except Exception as e:
            print(f"   -> ⚠️ 失败: {e}")

    unique_links = list(set(all_links))
    if not unique_links:
        print("❌ 未获取到任何节点，终止运行。")
        return

    print(f"⚡ 开始测速 {len(unique_links)} 个节点 (超时 {CONNECT_TIMEOUT}s)...")
    
    valid_nodes = []
    # 使用并发测速
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_node, link): link for link in unique_links}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                valid_nodes.append(res)
    
    # 🔴 关键修复：检查列表是否为空
    if not valid_nodes:
        print("❌ 悲报：所有节点均测速失败（可能网络限制或节点已挂）。")
        print("⚠️ 尝试启用兜底模式：强制保留所有格式正确的节点（不保证连通性）。")
        # 兜底：如果没有通过测速的节点，则不过滤，直接使用所有解析成功的链接
        for link in unique_links[:MAX_KEEP_NODES]:
             # 伪造一个 latency 数据以便通过后续逻辑
             try:
                u = urlparse(link)
                if u.hostname:
                    valid_nodes.append({"link": link, "u": u, "latency": 9999})
             except: pass
        
        if not valid_nodes:
             print("❌ 兜底失败，无有效格式链接。")
             return

    # 按延迟排序
    valid_nodes.sort(key=lambda x: x['latency'])
    print(f"✅ 最终选用 {len(valid_nodes)} 个节点")

    # 生成配置
    cfg = {
        "log": {"level": "info"},
        "dns": {
            "servers": [{"tag": "dns_proxy", "address": "8.8.8.8", "detour": "proxy"}, {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"}],
            "rules": [{"rule_set": "geosite_cn", "server": "dns_local"}],
            "final": "dns_proxy"
        },
        "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": True, "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "http://cp.cloudflare.com", "interval": "10m"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [{"protocol": "dns", "outbound": "dns-out"},{"ip_is_private": True, "outbound": "direct"},{"rule_set": ["geoip_cn", "geosite_cn"], "outbound": "direct"}],
            "final": "proxy",
            "rule_set": [{"tag": k, "type": "remote", "format": "binary", "url": f"{RULE_CDN}/{v}"} for k, v in RULE_PATHS.items()]
        }
    }

    # 填入节点
    for i, item in enumerate(valid_nodes[:MAX_KEEP_NODES]):
        u = item['u']
        q = parse_qs(u.query)
        tag = f"Node-{i+1:02d} {u.scheme.upper()}"
        
        try:
            node = None
            if u.scheme == "vless": node = parse_vless(u, q, tag)
            elif u.scheme in ["hysteria2", "hy2"]: node = parse_hysteria2(u, q, tag)
            elif u.scheme == "trojan": node = parse_trojan(u, q, tag)
            
            if node:
                cfg["outbounds"].append(node)
                cfg["outbounds"][1]["outbounds"].append(tag)
                cfg["outbounds"][0]["outbounds"].append(tag)
        except: continue

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print("💾 config.json 生成完毕")

if __name__ == "__main__":
    main()
