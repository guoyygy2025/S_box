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

RULE_CDN = "https://gh-proxy.com/https://raw.githubusercontent.com"
RULE_PATHS = {
    "adblock": "217heidai/adblockfilters/main/rules/adblocksingbox.srs",
    "geosite_ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite_cn": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip_cn": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

# ⚡ 参数微调：云端运行建议稍微放宽超时
MAX_THREADS = 40        
MAX_KEEP_NODES = 80     
CONNECT_TIMEOUT = 1.0   

# ===================== 核心工具 =====================
def get_content(url):
    """下载并智能解码内容"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.encoding = 'utf-8'
        text = resp.text.strip()
        
        # 1. 如果内容包含明显的协议头，说明是明文，不需要解码
        if "vless://" in text or "vmess://" in text or "trojan://" in text:
            return text
            
        # 2. 尝试 Base64 解码
        try:
            # 处理 URL Safe Base64
            text_safe = text.replace('-', '+').replace('_', '/')
            # 补全 padding
            padding = len(text_safe) % 4
            if padding:
                text_safe += '=' * (4 - padding)
            decoded = base64.b64decode(text_safe).decode('utf-8', 'ignore')
            # 只有当解码后包含协议头时，才认为解码成功
            if "://" in decoded:
                return decoded
        except:
            pass
            
        # 3. 如果解码失败，返回原始文本（可能是混杂模式）
        return text
    except Exception as e:
        print(f"⚠️ 下载失败 {url}: {e}")
        return ""

def extract_links(content):
    """稳健的链接提取：按行处理 + 正则补充"""
    links = []
    lines = content.splitlines()
    
    # 策略 A: 按行扫描 (最稳健)
    for line in lines:
        line = line.strip()
        if not line: continue
        # 提取协议开头的字符串
        match = re.search(r'(vless|trojan|hysteria2|hy2)://.*', line)
        if match:
            # 去掉末尾可能的注释（从空格或#开始截断）
            clean_link = re.split(r'[\s|#]', match.group(0))[0]
            links.append(clean_link)

    # 策略 B: 只有当按行没找到时，尝试全文正则 (应对挤在一起的情况)
    if not links:
        found = re.findall(r"(vless|trojan|hysteria2|hy2)://[a-zA-Z0-9%\-\._~:/?#\[\]@!$&'()*+,;=]+", content)
        links.extend(found)
        
    return links

def check_node(link):
    """TCP 握手测速"""
    try:
        u = urlparse(link)
        host = u.hostname
        port = u.port or 443
        if not host: return None
        # 过滤本地回环
        if "127.0.0.1" in host or "localhost" in host: return None

        start_time = time.time()
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            latency = int((time.time() - start_time) * 1000)
            return {"link": link, "u": u, "latency": latency}
    except:
        return None

# ===================== 解析器 =====================
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
    if q.get("type", ["tcp"])[0] == "ws":
        node["transport"] = {"type": "ws", "path": q.get("path", ["/"])[0], "headers": {"Host": q.get("host", [u.hostname])[0]}}
    elif q.get("type", ["tcp"])[0] == "grpc":
        node["transport"] = {"type": "grpc", "service_name": q.get("serviceName", [""])[0]}
    return node

def parse_hysteria2(u, q, tag):
    node = {
        "type": "hysteria2", "tag": tag, "server": u.hostname, "server_port": u.port or 443,
        "password": u.username,
        "tls": {"enabled": True, "server_name": q.get("sni", [u.hostname])[0], "insecure": q.get("insecure", ["0"])[0] == "1", "alpn": ["h3"]}
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
    print("🚀 启动 Sing-box 配置生成器 (V3.0 修复版)...")
    
    # 1. 获取并提取链接
    all_links = []
    for src in SOURCES:
        content = get_content(src)
        links = extract_links(content)
        if links:
            all_links.extend(links)
            print(f"✅ {src} -> 提取到 {len(links)} 个链接")
        else:
            print(f"❌ {src} -> 未提取到链接 (可能格式不支持)")

    unique_links = list(set(all_links))
    total_count = len(unique_links)
    if total_count == 0:
        print("🛑 致命错误：未找到任何有效链接，请检查网络或源地址。")
        return

    print(f"⚡ 开始测速 {total_count} 个唯一节点 (超时 {CONNECT_TIMEOUT}s)...")
    
    # 2. 并发测速
    valid_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(check_node, link): link for link in unique_links}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res: valid_nodes.append(res)
    
    # 3. 结果处理（兜底逻辑）
    if not valid_nodes:
        print("⚠️ 警告：所有节点测速均失败！可能是网络环境限制。")
        print("🛡️ 启用【强制保留模式】：不进行连通性检查，保留所有格式正确的节点。")
        for link in unique_links[:MAX_KEEP_NODES]:
            try:
                u = urlparse(link)
                if u.hostname:
                    valid_nodes.append({"link": link, "u": u, "latency": 9999})
            except: pass
    else:
        valid_nodes.sort(key=lambda x: x['latency'])
        print(f"✅ 测速完成，有效节点: {len(valid_nodes)} 个")

    if not valid_nodes:
        print("🛑 最终失败：没有可生成的节点。")
        return

    # 4. 生成配置
    final_nodes = valid_nodes[:MAX_KEEP_NODES]
    cfg = {
        "log": {"level": "info"},
        "dns": {
            "servers": [{"tag": "dns_proxy", "address": "8.8.8.8", "detour": "proxy"}, {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"}],
            "rules": [{"rule_set": "geosite_cn", "server": "dns_local"}],
            "final": "dns_proxy"
        },
        "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": True, "strict_route": True, "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "http://cp.cloudflare.com", "interval": "10m", "tolerance": 50},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "rules": [{"protocol": "dns", "outbound": "dns-out"}, {"ip_is_private": True, "outbound": "direct"}, {"rule_set": ["geoip_cn", "geosite_cn"], "outbound": "direct"}],
            "final": "proxy",
            "rule_set": [{"tag": k, "type": "remote", "format": "binary", "url": f"{RULE_CDN}/{v}"} for k, v in RULE_PATHS.items()]
        }
    }

    count = 0
    for i, item in enumerate(final_nodes):
        u = item['u']
        q = parse_qs(u.query)
        # 处理节点命名：解码 URL 编码的备注 (如 #美国)
        try:
            remark = unquote(u.fragment) if u.fragment else f"Node-{i+1}"
        except: remark = f"Node-{i+1}"
        
        tag = f"{remark} [{item['latency']}ms]" if item['latency'] != 9999 else f"{remark} {i+1}"
        
        # 查重 tag，防止重复
        if any(o['tag'] == tag for o in cfg['outbounds']):
            tag = f"{tag}-{i}"

        try:
            node = None
            if u.scheme == "vless": node = parse_vless(u, q, tag)
            elif u.scheme in ["hysteria2", "hy2"]: node = parse_hysteria2(u, q, tag)
            elif u.scheme == "trojan": node = parse_trojan(u, q, tag)
            
            if node:
                cfg["outbounds"].append(node)
                cfg["outbounds"][1]["outbounds"].append(tag)
                cfg["outbounds"][0]["outbounds"].append(tag)
                count += 1
        except Exception as e:
            # print(f"解析节点出错: {e}")
            continue

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"💾 成功生成 config.json，包含 {count} 个节点！")

if __name__ == "__main__":
    main()
