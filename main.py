import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import hashlib
from urllib.parse import urlparse, parse_qs, unquote

# ===================== 核心配置 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", 
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

CDN_HOST = "gh-proxy.com" 
GH_RAW_BASE = "https://raw.githubusercontent.com"
RULE_CDN_PREFIX = f"https://{CDN_HOST}/{GH_RAW_BASE}"

RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 100 
MAX_KEEP_NODES = 100 # 修改为保留100个
TIMEOUT = 4.0 
ALIDNS = "223.5.5.5"

dns_cache = {}

# ===================== 工具函数 =====================

def resolve_hostname(hostname):
    if hostname in dns_cache: return dns_cache[hostname]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname): return hostname
    try:
        ip = socket.gethostbyname(hostname)
        dns_cache[hostname] = ip
        return ip
    except: return None

def get_ip_country(hostname):
    try:
        ip = resolve_hostname(hostname)
        if not ip: return "[UN]"
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        return f"[{resp.get('countryCode')}]" if resp.get("status") == "success" else "[UN]"
    except: return "[UN]"

def decode_base64(data):
    try:
        missing_padding = len(data) % 4
        if missing_padding: data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', 'ignore')
    except: return data

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        text = resp.text.strip()
        if "://" not in text[:30]: return decode_base64(text)
        return text
    except: return ""

def check_node(link):
    try:
        u = urlparse(link)
        if not u.hostname or ":" in u.hostname: return None 
        ip = resolve_hostname(u.hostname)
        if not ip: return None

        start = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, u.port or 443))
            latency = int((time.time() - start) * 1000)
        
        # 节点唯一指纹去重（协议+地址+端口+UUID/密码）
        fp = hashlib.md5(f"{u.scheme}{u.hostname}{u.port}{u.username}".encode()).hexdigest()
        return {"link": link, "u": u, "latency": latency, "fp": fp}
    except: return None

# ===================== 解析逻辑 (保留原始 SNI) =====================

def get_tls_config(u, q):
    # 核心：保留原始 SNI，不进行过滤截断
    raw_sni = q.get("sni", [None])[0] or q.get("host", [None])[0] or u.hostname
    final_sni = unquote(raw_sni).strip()

    return {
        "enabled": True,
        "server_name": final_sni,
        "insecure": True, # 提高公共节点兼容性
        "utls": {"enabled": True, "fingerprint": "chrome"}
    }

def parse_vless(u, q, tag):
    node = {
        "type": "vless", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "uuid": u.username, "packet_encoding": "xudp", "tls": get_tls_config(u, q)
    }
    # Reality 协议支持
    if q.get("security", [""])[0] == "reality":
        reality_cfg = {
            "enabled": True,
            "public_key": q.get("pbk", [""])[0],
            "short_id": q.get("sid", [""])[0]
        }
        if q.get("spx"): reality_cfg["spider_x"] = q.get("spx")[0]
        node["tls"]["reality"] = reality_cfg
    
    if "vision" in q.get("flow", [""])[0]:
        node["flow"] = "xtls-rprx-vision"
    return node

def parse_trojan(u, q, tag):
    return {
        "type": "trojan", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "password": u.username, "tls": get_tls_config(u, q)
    }

# ===================== 主程序 =====================
def main():
    print(f"🚀 开始处理节点 (适配 sing-box 1.12.x)...")
    
    # 1. 下载并初步合并所有源
    all_text = ""
    for s in SOURCES:
        content = get_content(s)
        all_text += content + "\n"
    
    # 2. 提取并去重
    links = list(set(re.findall(r'((?:vless|trojan)://[^\s#]+)', all_text)))
    print(f"🔍 发现 {len(links)} 个节点，正在进行并发连通性测试...")
    
    # 3. 并发测速
    tested_nodes = []
    seen_fps = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node, links))
        for res in results:
            if res and res["fp"] not in seen_fps:
                tested_nodes.append(res)
                seen_fps.add(res["fp"])

    if not tested_nodes:
        print("❌ 未发现可用节点，请检查源或网络。")
        return

    # 4. 按延迟排序并取前 100 个
    tested_nodes.sort(key=lambda x: x['latency'])
    top_nodes = tested_nodes[:MAX_KEEP_NODES]
    print(f"✅ 测速通过: {len(tested_nodes)} 个，保留最快的前 {len(top_nodes)} 个节点。")

    # 5. 构建 sing-box config.json 结构
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": ALIDNS, "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                {"rule_set": "ads", "server": "dns_block"},
                {"domain": [CDN_HOST], "server": "dns_local"},
                {"rule_set": "cn_site", "server": "dns_local"}
            ],
            "final": "dns_proxy", "strategy": "ipv4_only"
        },
        "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "mtu": 1400, "auto_route": True, "strict_route": True, "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "http://cp.cloudflare.com/generate_204", "interval": "3m0s"},
            {"type": "direct", "tag": "direct"}, 
            {"type": "dns", "tag": "dns-out"}, 
            {"type": "block", "tag": "dns_block"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"rule_set": "ads", "outbound": "dns_block"},
                {"domain": [CDN_HOST], "outbound": "direct"},
                {"rule_set": ["cn_site", "cn_ip"], "outbound": "direct"}
            ],
            "rule_set": [
                {"tag": k, "type": "remote", "format": "binary", "url": f"{RULE_CDN_PREFIX}/{v}", "download_detour": "direct"} 
                for k, v in RULE_PATHS.items()
            ],
            "final": "proxy"
        }
    }

    # 6. 将节点填入出站列表
    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        country = get_ip_country(u.hostname)
        node_name = unquote(u.fragment).strip() if u.fragment else f"Node-{i+1}"
        tag = f"{country} {node_name} | {item['latency']}ms"
        
        node = parse_vless(u, q, tag) if u.scheme == "vless" else parse_trojan(u, q, tag)
        if node:
            cfg["outbounds"].append(node)
            cfg["outbounds"][0]["outbounds"].append(tag) # 添加到 proxy 选择器
            cfg["outbounds"][1]["outbounds"].append(tag) # 添加到 auto-test 组

    # 7. 保存文件
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"🎉 成功! 已将 100 个节点写入 config.json")

if __name__ == "__main__":
    main()
