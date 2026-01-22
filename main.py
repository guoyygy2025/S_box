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

CDN_HOST = "gh-proxy.com"  # ✅ 统一使用 .com（更稳定）
GH_RAW_BASE = "https://raw.githubusercontent.com"
RULE_CDN_PREFIX = f"https://{CDN_HOST}/{GH_RAW_BASE}"

RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 100 
MAX_KEEP_NODES = 50
TIMEOUT = 4.0  # Actions环境建议保持 4.0
ALIDNS = "223.5.5.5"

dns_cache = {}

# ===================== 工具函数 =====================

def resolve_hostname(hostname):
    """预解析域名并缓存，避免测速时产生额外的 DNS 耗时"""
    if hostname in dns_cache:
        return dns_cache[hostname]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        return hostname
    try:
        ip = socket.gethostbyname(hostname)
        dns_cache[hostname] = ip
        return ip
    except:
        return None

def get_ip_country(hostname):
    try:
        ip = resolve_hostname(hostname)
        if not ip:
            return "[UN]"
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        return f"[{resp.get('countryCode')}]" if resp.get("status") == "success" else "[UN]"
    except:
        return "[UN]"

def decode_base64(data):
    try:
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', 'ignore')
    except:
        return data

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        text = resp.text.strip()
        if "://" not in text[:30]:
            return decode_base64(text)
        return text
    except:
        return ""

def check_node(link):
    """测速核心逻辑：捕获 ConnectionResetError"""
    try:
        u = urlparse(link)
        if not u.hostname or ":" in u.hostname:
            return None 
        
        ip = resolve_hostname(u.hostname)
        if not ip:
            return None

        start = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((ip, u.port or 443))
            latency = int((time.time() - start) * 1000)
        
        fp = hashlib.md5(f"{u.scheme}{u.hostname}{u.port}{u.username}".encode()).hexdigest()
        return {"link": link, "u": u, "latency": latency, "fp": fp}
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
        return None
    except:
        return None

# ===================== 节点解析逻辑 =====================

def get_tls_config(u, q):
    # 优先从 sni 参数获取，其次 fallback 到 hostname
    sni_candidates = q.get("sni", []) + q.get("host", []) + [u.hostname]
    raw_sni = sni_candidates[0].lower() if sni_candidates else u.hostname

    # URL 解码（处理 %2f 等）
    decoded_sni = unquote(raw_sni)

    # 移除路径、端口、查询参数，只保留主域名
    clean_sni = decoded_sni.split("/")[0].split(":")[0].split("?")[0].strip()

    # 基本校验：必须包含点且不含非法字符
    if not clean_sni or "." not in clean_sni or any(c in clean_sni for c in " @#{}[]<>|\\"):
        clean_sni = u.hostname  # fallback

    return {
        "enabled": True,
        "server_name": clean_sni,
        "insecure": True,
        "utls": {"enabled": True, "fingerprint": "chrome"}
    }

def parse_vless(u, q, tag):
    node = {
        "type": "vless",
        "tag": tag,
        "server": u.hostname,
        "server_port": int(u.port or 443),
        "uuid": u.username,
        "packet_encoding": "xudp",
        "tls": get_tls_config(u, q)
    }
    if q.get("security", [""])[0] == "reality":
        reality_cfg = {
            "enabled": True,
            "public_key": q.get("pbk", [""])[0],
            "short_id": q.get("sid", [""])[0]
        }
        if q.get("spx"):  # ✅ 正确提取 spx
            reality_cfg["spider_x"] = q.get("spx")[0]  # ✅ 字段名是 spider_x
        node["tls"]["reality"] = reality_cfg

    if "vision" in q.get("flow", [""])[0]:
        node["flow"] = "xtls-rprx-vision"
    return node

def parse_trojan(u, q, tag):
    return {
        "type": "trojan",
        "tag": tag,
        "server": u.hostname,
        "server_port": int(u.port or 443),
        "password": u.username,
        "tls": get_tls_config(u, q)
    }

# ===================== 主程序 =====================
def main():
    print(f"🚀 开始更新 sing-box 配置 (阿里DNS: {ALIDNS})")
    
    all_text = ""
    for s in SOURCES:
        all_text += get_content(s) + "\n"
    
    links = list(set(re.findall(r'((?:vless|trojan)://[^\s#]+)', all_text)))
    print(f"解析到 {len(links)} 个潜在 IPv4 节点，开始并发测速...")

    tested_nodes = []
    seen_fps = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node, links))
        for res in results:
            if res and res["fp"] not in seen_fps:
                tested_nodes.append(res)
                seen_fps.add(res["fp"])

    print(f"测试完成，可用节点: {len(tested_nodes)}")

    if not tested_nodes:
        print("❌ 所有节点连接重置或超时，停止更新。")
        return

    # ✅ 可选：过滤弱密码 Trojan 节点
    filtered_nodes = []
    weak_passwords = {"123456", "trojan", "password", ""}
    for item in tested_nodes:
        u = item['u']
        if u.scheme == "trojan":
            pwd = u.username or ""
            if pwd in weak_passwords:
                continue
        filtered_nodes.append(item)
    
    filtered_nodes.sort(key=lambda x: x['latency'])
    top_nodes = filtered_nodes[:MAX_KEEP_NODES]

    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": ALIDNS, "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}  # ✅ 补全 dns_block
            ],
            "rules": [
                {"rule_set": "ads", "server": "dns_block"},  # ✅ 广告拦截
                {"domain": [CDN_HOST], "server": "dns_local"},
                {"rule_set": "cn_site", "server": "dns_local"}
            ],
            "final": "dns_proxy",
            "strategy": "ipv4_only"
        },
        "inbounds": [{
            "type": "tun", 
            "inet4_address": "172.19.0.1/30", 
            "mtu": 1400,  # ✅ 防重置
            "auto_route": True, 
            "strict_route": True, 
            "sniff": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {
                "type": "urltest", 
                "tag": "auto-test", 
                "outbounds": [], 
                "url": "http://cp.cloudflare.com/generate_204",  # ✅ 更健壮的测速地址
                "interval": "3m0s"
            },
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "dns_block"}  # ✅ 补全出站
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"rule_set": "ads", "outbound": "dns_block"},  # ✅ 双重广告拦截
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

    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        country = get_ip_country(u.hostname)
        tag = f"{country} {unquote(u.fragment) or f'Node-{i}'} | {item['latency']}ms"
        if u.scheme == "vless":
            node = parse_vless(u, q, tag)
        elif u.scheme == "trojan":
            node = parse_trojan(u, q, tag)
        else:
            continue
        if node:
            cfg["outbounds"].append(node)
            cfg["outbounds"][0]["outbounds"].append(tag)
            cfg["outbounds"][1]["outbounds"].append(tag)

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"✅ 写入 {len(top_nodes)} 个节点到 config.json")

if __name__ == "__main__":
    main()
