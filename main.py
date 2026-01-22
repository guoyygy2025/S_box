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

# 规则集配置
RULE_CDN_DOMAIN = "gh-proxy.com"
RULE_CDN = f"https://{RULE_CDN_DOMAIN}/https://raw.githubusercontent.com"
RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs",
    "privacy": "SagerNet/sing-geosite/rule-set/geosite-privacy.srs"
}

MAX_THREADS = 50          
MAX_KEEP_NODES = 50       
LATENCY_THRESHOLD = 500   
SAMPLE_COUNT = 3          
TEST_URL = "http://cp.cloudflare.com/generate_204"

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

def is_suspicious(u, link):
    """清理可疑节点逻辑"""
    host = u.hostname.lower() if u.hostname else ""
    # 1. 过滤本地/无效IP
    if host in ["127.0.0.1", "localhost", "0.0.0.0", "::1"]: return True
    # 2. 过滤明显的特征字符或非法节点
    if "private" in link.lower() or len(host) < 3: return True
    # 3. 过滤纯数字主机名（通常是未配置好的临时节点）
    if host.replace('.', '').isdigit(): return True
    return False

def extract_links(content):
    links = []
    for line in content.splitlines():
        match = re.search(r'(vless|trojan|hysteria2|hy2)://[^\s#]+', line.strip())
        if match:
            link = match.group(0)
            u = urlparse(link)
            if not is_suspicious(u, link):
                links.append(link)
    return list(set(links))

def check_node_stability(link):
    try:
        u = urlparse(link)
        latencies = []
        for _ in range(SAMPLE_COUNT):
            start = time.time()
            with socket.create_connection((u.hostname, u.port or 443), timeout=1.2) as s:
                latencies.append(int((time.time() - start) * 1000))
        avg_latency = sum(latencies) // len(latencies)
        if avg_latency < LATENCY_THRESHOLD:
            return {"link": link, "u": u, "latency": avg_latency}
    except: pass
    return None

# ===================== 解析逻辑 (SNI 小写化) =====================
def parse_vless(u, q, tag):
    sni = q.get("sni", [u.hostname])[0].lower() # 🟢 统一小写
    raw_flow = q.get("flow", [""])[0]
    clean_flow = "xtls-rprx-vision" if "xtls-rprx-vision" in raw_flow else ""
    node = {
        "type": "vless", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "uuid": u.username, "flow": clean_flow, "packet_encoding": "xudp",
        "tls": {"enabled": True, "server_name": sni, "utls": {"enabled": True, "fingerprint": "chrome"}}
    }
    if q.get("security", [""])[0] == "reality":
        node["tls"]["reality"] = {"enabled": True, "public_key": q.get("pbk",
