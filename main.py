import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import hashlib
from urllib.parse import urlparse, parse_qs, unquote

# ===================== 配置中心 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

RULE_CDN = "https://gh-proxy.com/https://raw.githubusercontent.com"
RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 50
MAX_KEEP_NODES = 50
SAMPLE_COUNT = 2

# ===================== 核心工具库 =====================
def get_node_fingerprint(u):
    """指纹去重：基于协议、地址、端口、用户ID生成唯一标识"""
    raw_str = f"{u.scheme}|{u.hostname}|{u.port}|{u.username}"
    return hashlib.md5(raw_str.encode()).hexdigest()

def get_ip_country(hostname):
    """查询国家代码 [US], [JP] 等"""
    try:
        # 内部 DNS 预解析
        ip = socket.gethostbyname(hostname)
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        return f"[{resp.get('countryCode')}]" if resp.get("status") == "success" else "[UN]"
    except: return "[UN]"

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        text = resp.text.strip()
        if "://" not in text:
            # 兼容 Base64
            padded = text.replace('-', '+').replace('_', '/') + '=' * (-len(text) % 4)
            return base64.b64decode(padded).decode('utf-8', 'ignore')
        return text
    except: return ""

def check_node_stability(link):
    """稳定性检测：兼容 IPv6 且支持 0 丢包过滤"""
    try:
        u = urlparse(link)
        if not u.hostname: return None
        # IPv6 格式处理
        family = socket.AF_INET6 if ":" in u.hostname and "[" not in u.hostname else socket.AF_INET
        
        latencies = []
        for _ in range(SAMPLE_COUNT):
            start = time.time()
            with socket.socket(family, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                s.connect((u.hostname, u.port or 443))
                latencies.append(int((time.time() - start) * 1000))
        return {"link": link, "u": u, "latency": sum(latencies)//len(latencies), "fp": get_node_fingerprint(u)}
    except: return None

# ===================== 协议解析增强 =====================
def build_tls_obj(u, q):
    """统一处理 TLS, SNI, allowInsecure"""
    sni = q.get("sni", [u.hostname])[0].lower()
    insecure = q.get("allowInsecure", ["0"])[0] == "1" or q.get("insecure", ["0"])[0] == "1"
    return {
        "enabled": True,
        "server_name": sni,
        "insecure": insecure,
        "utls": {"enabled": True, "fingerprint": "chrome"}
    }

def parse_vless(u, q, tag):
    node = {
        "type": "vless", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "uuid": u.username, "packet_encoding": "xudp", "tls": build_tls_obj(u, q)
    }
    # 补全 REALITY 参数
    if q.get("security", [""])[0] == "reality":
        node["tls"]["reality"] = {
            "enabled": True, "public_key": q.get("pbk", [""])[0],
            "short_id": q.get("sid", [""])[0], "spider_x": q.get("spx", ["/"])[0]
        }
    if "vision" in q.get("flow", [""])[0]: node["flow"] = "xtls-rprx-vision"
    return node

def parse_hy2(u, q, tag):
    node = {
        "type": "hysteria2", "tag": tag, "server": u.hostname, "server_port": int(u.port or 443),
        "password": u.username, "tls": build_tls_obj(u, q)
    }
    # 补全 Obfs
    if q.get("obfs"):
        node["obfs"] = {"type": q.get("obfs")[0], "password": q.get("obfs-password", [""])[0]}
    return node

# ===================== 执行流 =====================
def main():
    print("🚀 正在初始化 Sing-box 节点筛选任务...")
    all_links = []
    for s in SOURCES:
        content = get_content(s)
        links = re.findall(r'((?:vless|trojan|hysteria2|hy2)://[^\s#]+)', content)
        all_links.extend(links)

    # 去重测速
    unique_links = list(set(all_links))
    valid_nodes = []
    seen_fps = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node_stability, unique_links))
        for r in results:
            if r and r["fp"] not in seen_fps:
                valid_nodes.append(r)
                seen_fps.add(r["fp"])

    valid_nodes.sort(key=lambda x: x['latency'])
    top_nodes = valid_nodes[:MAX_KEEP_NODES]

    # 构建配置骨架
    cfg = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://8.8.8.8/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"}
            ],
            "final": "dns_proxy"
        },
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"]},
            {"type": "urltest", "tag": "auto", "outbounds": []},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "rule_set": [{"tag": k, "type": "remote", "format": "binary", "url": f"{RULE_CDN}/{v}", "download_detour": "direct"} for k, v in RULE_PATHS.items()],
            "final": "proxy"
        }
    }

    # 填充节点
    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        country = get_ip_country(u.hostname)
        tag = f"{country} {unquote(u.fragment) or f'Node-{i}'} | {item['latency']}ms"
        
        node = None
        if u.scheme == "vless": node = parse_vless(u, q, tag)
        elif u.scheme in ["hy2", "hysteria2"]: node = parse_hy2(u, q, tag)
        elif u.scheme == "trojan": node = {"type":"trojan","tag":tag,"server":u.hostname,"server_port":int(u.port or 443),"password":u.username,"tls":build_tls_obj(u, q)}
        
        if node:
            cfg["outbounds"].append(node)
            cfg["outbounds"][0]["outbounds"].append(tag)
            cfg["outbounds"][1]["outbounds"].append(tag)

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print(f"✅ 任务成功完成！已筛选 {len(top_nodes)} 个唯一且稳定的节点。")

if __name__ == "__main__":
    main()
