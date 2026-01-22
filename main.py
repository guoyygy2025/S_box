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
MAX_KEEP_NODES = 100  # 保留前 100 个最快节点
TIMEOUT = 4.0
ALIDNS = "223.5.5.5"

dns_cache = {}

# ===================== 工具函数 =====================

def resolve_hostname(hostname):
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
        return f"[{resp.get('countryCode', 'UN')}]" if resp.get("status") == "success" else "[UN]"
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
    except Exception as e:
        print(f"⚠️ 获取 {url} 失败: {str(e)[:50]}")
        return ""

def is_valid_sni(s):
    """校验是否为合法 SNI（域名格式）"""
    if not s or len(s) > 253 or "." not in s:
        return False
    if any(c in s for c in " @#{}[]<>|\\?/"):
        return False
    parts = s.split(".")
    for part in parts:
        if not part or len(part) > 63 or part.startswith("-") or part.endswith("-"):
            return False
        if not all(c.isalnum() or c == "-" for c in part):
            return False
    return True

def get_tls_config(u, q):
    # 优先级: sni > host > u.hostname
    raw_sni = q.get("sni", [None])[0] or q.get("host", [None])[0] or u.hostname
    if not raw_sni:
        raw_sni = u.hostname

    # URL 解码
    decoded = unquote(str(raw_sni)).strip()

    # 清洗：移除路径、端口、查询、片段
    clean_sni = decoded.split("/")[0].split(":")[0].split("?")[0].split("#")[0].strip()

    # 校验并 fallback
    final_sni = clean_sni if is_valid_sni(clean_sni) else u.hostname

    return {
        "enabled": True,
        "server_name": final_sni,
        "insecure": True,
        "utls": {"enabled": True, "fingerprint": "chrome"}
    }

def check_node(link):
    if not link.startswith(("vless://", "trojan://")):
        return None
    try:
        u = urlparse(link)
        if not u.hostname or not u.username or ":" in u.hostname:
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
    except:
        return None

# ===================== 节点解析逻辑 =====================

def parse_vless(u, q, tag):
    # 跳过无 UUID 的 VLESS
    if not u.username:
        return None

    node = {
        "type": "vless",
        "tag": tag,
        "server": u.hostname,
        "server_port": int(u.port or 443),
        "uuid": u.username,
        "packet_encoding": "xudp",
        "tls": get_tls_config(u, q)
    }

    # REALITY 支持
    if q.get("security", [""])[0] == "reality":
        pbk = q.get("pbk", [""])[0]
        if not pbk:  # 公钥为空则跳过
            return None
        reality_cfg = {
            "enabled": True,
            "public_key": pbk,
            "short_id": q.get("sid", [""])[0]
        }
        if q.get("spx"):
            reality_cfg["spider_x"] = q.get("spx")[0]
        node["tls"]["reality"] = reality_cfg

    if "vision" in q.get("flow", [""])[0]:
        node["flow"] = "xtls-rprx-vision"
    return node

def parse_trojan(u, q, tag):
    if not u.username:  # 跳过空密码
        return None
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
    print(f"🚀 开始处理节点 (适配 sing-box 1.12.x，保留前 {MAX_KEEP_NODES} 个最快节点)...")

    # 1. 下载并合并所有源
    all_text = ""
    for s in SOURCES:
        content = get_content(s)
        all_text += content + "\n"

    # 2. 提取并去重节点链接
    links = list(set(re.findall(r'((?:vless|trojan)://[^\s#]+)', all_text)))
    print(f"🔍 发现 {len(links)} 个潜在节点，开始并发测速...")

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
        print("❌ 未发现任何可用节点，请检查网络或订阅源。")
        return

    # 4. 按延迟排序，取前 N 个
    tested_nodes.sort(key=lambda x: x['latency'])
    top_nodes = tested_nodes[:MAX_KEEP_NODES]
    print(f"✅ 测速完成: {len(tested_nodes)} 个可用，保留最快的 {len(top_nodes)} 个。")

    # 5. 构建 sing-box 配置
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
            "final": "dns_proxy",
            "strategy": "ipv4_only"
        },
        "inbounds": [{
            "type": "tun",
            "inet4_address": "172.19.0.1/30",
            "mtu": 1400,
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
                "url": "http://cp.cloudflare.com/generate_204",
                "interval": "3m0s"
            },
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
                {
                    "tag": k,
                    "type": "remote",
                    "format": "binary",
                    "url": f"{RULE_CDN_PREFIX}/{v}",
                    "download_detour": "direct"
                } for k, v in RULE_PATHS.items()
            ],
            "final": "proxy"
        }
    }

    # 6. 填充节点到配置
    valid_nodes = 0
    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        country = get_ip_country(u.hostname)
        node_name = (unquote(u.fragment).strip() if u.fragment else "") or f"Node-{i+1}"
        tag = f"{country} {node_name} | {item['latency']}ms"

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
            valid_nodes += 1

    # 7. 保存配置
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

    print(f"🎉 成功! 写入 {valid_nodes} 个有效节点到 config.json")

if __name__ == "__main__":
    main()
