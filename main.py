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

CDN_HOST = "gh-proxy.com"  # 用于加速 GitHub Raw
GH_RAW_BASE = "https://raw.githubusercontent.com"
RULE_CDN_PREFIX = f"https://{CDN_HOST}/{GH_RAW_BASE}"

RULE_PATHS = {
    "geosite-category-ads-all": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite-cn": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip-cn": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 100
MAX_KEEP_NODES = 100
TIMEOUT = 5.0
ALIDNS = "223.5.5.5"  # 阿里 DNS (Do53)

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

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15)
        text = resp.text.strip()
        if "://" not in text[:30]:
            try:
                missing_padding = len(text) % 4
                if missing_padding:
                    text += '=' * (4 - missing_padding)
                return base64.b64decode(text).decode('utf-8', 'ignore')
            except:
                return text
        return text
    except Exception as e:
        print(f"⚠️ 获取 {url} 失败: {str(e)[:50]}")
        return ""

def get_tls_config(u, q):
    raw_sni = q.get("sni", [None])[0] or q.get("host", [None])[0] or u.hostname
    final_sni = unquote(str(raw_sni)).split("/")[0].split(":")[0].strip()
    return {
        "enabled": True,
        "server_name": final_sni,
        "insecure": True,
        "utls": {"enabled": True, "fingerprint": "chrome"}
    }

def check_node(link):
    try:
        u = urlparse(link)
        if not u.hostname or not u.username:
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

# ===================== 主构建程序 =====================

def main():
    print(f"🚀 正在处理节点并构建稳定配置...")
    all_text = "\n".join([get_content(s) for s in SOURCES])
    links = list(set(re.findall(r'((?:vless|trojan)://[^\s#]+)', all_text)))
    
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

    tested_nodes.sort(key=lambda x: x['latency'])
    top_nodes = tested_nodes[:MAX_KEEP_NODES]

    # 构建 Sing-box 配置
    cfg = {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": ALIDNS, "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                # ✅ 关键修复1: CDN 域名强制直连 DNS
                {"domain": [CDN_HOST], "server": "dns_local"},
                {"rule_set": "geosite-category-ads-all", "server": "dns_block"},
                {"rule_set": "geosite-cn", "server": "dns_local"}
            ],
            "final": "dns_proxy",
            "strategy": "ipv4_only"
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "inet4_address": "172.19.0.1/30",
            "mtu": 1400,
            "auto_route": True,
            "strict_route": True,
            "stack": "system",
            "sniff": True,
            "sniff_override_destination": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {
                "type": "urltest",
                "tag": "auto-test",
                "outbounds": [],
                "url": "http://cp.cloudflare.com/generate_204",
                "interval": "3m",
                "tolerance": 50
            },
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "rule_set": [
                {
                    "type": "remote",
                    "tag": k,
                    "format": "binary",
                    "url": f"{RULE_CDN_PREFIX}/{v}",
                    "download_detour": "direct"  # 规则下载走 direct
                } for k, v in RULE_PATHS.items()
            ],
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                # ✅ 关键修复2: CDN 域名流量也直连
                {"domain": [CDN_HOST], "outbound": "direct"},
                {"rule_set": "geosite-category-ads-all", "outbound": "block"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True
        }
    }

    # 填充有效节点
    valid_count = 0
    for i, item in enumerate(top_nodes):
        u, q = item['u'], parse_qs(item['u'].query)
        country = get_ip_country(u.hostname)
        tag = f"{country} {unquote(u.fragment or f'Node-{i+1}')} | {item['latency']}ms"
        
        if u.scheme == "vless":
            if not u.username:
                continue
            node = {
                "type": "vless",
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port or 443),
                "uuid": u.username,
                "packet_encoding": "xudp",
                "tls": get_tls_config(u, q)
            }
            flow_val = q.get("flow", [""])[0]
            if "vision" in flow_val:
                node["flow"] = "xtls-rprx-vision"
                
        elif u.scheme == "trojan":
            if not u.username:
                continue
            node = {
                "type": "trojan",
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port or 443),
                "password": u.username,
                "tls": get_tls_config(u, q)
            }
        else:
            continue

        # Reality 支持
        if q.get("security", [""])[0] == "reality":
            pbk = q.get("pbk", [""])[0]
            if not pbk:
                continue
            node["tls"]["reality"] = {
                "enabled": True,
                "public_key": pbk,
                "short_id": q.get("sid", [""])[0]
            }
            if q.get("spx"):
                node["tls"]["reality"]["spider_x"] = q.get("spx")[0]

        cfg["outbounds"].append(node)
        cfg["outbounds"][0]["outbounds"].append(tag)
        cfg["outbounds"][1]["outbounds"].append(tag)
        valid_count += 1

    # 保存配置
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"🎉 成功! config.json 已生成，包含 {valid_count} 个有效节点。")
    print("💡 启动命令: sing-box run -c config.json")

if __name__ == "__main__":
    main()
