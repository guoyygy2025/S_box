import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import hashlib
from urllib.parse import urlparse, parse_qs, unquote

# ===================== 订阅源 =====================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

# ✅ 使用 gh-proxy.com 加速 GitHub Raw
GH_RAW_BASE = "https://raw.githubusercontent.com"
CDN_HOST = "gh-proxy.com"
RULE_URLS = {
    "geosite-cn": f"https://{CDN_HOST}/{GH_RAW_BASE}/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "category-ads-all": f"https://{CDN_HOST}/{GH_RAW_BASE}/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs"
}

MAX_THREADS = 100
MAX_KEEP_NODES = 100
TIMEOUT = 5.0
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

# ===================== 主程序 =====================

def main():
    print("🚀 正在处理节点并构建使用 gh-proxy.com 的配置...")
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

    # 构建配置
    cfg = {
        "log": {"disabled": False, "level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
                {"tag": "local", "address": ALIDNS},  # ⚠️ 无 detour！关键！
                {"tag": "block", "address": "rcode://success"}
            ],
            "rules": [
                # ✅ 关键：gh-proxy.com 强制走 local DNS（防环路）
                {"domain": [CDN_HOST], "server": "local"},
                {"clash_mode": "Proxy", "server": "remote"},
                {"clash_mode": "Direct", "server": "local"},
                {"rule_set": ["geosite-cn"], "server": "local"},
                {"rule_set": ["category-ads-all"], "server": "block"}
            ],
            "strategy": "ipv4_only"
        },
        "inbounds": [
            {
                "type": "tun",
                "inet4_address": "172.18.0.1/30",
                "inet6_address": "fdfe:dcba:9876::1/126",
                "auto_route": True,
                "strict_route": True,
                "stack": "system",
                "sniff": True,
                "sniff_override_destination": True
            },
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2333
            }
        ],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto", "direct"]},
            {"type": "urltest", "tag": "auto", "outbounds": [], "url": "http://cp.cloudflare.com/generate_204", "interval": "3m"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
            {"type": "dns", "tag": "dns-out"}
        ],
        "route": {
            "default_domain_resolver": "local",
            "auto_detect_interface": True,
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                # ✅ 关键：gh-proxy.com 流量强制直连
                {"domain": [CDN_HOST], "outbound": "direct"},
                {"clash_mode": "Direct", "outbound": "direct"},
                {"clash_mode": "Proxy", "outbound": "proxy"},
                {"rule_set": ["geosite-cn"], "outbound": "direct"},
                {"ip_is_private": True, "outbound": "direct"},
                {"rule_set": ["category-ads-all"], "outbound": "block"}
            ],
            "rule_set": [
                {
                    "tag": "geosite-cn",
                    "type": "remote",
                    "format": "binary",
                    "url": RULE_URLS["geosite-cn"],
                    "download_detour": "direct"
                },
                {
                    "tag": "category-ads-all",
                    "type": "remote",
                    "format": "binary",
                    "url": RULE_URLS["category-ads-all"],
                    "download_detour": "direct"
                }
            ]
        }
    }

    # 填充节点
    valid_count = 0
    node_tags = []
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
        node_tags.append(tag)
        valid_count += 1

    cfg["outbounds"][0]["outbounds"] = ["auto", "direct"] + node_tags
    cfg["outbounds"][1]["outbounds"] = node_tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"🎉 成功! config.json 已生成，包含 {valid_count} 个有效节点。")
    print(f"🔗 规则通过 {CDN_HOST} 下载，已防环路。")
    print("💡 启动命令: sing-box run -c config.json")

if __name__ == "__main__":
    main()
