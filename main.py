import requests
import base64
import socket
import concurrent.futures
import json
import time
import re
import sys
from urllib.parse import urlparse, parse_qs, unquote

# 强制刷新输出
def log(msg):
    print(msg, flush=True)

# --- 配置区 ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", 
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

MAX_KEEP_NODES = 100 
TIMEOUT = 0.2       

def get_modern_template():
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_fakeip", "address": "fakeip"},
                {"tag": "dns_proxy", "address": "https://223.5.5.5/dns-query", "detour": "proxy"},
                {"tag": "dns_direct", "address": "https://223.6.6.6/dns-query", "detour": "direct"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"}
            ],
            "rules": [
                {"rule_set": "geosite-cn", "server": "dns_direct"},
                {"query_type": ["A", "AAAA"], "server": "dns_fakeip"}
            ],
            "final": "dns_direct",
            "strategy": "prefer_ipv4",
            "fakeip": {"enabled": True, "inet4_range": "198.18.0.0/15"}
        },
        "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30"], "auto_route": True, "strict_route": True, "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://223.5.5.5/dns-query", "interval": "10m"},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {"rules": [{"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}], "final": "proxy"}
    }

def resolve_with_1111(domain):
    if not domain or re.match(r"^\d", domain): return domain
    try:
        r = requests.get(f"https://1.1.1.1/dns-query?name={domain}&type=A", headers={"accept": "application/dns-json"}, timeout=5)
        ans = r.json().get("Answer", [])
        return ans[0]["data"] if ans else None
    except: return None

def check_conn(info):
    link, ip, port = info
    try:
        s = time.time()
        socket.create_connection((ip, int(port)), timeout=TIMEOUT).close()
        return (link, ip, time.time() - s)
    except: return None

def main():
    log("开始运行脚本...")
    links = []
    for s in SOURCES:
        try:
            log(f"正在抓取: {s[:30]}...")
            r = requests.get(s, timeout=10)
            txt = r.text
            if "://" not in txt:
                txt = base64.b64decode(txt + "==").decode('utf-8', 'ignore')
            found = re.findall(r"(?:vless|trojan|hysteria2|hy2)://[^\s]+", txt)
            links.extend(found)
        except Exception as e: log(f"抓取失败: {e}")

    unique = list(set(links))
    log(f"去重后节点数: {len(unique)}")

    log("开始解析 IP (使用 1.1.1.1)...")
    to_test = []
    for l in unique:
        try:
            u = urlparse(l)
            ip = resolve_with_1111(u.hostname)
            if ip: to_test.append((l, ip, u.port or 443))
        except: pass
    
    log(f"解析成功: {len(to_test)}")
    if not to_test: return

    log("开始测速 (阿里 223.5.5.5)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        r1 = [res for res in ex.map(check_conn, to_test) if res]
    
    r1.sort(key=lambda x: x[2])
    # 进行三次测速筛选
    final_nodes = r1[:MAX_KEEP_NODES]
    log(f"测速完成，保留节点: {len(final_nodes)}")

    outbounds, tags = [], []
    for link, ip, lat in final_nodes:
        try:
            u = urlparse(link)
            q = parse_qs(u.query)
            ms = int(lat * 1000)
            tag = f"{unquote(u.fragment)[:5] or 'Node'}|{ms}ms"
            while tag in tags: tag += "_"
            tags.append(tag)
            
            node = {
                "type": "hysteria2" if u.scheme in ["hy2", "hysteria2"] else u.scheme,
                "tag": tag, "server": ip, "server_port": int(u.port or 443),
                "password" if u.scheme != "vless" else "uuid": u.username
            }
            if "tls" in link or "reality" in str(q) or u.scheme == "hysteria2":
                node["tls"] = {"enabled": True, "server_name": q.get('sni', [u.hostname])[0]}
            outbounds.append(node)
        except: continue

    conf = get_modern_template()
    conf["outbounds"].extend(outbounds)
    conf["outbounds"][0]["outbounds"].extend(tags)
    conf["outbounds"][1]["outbounds"] = tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(conf, f, indent=2, ensure_ascii=False)
    log("✅ 成功生成 config.json")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"程序运行崩溃: {str(e)}")
