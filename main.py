import requests
import base64
import socket
import concurrent.futures
import json
import re
from urllib.parse import urlparse, parse_qs

# ===================== 配置参数 =====================
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

MAX_THREADS = 25
MAX_KEEP_NODES = 50

# ===================== 工具函数 =====================
def safe_decode(text):
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
    except: return text

def check_node(link):
    try:
        u = urlparse(link)
        if not u.hostname: return None
        # Hy2 默认通常也是 443，但 UDP 测试较难通过简单 TCP 握手完全模拟
        # 这里的 RTT 测试主要用于筛选服务器在线状态
        with socket.create_connection((u.hostname, u.port or 443), timeout=1.5):
            return {"link": link, "u": u}
    except: return None

# ===================== 配置生成 =====================
def main():
    print("🚀 启动 Sing-box 配置生成器 (支持 Hy2)...")
    
    all_links = []
    for src in SOURCES:
        try:
            r = requests.get(src, timeout=10).text
            content = safe_decode(r) if "://" not in r[:20] else r
            # 匹配 vless, trojan, hy2
            found = re.findall(r"(vless|trojan|hysteria2|hy2)://[^\s#]+", content)
            all_links.extend(found)
        except: pass

    unique_links = list(set(all_links))
    print(f"找到 {len(unique_links)} 个原始链接，正在筛选有效节点...")

    valid_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(check_node, l) for l in unique_links]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: valid_results.append(res)

    # 基础配置模板
    cfg = {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://8.8.8.8/dns-query"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"}
            ],
            "rules": [{"rule_set": "geosite_cn", "server": "dns_local"}],
            "final": "dns_proxy"
        },
        "inbounds": [{"type": "tun", "inet4_address": "172.19.0.1/30", "auto_route": True, "sniff": True}],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"]},
            {"type": "urltest", "tag": "auto", "outbounds": []},
            {"type": "direct", "tag": "direct"}
        ],
        "route": {
            "rules": [
                {"ip_is_private": True, "outbound": "direct"},
                {"rule_set": ["geoip_cn", "geosite_cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "rule_set": [
                {"tag": k, "type": "remote", "format": "binary", "url": f"{RULE_CDN}/{v}"} 
                for k, v in RULE_PATHS.items()
            ]
        }
    }

    # 解析节点
    for i, res in enumerate(valid_results[:MAX_KEEP_NODES]):
        u = res['u']
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        tag = f"Node-{i:02d}-{u.scheme.upper()}"
        
        node = {
            "tag": tag,
            "server": u.hostname,
            "server_port": u.port or 443
        }

        if u.scheme in ["vless"]:
            node.update({
                "type": "vless", "uuid": u.username, "flow": q.get("flow", ""),
                "tls": {"enabled": True, "server_name": q.get("sni", u.hostname), "utls": {"enabled": True}}
            })
        elif u.scheme == "trojan":
            node.update({
                "type": "trojan", "password": u.username,
                "tls": {"enabled": True, "server_name": q.get("sni", u.hostname)}
            })
        elif u.scheme in ["hysteria2", "hy2"]:
            node.update({
                "type": "hysteria2",
                "password": u.username,
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", u.hostname),
                    "insecure": q.get("insecure", "false").lower() == "true"
                }
            })

        cfg["outbounds"].append(node)
        cfg["outbounds"][1]["outbounds"].append(tag) # 添加到 auto 组
        cfg["outbounds"][0]["outbounds"].append(tag) # 添加到 proxy 组

    with open("config.json", "w") as f:
        json.dump(cfg, f, indent=2)
    
    print(f"✅ 完成！已写入 {len(valid_results[:MAX_KEEP_NODES])} 个节点到 config.json")

if __name__ == "__main__":
    main()
