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

# 备用规则镜像，提高国内访问稳定性
RULE_CDN = [
    "https://gh-proxy.com/https://raw.githubusercontent.com",
    "https://cdn.jsdelivr.net/gh"
]

RULE_PATHS = {
    "adblock": "217heidai/adblockfilters/main/rules/adblocksingbox.srs",
    "geosite_ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "geosite_cn": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "geoip_cn": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 20  # 并发测速线程数
CONNECT_TIMEOUT = 1.5
MAX_KEEP_NODES = 50
TIKTOK_SELECTOR = "JP"

COUNTRY_KEYWORDS = {
    "HK": ["hk", "hongkong", "香港", "🇭🇰"],
    "JP": ["jp", "japan", "日本", "东京", "大阪", "🇯🇵"],
    "US": ["us", "united", "america", "美国", "🇺🇸"],
    "SG": ["sg", "singapore", "新加坡", "🇸🇬"]
}

# ===================== 工具函数 =====================
def safe_decode(text):
    text = text.strip()
    try:
        # 补充Base64填充并解码
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "ignore")
    except Exception:
        return text

def detect_country(link_text):
    t = link_text.lower()
    for code, keys in COUNTRY_KEYWORDS.items():
        if any(k in t for k in keys):
            return code
    return "US"

def check_node(link):
    """测试节点连接性并返回基础信息"""
    try:
        u = urlparse(link)
        if not u.hostname: return None
        port = u.port or (443 if u.scheme in ['vless', 'trojan'] else 80)
        
        # 简单的TCP握手测试
        start = socket.time.time()
        with socket.create_connection((u.hostname, port), timeout=CONNECT_TIMEOUT):
            rtt = int((socket.time.time() - start) * 1000)
            return {"link": link, "rtt": rtt, "u": u}
    except:
        return None

def get_best_rule_url(path):
    for cdn in RULE_CDN:
        url = f"{cdn}/{path}"
        try:
            if requests.head(url, timeout=3).status_code == 200:
                return url
        except: continue
    return f"https://raw.githubusercontent.com/{path}"

# ===================== 核心配置模版 =====================
def create_singbox_template(rule_urls):
    return {
        "log": {"level": "info"},
        "dns": {
            "servers": [
                {"tag": "dns_proxy", "address": "https://8.8.8.8/dns-query", "detour": "proxy"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"},
                {"tag": "dns_block", "address": "rcode://success"}
            ],
            "rules": [
                {"rule_set": ["adblock", "geosite_ads"], "server": "dns_block"},
                {"rule_set": "geosite_cn", "server": "dns_local"},
                {"domain_suffix": ["tiktok.com", "googlevideo.com"], "server": "dns_proxy"}
            ],
            "final": "dns_proxy"
        },
        "inbounds": [{
            "type": "tun",
            "inet4_address": "172.19.0.1/30",
            "auto_route": True,
            "strict_route": True,
            "sniff": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto"]},
            {"type": "urltest", "tag": "auto", "outbounds": []},
            {"type": "selector", "tag": "HK", "outbounds": []},
            {"type": "selector", "tag": "JP", "outbounds": []},
            {"type": "selector", "tag": "US", "outbounds": []},
            {"type": "selector", "tag": "SG", "outbounds": []},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ],
        "route": {
            "rules": [
                {"ip_is_private": True, "outbound": "direct"},
                {"rule_set": ["adblock", "geosite_ads"], "action": "reject"},
                {"rule_set": ["geoip_cn", "geosite_cn"], "outbound": "direct"},
                {"domain_suffix": ["tiktok.com"], "outbound": TIKTOK_SELECTOR}
            ],
            "final": "proxy",
            "rule_set": [
                {"tag": k, "type": "remote", "format": "binary", "url": v} for k, v in rule_urls.items()
            ]
        }
    }

# ===================== 执行流程 =====================
def main():
    print("🔍 正在获取订阅源...")
    raw_links = []
    for src in SOURCES:
        try:
            resp = requests.get(src, timeout=10).text
            # 自动处理可能存在的Base64全文本加密
            content = safe_decode(resp) if "://" not in resp[:20] else resp
            found = re.findall(r"(vless|trojan)://[^\s#]+", content)
            raw_links.extend(found)
        except Exception as e:
            print(f"⚠️ 读取源 {src} 失败: {e}")

    unique_links = list(set(raw_links))
    print(f"检测到 {len(unique_links)} 个候选节点，开始并发测速...")

    # 并发测速
    valid_nodes = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [executor.submit(check_node, link) for link in unique_links]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if res: valid_nodes.append(res)
    
    # 按延迟排序并截取
    valid_nodes.sort(key=lambda x: x['rtt'])
    valid_nodes = valid_nodes[:MAX_KEEP_NODES]

    # 构建配置
    rule_urls = {k: get_best_rule_url(v) for k, v in RULE_PATHS.items()}
    cfg = create_singbox_template(rule_urls)
    
    added_count = 0
    for node_data in valid_nodes:
        u = node_data['u']
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        country = detect_country(u.fragment or u.hostname)
        tag = f"{country}-{added_count:02d}-{node_data['rtt']}ms"
        
        # 节点基础结构
        node_cfg = {
            "type": u.scheme,
            "tag": tag,
            "server": u.hostname,
            "server_port": u.port or 443
        }

        # 协议详情解析
        if u.scheme == "vless":
            node_cfg.update({
                "uuid": u.username,
                "flow": q.get("flow", ""),
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", u.hostname),
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }
            })
            if "pbk" in q: # Reality 支持
                node_cfg["tls"]["reality"] = {
                    "enabled": True, 
                    "public_key": q["pbk"],
                    "short_id": q.get("sid", "")
                }
        
        elif u.scheme == "trojan":
            node_cfg.update({
                "password": u.username,
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", u.hostname),
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }
            })

        # 将节点添加到配置
        cfg["outbounds"].append(node_cfg)
        
        # 分流逻辑
        for out in cfg["outbounds"]:
            if out["tag"] in ["auto", country]:
                out["outbounds"].append(tag)
        added_count += 1

    # 清理没有任何节点的国家组，防止 sing-box 报错
    cfg["outbounds"] = [
        o for o in cfg["outbounds"] 
        if o.get("type") != "selector" or (o.get("outbounds") and len(o["outbounds"]) > 0)
    ]

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    
    print(f"✨ 成功！已筛选 {added_count} 个优质节点并生成 config.json")

if __name__ == "__main__":
    main()
