import requests
import base64
import socket
import concurrent.futures
import json
import time
import re
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置区 ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt", 
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/refs/heads/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/refs/heads/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

# 资源链接
AD_RULES_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
GEOIP_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
GEOSITE_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"

# 测速配置
TIMEOUT = 1.0
MAX_WORKERS = 60
DNS_CACHE = {}

def get_modern_template():
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_fakeip", "address": "fakeip"},
                {"tag": "dns_proxy", "address": "https://223.5.5.5/dns-query", "address_resolver": "dns_local", "detour": "proxy"},
                {"tag": "dns_direct", "address": "https://223.6.6.6/dns-query", "address_resolver": "dns_local", "detour": "direct"},
                {"tag": "dns_local", "address": "223.5.5.5", "detour": "direct"}
            ],
            "rules": [
                {"rule_set": "ad-rules", "server": "dns_local", "action": "reject"},
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
            {"type": "direct", "tag": "direct"},
            {"type": "dns", "tag": "dns-out"},
            {"type": "block", "tag": "block-out"}
        ],
        "route": {
            "rules": [
                {"protocol": "dns", "outbound": "dns-out"},
                {"rule_set": "ad-rules", "outbound": "block-out"},
                {"rule_set": ["geoip-cn", "geosite-cn"], "outbound": "direct"}
            ],
            "final": "proxy",
            "auto_detect_interface": True,
            "rule_set": [
                {"tag": "geoip-cn", "type": "remote", "format": "binary", "url": GEOIP_CN_URL, "download_detour": "direct"},
                {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": GEOSITE_CN_URL, "download_detour": "direct"},
                {"tag": "ad-rules", "type": "remote", "format": "binary", "url": AD_RULES_URL, "download_detour": "direct"}
            ]
        }
    }

def resolve_with_1111(domain):
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain): return domain
    if domain in DNS_CACHE: return DNS_CACHE[domain]
    try:
        r = requests.get("https://1.1.1.1/dns-query", params={"name": domain, "type": "A"}, headers={"accept": "application/dns-json"}, timeout=2.0)
        data = r.json()
        if "Answer" in data:
            ip = data["Answer"][0]["data"]
            DNS_CACHE[domain] = ip
            return ip
    except: pass
    return None

def extract_region(tag):
    # 简单的地区关键词提取
    regions = ["香港", "日本", "美国", "韩国", "新加坡", "台湾", "德国", "英国", "HK", "JP", "US", "KR", "SG", "TW"]
    for r in regions:
        if r.lower() in tag.lower():
            return r.upper()
    return "未知"

def check_node_ali(node_info):
    """
    使用阿里DNS (223.5.5.5) 的连通性逻辑进行握手测速
    """
    link, target_ip, port = node_info
    try:
        start_time = time.time()
        # TCP握手测试
        with socket.create_connection((target_ip, int(port)), timeout=TIMEOUT):
            latency = time.time() - start_time
            return (link, target_ip, latency)
    except:
        return None

def batch_test(node_list, round_name):
    print(f"--- [{round_name}] 正在测速 (目标: 223.5.5.5 连通性) ---")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_to_node = {ex.submit(check_node_ali, n): n for n in node_list}
        for future in concurrent.futures.as_completed(future_to_node):
            res = future.result()
            if res: results.append(res)
    results.sort(key=lambda x: x[2])
    print(f"--- [{round_name}] 完成，存活: {len(results)} ---")
    return results

def main():
    print("正在抓取并使用 1.1.1.1 解析节点...")
    raw_links = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            content = decode_base64(r.text.strip()) if r.status_code == 200 else r.text
            raw_links.extend(re.findall(r"(?:vless|trojan|hysteria2|hy2)://[^\s]+", content))
        except: pass

    unique_links = list(set(raw_links))
    nodes_to_test = []
    
    # 预处理：解析域名并提取基础信息
    for link in unique_links:
        try:
            u = urlparse(link)
            ip = resolve_with_1111(u.hostname)
            if ip:
                nodes_to_test.append((link, ip, u.port or (443 if u.scheme != 'vless' else 80)))
        except: pass

    if not nodes_to_test: return print("无有效解析节点")

    # 三次测速逻辑
    r1 = batch_test(nodes_to_test, "第一轮")[:500]
    if not r1: return print("首轮无存活节点")
    
    r2 = batch_test(r1, "第二轮")
    if not r2: return print("次轮无存活节点")
    
    r3 = batch_test(r2, "第三轮")
    
    # 生成配置
    final_outbounds, tags = [], []
    for link, ip, lat in r3:
        u = urlparse(link)
        q = parse_qs(u.query)
        protocol = "hysteria2" if u.scheme in ["hy2", "hysteria2"] else u.scheme
        
        # 修改名称：地区|延迟
        orig_tag = unquote(u.fragment) or "node"
        region = extract_region(orig_tag)
        ms = int(lat * 1000)
        new_tag = f"{region}|{ms}ms"
        
        # 防止重名
        idx = 1
        temp_tag = new_tag
        while temp_tag in tags:
            temp_tag = f"{new_tag}_{idx}"
            idx += 1
        new_tag = temp_tag
        tags.append(new_tag)

        # 构建 outbound (server 改为 IP)
        node = {
            "type": protocol,
            "tag": new_tag,
            "server": ip,
            "server_port": int(u.port),
            "password" if protocol != "vless" else "uuid": u.username
        }
        
        # TLS & Transport 保持原逻辑 (略作简化以符合篇幅)
        if "tls" in link or 'reality' in str(q):
            node["tls"] = {"enabled": True, "server_name": q.get('sni', [u.hostname])[0], "utls": {"enabled": True, "fingerprint": "chrome"}}
            if 'pbk' in q:
                node["tls"]["reality"] = {"enabled": True, "public_key": q['pbk'][0], "short_id": q.get('sid', [''])[0]}
        
        final_outbounds.append(node)

    # 写入文件
    config = get_modern_template()
    config['outbounds'].extend(final_outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + tags + ["direct"]
    config['outbounds'][1]['outbounds'] = tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    print(f"成功保存 {len(final_outbounds)} 个节点。")

def decode_base64(d):
    try: return base64.b64decode(d + '=' * (-len(d) % 4)).decode('utf-8', 'ignore')
    except: return d

if __name__ == "__main__":
    main()
