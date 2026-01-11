import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置区 ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

# 资源链接 (镜像加速)
AD_RULES_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
GEOIP_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
GEOSITE_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"

# 严格过滤参数
MAX_LATENCY = 0.2  # 200ms
TIMEOUT = 0.4      # 1秒超时
MAX_WORKERS = 80

# 仅保留：日本、美国、香港、韩国
REGION_RE = re.compile(r"日本|JP|Japan|美国|US|United States|香港|HK|HongKong|韩国|KR|Korea", re.I)

def get_modern_template():
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_fakeip", "address": "fakeip"},
                # 阿里 DNS Over HTTPS
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
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30"],
            "auto_route": True,
            "strict_route": True,
            "sniff": True
        }],
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": ["auto-test", "direct"]},
            {"type": "urltest", "tag": "auto-test", "outbounds": [], "url": "https://www.gstatic.com/generate_204", "interval": "10m"},
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

def decode_base64(data):
    try:
        data = data.replace('-', '+').replace('_', '/')
        missing_padding = len(data) % 4
        if missing_padding: data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except: return ""

def check_node(node_link):
    """
    检测节点存活并返回延迟，剔除 > 500ms 的节点
    """
    try:
        u = urlparse(node_link)
        host, port = u.hostname, u.port
        if not host or not port: return None
        
        start_time = time.time()
        with socket.create_connection((host, int(port)), timeout=TIMEOUT):
            latency = time.time() - start_time
            if latency <= MAX_LATENCY:
                return (node_link, latency)
        return None
    except: return None

def parse_to_outbound(link):
    try:
        u = urlparse(link)
        q = parse_qs(u.query)
        protocol = u.scheme
        if protocol not in ["vless", "trojan", "hysteria2", "hy2"]:
            return None

        tag = unquote(u.fragment) or f"{protocol}_{u.hostname}"
        # 严格地区过滤
        if not REGION_RE.search(tag): 
            return None

        node = {
            "type": "hysteria2" if protocol in ["hysteria2", "hy2"] else protocol,
            "tag": tag,
            "server": u.hostname,
            "server_port": int(u.port)
        }

        if protocol == "vless":
            node["uuid"] = u.username
        else:
            node["password"] = u.username

        if protocol in ["hysteria2", "hy2"]:
            node["tls"] = {
                "enabled": True,
                "server_name": q.get('sni', [u.hostname])[0],
                "insecure": True if q.get('insecure', ['0'])[0] == '1' else False
            }
            if q.get('obfs', [''])[0] == 'aes-128-gcm':
                node["obfs"] = {"type": "password", "password": q.get('obfs-password', [''])[0]}
            return node

        security = q.get('security', [''])[0]
        if "tls" in link or security in ['tls', 'reality']:
            node["tls"] = {
                "enabled": True,
                "server_name": q.get('sni', [u.hostname])[0],
                "utls": {"enabled": True, "fingerprint": "chrome"}
            }
            if security == 'reality':
                node["tls"]["reality"] = {
                    "enabled": True,
                    "public_key": q.get('pbk', [''])[0],
                    "short_id": q.get('sid', [''])[0]
                }

        transport_type = q.get('type', [''])[0]
        if transport_type == 'ws':
            node["transport"] = {
                "type": "ws",
                "path": q.get('path', ['/'])[0],
                "headers": {"Host": q.get('host', [''])[0]}
            }
        elif transport_type == 'grpc':
            node["transport"] = {"type": "grpc", "service_name": q.get('serviceName', [''])[0]}

        return node
    except:
        return None

def main():
    print(f"开始工作：仅保留日/美/港/韩 且延迟 < 500ms 的节点...")
    all_raw_links = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                content = r.text.strip()
                decoded = decode_base64(content)
                final_text = decoded if decoded else content
                all_raw_links.extend([
                    l.strip() for l in final_text.splitlines() 
                    if any(p in l for p in ["vless://", "trojan://", "hysteria2://", "hy2://"])
                ])
        except Exception as e:
            print(f"源 {url} 获取失败")

    all_raw_links = list(set(all_raw_links))
    print(f"初步抓取 {len(all_raw_links)} 个节点，正在进行严格测速与过滤...")
    
    valid_nodes_with_latency = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(check_node, all_raw_links))
        valid_nodes_with_latency = [r for r in results if r]

    outbounds, final_tags = [], []
    # 按延迟排序，优先放置低延迟节点
    valid_nodes_with_latency.sort(key=lambda x: x[1])

    for link, lat in valid_nodes_with_latency:
        o = parse_to_outbound(link)
        if o:
            # 标记延迟在名称上方便查看
            ms = int(lat * 1000)
            base_tag = f"[{ms}ms] {o['tag']}".replace(':', '-')
            t = base_tag
            counter = 1
            while t in final_tags:
                t = f"{base_tag}_{counter}"
                counter += 1
            o['tag'] = t
            outbounds.append(o)
            final_tags.append(t)

    config = get_modern_template()
    if not final_tags:
        print("未发现符合条件的低延迟节点。")
        return

    config['outbounds'].extend(outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + final_tags + ["direct"]
    config['outbounds'][1]['outbounds'] = final_tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"成功！保存了 {len(outbounds)} 个优质节点至 config.json")

if __name__ == "__main__":
    main()
