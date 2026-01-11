import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
import dns.resolver
from urllib.parse import urlparse, parse_qs, unquote

# --- 配置区 ---
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/refs/heads/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt"
]

# 资源链接
AD_RULES_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblocksingbox.srs"
GEOIP_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs"
GEOSITE_CN_URL = "https://gh-proxy.com/https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs"

ALI_IP = "223.5.5.5"
TIMEOUT = 1.0  
MAX_WORKERS = 50
REGION_RE = re.compile(r"日本|JP|Japan|韩国|KR|Korea|美国|US|United States|新加坡|SG|Singapore|香港|HK|HongKong", re.I)

def get_modern_template():
    """
    针对报错 'unknown field rule_set' 优化的模板
    将 rule_set 放置在 route 内部以提高兼容性
    """
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {
            "servers": [
                {"tag": "dns_fakeip", "address": "fakeip"},
                {"tag": "dns_proxy", "address": "https://1.1.1.1/dns-query", "address_resolver": "dns_local", "detour": "proxy"},
                {"tag": "dns_direct", "address": "https://223.5.5.5/dns-query", "address_resolver": "dns_local", "detour": "direct"},
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
            # 关键修复：在 route 内部定义 rule_set 列表
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
    try:
        host, port = None, None
        if "vmess://" in node_link:
            data = json.loads(decode_base64(node_link[8:]))
            host, port = data.get('add'), data.get('port')
        else:
            u = urlparse(node_link)
            host, port = u.hostname, u.port
        if not host or not port: return None
        with socket.create_connection((host, int(port)), timeout=TIMEOUT):
            return node_link
    except: return None

def parse_to_outbound(link):
    try:
        if link.startswith("vmess://"):
            data = json.loads(decode_base64(link[8:]))
            tag = data.get('ps', 'VMess').strip()
            if not REGION_RE.search(tag): return None
            node = {
                "type": "vmess", "tag": tag, "server": data['add'], "server_port": int(data['port']),
                "uuid": data['id'], "security": "auto", "alter_id": 0
            }
            if data.get('net') == 'ws':
                node["transport"] = {"type": "ws", "path": data.get('path', '/'), "headers": {"Host": data.get('host', '')}}
            if data.get('tls') == 'tls':
                node["tls"] = {"enabled": True, "server_name": data.get('sni', data.get('host', '')), "insecure": True}
            return node

        elif link.startswith("ss://"):
            u = urlparse(link)
            tag = unquote(u.fragment) or "SS"
            if not REGION_RE.search(tag): return None
            if "@" in u.netloc:
                user_part = u.netloc.split("@")[0]
                user_info = decode_base64(user_part) if ":" not in user_part else user_part
                m, p = user_info.split(":", 1)
                return {"type": "shadowsocks", "tag": tag, "server": u.hostname, "server_port": u.port, "method": m, "password": p}
            
        elif link.startswith(("vless://", "trojan://")):
            u = urlparse(link); q = parse_qs(u.query); protocol = u.scheme
            tag = unquote(u.fragment) or protocol
            if not REGION_RE.search(tag): return None
            node = {"type": protocol, "tag": tag, "server": u.hostname, "server_port": int(u.port)}
            if protocol == "vless": node["uuid"] = u.username
            else: node["password"] = u.username
            
            if "tls" in link or q.get('security', [''])[0] in ['tls', 'reality']:
                node["tls"] = {
                    "enabled": True, 
                    "server_name": q.get('sni', [u.hostname])[0], 
                    "utls": {"enabled": True, "fingerprint": "chrome"}
                }
                if q.get('security', [''])[0] == 'reality':
                    node["tls"]["reality"] = {"enabled": True, "public_key": q.get('pbk', [''])[0], "short_id": q.get('sid', [''])[0]}
            
            transport_type = q.get('type', [''])[0]
            if transport_type == 'ws':
                node["transport"] = {"type": "ws", "path": q.get('path', ['/'])[0]}
            elif transport_type == 'grpc':
                node["transport"] = {"type": "grpc", "service_name": q.get('serviceName', [''])[0]}
            return node
    except: return None

def main():
    print("正在抓取并检测节点中...")
    all_raw_links = []
    for url in SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                content = r.text.strip()
                decoded = decode_base64(content)
                final_text = decoded if decoded else content
                all_raw_links.extend([l.strip() for l in final_text.splitlines() if "://" in l])
        except Exception as e:
            print(f"源 {url} 失败: {e}")

    all_raw_links = list(set(all_raw_links))
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        alive_links = [r for r in list(ex.map(check_node, all_raw_links)) if r]

    outbounds, final_tags = [], []
    for l in alive_links:
        o = parse_to_outbound(l)
        if o:
            base_tag = o['tag'].replace(':', '-').strip()
            t = base_tag
            counter = 1
            while t in final_tags:
                t = f"{base_tag} ({counter})"
                counter += 1
            o['tag'] = t
            outbounds.append(o)
            final_tags.append(t)

    config = get_modern_template()
    if not final_tags:
        print("未发现有效节点。")
        return

    config['outbounds'].extend(outbounds)
    config['outbounds'][0]['outbounds'] = ["auto-test"] + final_tags + ["direct"]
    config['outbounds'][1]['outbounds'] = final_tags

    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"成功！已生成兼容性配置 config.json，共 {len(outbounds)} 个节点。")

if __name__ == "__main__":
    main()
