import requests
import base64
import socket
import concurrent.futures
import json
import re
import time
from urllib.parse import urlparse, parse_qs

# ================= 配置参数 =================
SOURCES = [
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/WLget/V2Ray_configs_64/master/ConfigSub_list.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
]

# jsdelivr 加速规则
RULE_PROXY = "https://cdn.jsdelivr.net/gh"

MAX_KEEP_NODES = 50
CONNECT_TIMEOUT = 2
MAX_RTT = 1500
TIKTOK_OUTBOUND = "JP"  # 可改 SG

COUNTRY_KEYWORDS = {
    "US": ["us","united"],
    "HK": ["hk","hong"],
    "JP": ["jp","japan"],
    "SG": ["sg","sing"]
}

# ================= 工具函数 =================
def safe_decode(text):
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8","ignore")
    except:
        return text

def detect_country(text):
    t = text.lower()
    for c, ks in COUNTRY_KEYWORDS.items():
        if any(k in t for k in ks):
            return c
    return "US"

def speed_test(link):
    try:
        u = urlparse(link)
        start = time.time()
        s = socket.create_connection((u.hostname, u.port or 443), timeout=CONNECT_TIMEOUT)
        s.close()
        rtt = (time.time() - start) * 1000
        if rtt <= MAX_RTT:
            return link, rtt
    except:
        return None

# ================= 基础模板 =================
def base_config():
    return {
        "log":{"level":"warn","timestamp":True},
        "dns":{
            "servers":[
                {"tag":"dns_proxy","address":"https://1.1.1.1/dns-query","detour":"proxy"},
                {"tag":"dns_local","address":"https://223.5.5.5/dns-query","detour":"direct"},
                {"tag":"dns_block","address":"rcode://success"},
                {"tag":"fakeip_server","address":"fakeip"}
            ],
            "rules":[
                {"rule_set":["geosite-ads","adblock-extra"],"server":"dns_block","action":"route"},
                {"rule_set":"geosite-cn","server":"dns_local","action":"route"},
                {"query_type":["A","AAAA"],"server":"fakeip_server","action":"route"}
            ],
            "final":"dns_proxy",
            "strategy":"prefer_ipv4",
            "fakeip":{"enabled":True,"inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}
        },
        "inbounds":[
            {"type":"tun","tag":"tun-in","inet4_address":["172.19.0.1/30"],"inet6_address":["fd00::1/126"],
             "mtu":1280,"auto_route":True,"strict_route":True,"stack":"gvisor","sniff":True,"sniff_override_destination":True}
        ],
        "outbounds":[
            {"type":"selector","tag":"proxy","outbounds":["auto","US","HK","JP","SG"]},
            {"type":"urltest","tag":"auto","outbounds":[],"url":"https://www.gstatic.com/generate_204","interval":"10m"},
            {"type":"selector","tag":"US","outbounds":[]},
            {"type":"selector","tag":"HK","outbounds":[]},
            {"type":"selector","tag":"JP","outbounds":[]},
            {"type":"selector","tag":"SG","outbounds":[]},
            {"type":"direct","tag":"direct"},
            {"type":"dns","tag":"dns-out"},
            {"type":"block","tag":"block"}
        ],
        "route":{
            "default_domain_resolver":"dns_local",
            "rule_set":[
                {"tag":"adblock-extra","type":"remote","format":"binary","url":f"{RULE_PROXY}/217heidai/adblockfilters/main/rules/adblocksingbox.srs","download_detour":"direct"},
                {"tag":"geosite-ads","type":"remote","format":"binary","url":f"{RULE_PROXY}/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs","download_detour":"direct"},
                {"tag":"geosite-cn","type":"remote","format":"binary","url":f"{RULE_PROXY}/SagerNet/sing-geosite/rule-set/geosite-cn.srs","download_detour":"direct"},
                {"tag":"geoip-cn","type":"remote","format":"binary","url":f"{RULE_PROXY}/SagerNet/sing-geoip/rule-set/geoip-cn.srs","download_detour":"direct"}
            ],
            "rules":[
                {"protocol":"dns","outbound":"dns-out","action":"route"},
                {"rule_set":["geosite-ads","adblock-extra"],"action":"reject"},
                {"ip_is_private":True,"outbound":"direct","action":"route"},
                {"rule_set":["geoip-cn","geosite-cn"],"outbound":"direct","action":"route"}
            ],
            "final":"proxy",
            "auto_detect_interface":True
        }
    }

# ================= 主流程 =================
def main():
    print("🚀 构建 sing-box 终极配置...")

    raw_links = []
    for s in SOURCES:
        try:
            r = requests.get(s, timeout=8).text
            data = safe_decode(r) if "://" not in r else r
            raw_links += re.findall(r"(?:vless|trojan)://[^\s#]+", data)
        except:
            continue

    raw_links = list(set(raw_links))

    # 测速筛选
    with concurrent.futures.ThreadPoolExecutor(50) as ex:
        alive_nodes = [r for r in ex.map(speed_test, raw_links) if r]

    alive_nodes.sort(key=lambda x:x[1])
    alive_links = [x[0] for x in alive_nodes[:MAX_KEEP_NODES]]

    cfg = base_config()
    tag_count = {}

    # 添加节点
    for link in alive_links:
        u = urlparse(link)
        q = parse_qs(u.query)
        country = detect_country(link)
        if country not in ("US","HK","JP","SG"): country="US"

        base_tag = f"{country}-{u.hostname}"
        tag_count[base_tag] = tag_count.get(base_tag,0)+1
        tag = f"{base_tag}-{tag_count[base_tag]:02d}"

        node = {"type":u.scheme,"tag":tag,"server":u.hostname,"server_port":u.port or 443}

        if u.scheme=="vless":
            node.update({
                "uuid":u.username,
                "flow":"xtls-rprx-vision",
                "packet_encoding":"xudp",
                "tls":{
                    "enabled":True,
                    "server_name":q.get("sni",[u.hostname])[0],
                    "utls":{"enabled":True,"fingerprint":"chrome"}
                }
            })
            if "pbk" in q:
                node["tls"]["reality"]={"enabled":True,"public_key":q["pbk"][0],"short_id":q.get("sid",[""])[0]}

        if u.scheme=="trojan":
            node.update({"password":u.username,"tls":{"enabled":True}})

        cfg["outbounds"].append(node)

        # 放到 selector
        for o in cfg["outbounds"]:
            t=o.get("tag")
            if t in ("auto","proxy"):
                if tag not in o["outbounds"]: o["outbounds"].append(tag)
            elif t in ("US","HK","JP","SG") and t==country:
                if tag not in o["outbounds"]: o["outbounds"].append(tag)
            elif t in ("US","HK","JP","SG") and not o["outbounds"]:
                o["outbounds"].append(tag)

    # 写入 config.json
    with open("config.json","w",encoding="utf-8") as f:
        json.dump(cfg,f,indent=2,ensure_ascii=False)

    print(f"✅ config.json 生成完成（有效节点 {len(alive_links)} 个）")
    print("✅ rule_set 远程加载 via jsdelivr")

if __name__=="__main__":
    main()
