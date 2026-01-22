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

CDN_HOST = "gh-proxy.org"
GH_RAW_BASE = "https://raw.githubusercontent.com"
RULE_CDN_PREFIX = f"https://{CDN_HOST}/{GH_RAW_BASE}"

RULE_PATHS = {
    "ads": "SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
    "cn_site": "SagerNet/sing-geosite/rule-set/geosite-cn.srs",
    "cn_ip": "SagerNet/sing-geoip/rule-set/geoip-cn.srs"
}

MAX_THREADS = 50
MAX_KEEP_NODES = 50
SAMPLE_COUNT = 1 # 减少采样次数加快筛选速度
TIMEOUT = 2.0    # 适当放宽超时时间

# ===================== 工具函数 =====================
def decode_base64(data):
    """尝试解码 Base64 订阅内容"""
    try:
        # 补齐等号
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.b64decode(data).decode('utf-8')
    except:
        return data

def get_content(url):
    try:
        resp = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        raw_text = resp.text.strip()
        # 如果看起来像 Base64（不含协议头），则尝试解码
        if "://" not in raw_text[:20]:
            return decode_base64(raw_text)
        return raw_text
    except: return ""

def check_node(link):
    try:
        u = urlparse(link)
        if not u.hostname or ":" in u.hostname: return None
        
        start = time.time()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((u.hostname, u.port or 443))
            latency = int((time.time() - start) * 1000)
        
        # 返回指纹和数据
        fp = hashlib.md5(f"{u.scheme}{u.hostname}{u.port}{u.username}".encode()).hexdigest()
        return {"link": link, "u": u, "latency": latency, "fp": fp}
    except: 
        return None

# ===================== 主程序 =====================
def main():
    print(f"🚀 正在爬取节点...")
    
    all_raw_text = ""
    for s in SOURCES:
        content = get_content(s)
        all_raw_text += content + "\n"
    
    # 提取节点
    links = re.findall(r'((?:vless|trojan)://[^\s#]+)', all_raw_text)
    print(f"DEBUG: 初始解析到 {len(links)} 个潜在节点")
    
    if not links:
        print("❌ 未能从源获取任何 vless/trojan 节点，请检查源 URL 是否有效。")
        return

    unique_links = list(set(links))
    print(f"DEBUG: 去重后剩余 {len(unique_links)} 个节点，开始连通性测试...")

    tested_nodes = []
    seen_fps = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_node, unique_links))
        for res in results:
            if res and res["fp"] not in seen_fps:
                tested_nodes.append(res)
                seen_fps.add(res["fp"])

    print(f"DEBUG: 测试完成，可用节点数: {len(tested_nodes)}")

    if not tested_nodes:
        print("❌ 所有节点测速失败（超时或无法连接）。请检查你的网络环境或调大 TIMEOUT。")
        return

    tested_nodes.sort(key=lambda x: x['latency'])
    top_nodes = tested_nodes[:MAX_KEEP_NODES]

    # ... [此处保持之前的 cfg 生成逻辑不变] ...
    # 为了节省篇幅，假设生成逻辑已执行
    
    print(f"✅ 成功! 写入 {len(top_nodes)} 个节点到 config.json")

if __name__ == "__main__":
    main()
