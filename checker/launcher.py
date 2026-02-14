import asyncio, aiohttp, json, re, os, time, subprocess, random
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from datetime import datetime

OUTPUT_FILE = "best_nodes.txt"
XRAY_PATH = "./core/xray"

MAX_CHECK = 6000
FINAL_LIMIT = 30
CONCURRENCY = 40
SPEED_LIMIT = 1.5  # Mbps minimum

TEST_URL = "https://speed.cloudflare.com/__down?bytes=10000000"

PRIORITY_COUNTRIES = ["DE","NL","PL","LT","LV","SE"]

# ==== ТВОИ ИСТОЧНИКИ (НЕ ТРОГАЛ) ====
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/7.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/6.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/PL.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/LT.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/DE.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/LV.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/EE.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/NL.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/SE.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/25.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/22.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/23.txt"
]

# =============================

def month_expire():
    now=datetime.utcnow()
    m=now.month%12+1
    y=now.year+(now.month==12)
    return int(datetime(y,m,1).timestamp())

class Node:
    def __init__(self,link):
        self.link=link
        self.speed=0
        self.country="XX"

# ---------- SPEED TEST ----------
async def speedtest(port):
    start=time.time()
    try:
        connector=aiohttp.TCPConnector()
        timeout=aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(connector=connector,timeout=timeout) as s:
            async with s.get(TEST_URL,proxy=f"socks5://127.0.0.1:{port}") as r:
                await r.read()
        mbps=(10/(time.time()-start))*8
        return mbps
    except:
        return 0

# ---------- XRAY ----------
def normalize_host_port(parsed):
    host = parsed.hostname or ""
    port = parsed.port

    raw = parsed.netloc.split("@")[-1]

    # IPv6 mapped IPv4
    if "ffff:" in raw:
        raw = raw.split("ffff:")[-1]

    # remove brackets
    raw = raw.replace("[", "").replace("]", "")

    # extract port manually if python failed
    if port is None and ":" in raw:
        parts = raw.split(":")
        if parts[-1].isdigit():
            port = int(parts[-1])
            host = ":".join(parts[:-1])
        else:
            host = raw
            port = 443

    return host, port or 443


def build_config(link, port_local):
    p = urlparse(link)
    q = parse_qs(p.query)

    uuid = p.username
    host, real_port = normalize_host_port(p)
    sni = q.get("sni", [host])[0]

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"port": port_local, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": False}}
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {"address": host, "port": real_port, "users": [{"id": uuid, "encryption": "none"}]}
                    ]
                },
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {"serverName": sni, "allowInsecure": True}
                }
            }
        ]
    }
    p=urlparse(link)
    q=parse_qs(p.query)

    uuid=p.username
    host=p.hostname
    sni=q.get("sni",[host])[0]

    return {
    "log":{"loglevel":"warning"},
    "inbounds":[{"port":port,"listen":"127.0.0.1","protocol":"socks","settings":{"udp":False}}],
    "outbounds":[{
        "protocol":"vless",
        "settings":{"vnext":[{"address":host,"port":p.port or 443,"users":[{"id":uuid,"encryption":"none"}]}]},
        "streamSettings":{
            "security":"tls",
            "tlsSettings":{"serverName":sni,"allowInsecure":True}
        }
    }]
    }

async def check_node(node, sem):
    async with sem:
        port = random.randint(20000, 40000)
        cfg = f"tmp_{port}_{int(time.time()*1000)}.json"

        try:
            with open(cfg, "w") as f:
                json.dump(build_config(node.link, port), f)

            proc = subprocess.Popen(
                [XRAY_PATH, "run", "-c", cfg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            await asyncio.sleep(2)

            if proc.poll() is not None:
                return None

            sp = await speedtest(port)

            try:
                proc.kill()
            except:
                pass

            try:
                await asyncio.sleep(0.2)
            except:
                pass

            if sp > SPEED_LIMIT:
                node.speed = sp
                return node

        finally:
            try:
                if os.path.exists(cfg):
                    os.remove(cfg)
            except:
                pass
    async with sem:
        port=random.randint(20000,40000)
        cfg=f"tmp_{port}.json"

        with open(cfg,"w") as f:
            json.dump(build_config(node.link,port),f)

        proc=subprocess.Popen([XRAY_PATH,"run","-c",cfg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        await asyncio.sleep(2)

        sp=await speedtest(port)
        proc.kill()
        os.remove(cfg)

        if sp> SPEED_LIMIT:
            node.speed=sp
            return node

# ---------- LOAD ----------
async def load_links():
    all=[]
    async with aiohttp.ClientSession() as s:
        for src in SOURCES:
            try:
                async with s.get(src,timeout=15) as r:
                    t=await r.text()
                    all+=re.findall(r'vless://[^\s"]+',t)
            except: pass
    return list(set(all))[:MAX_CHECK]

# ---------- MAIN ----------
async def main():
    print("loading...")
    links=await load_links()
    nodes=[Node(l) for l in links]

    sem=asyncio.Semaphore(CONCURRENCY)
    res=await asyncio.gather(*(check_node(n,sem) for n in nodes))
    res=[r for r in res if r]

    res.sort(key=lambda x:-x.speed)
    final=res[:FINAL_LIMIT]

    TOTAL_GB=200
    TOTAL_BYTES=TOTAL_GB*1024*1024*1024
    header=f"""#profile-title: 🚀 GRAY VPN [Тариф: 200ГБ в месяц]
#profile-update-interval: 60
#profile-web-page-url: https://grayvpn.ru
#profile-icon-url: https://share.google/KjLlvBYwyC2j2Flp3
#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={month_expire()}

"""

    with open(OUTPUT_FILE,"w",encoding="utf-8") as f:
        f.write(header)
        for n in final:
            base=n.link.split("#")[0]
            f.write(f"{base}#FAST | {round(n.speed,1)}Mbps\n")

    print("done",len(final))

asyncio.run(main())
