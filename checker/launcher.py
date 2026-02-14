import asyncio, aiohttp, json, re, os, time, subprocess, random
from urllib.parse import urlparse, parse_qs
from datetime import datetime

OUTPUT_FILE="best_nodes.txt"
XRAY_PATH="./core/xray"

MAX_CHECK=6000
FINAL_LIMIT=30
CONCURRENCY=40
SPEED_LIMIT=0.2
TEST_URL="https://speed.cloudflare.com/__down?bytes=10000000"

# ---------------- FLAG ----------------
def flag_emoji(cc):
    if len(cc)!=2: return "🏳"
    return chr(127397+ord(cc[0].upper()))+chr(127397+ord(cc[1].upper()))

# ---------------- SOURCES ----------------
SOURCES=[ ... ОСТАВЬ СВОИ ИСТОЧНИКИ КАК ЕСТЬ ... ]
# (не меняй их — просто оставь как у тебя)

# ---------------- UTILS ----------------
def month_expire():
    now=datetime.utcnow()
    m=now.month%12+1
    y=now.year+(now.month==12)
    return int(datetime(y,m,1).timestamp())

def normalize_host_port(parsed):
    raw=parsed.netloc.split("@")[-1]
    raw=raw.replace("[","").replace("]","")
    if "ffff:" in raw: raw=raw.split("ffff:")[-1]

    host=raw; port=443
    if ":" in raw:
        parts=raw.split(":")
        if parts[-1].isdigit():
            port=int(parts[-1])
            host=":".join(parts[:-1])
    return host,port

# ---------- UNIVERSAL XRAY CONFIG ----------
def build_config(link,local_port):
    p=urlparse(link)
    q=parse_qs(p.query)

    uuid=p.username
    host,port=normalize_host_port(p)

    security=q.get("security",["tls"])[0]
    network=q.get("type",["tcp"])[0]
    sni=q.get("sni",[host])[0]
    flow=q.get("flow",[""])[0]
    pbk=q.get("pbk",[""])[0]
    sid=q.get("sid",[""])[0]
    fp=q.get("fp",["chrome"])[0]
    path=q.get("path",["/"])[0]
    service=q.get("serviceName",[""])[0]

    outbound={
        "protocol":"vless",
        "settings":{
            "vnext":[{
                "address":host,
                "port":port,
                "users":[{
                    "id":uuid,
                    "encryption":"none",
                    "flow":flow if flow else None
                }]
            }]
        },
        "streamSettings":{"network":network}
    }

    if security=="reality":
        outbound["streamSettings"]["security"]="reality"
        outbound["streamSettings"]["realitySettings"]={
            "serverName":sni,
            "fingerprint":fp,
            "publicKey":pbk,
            "shortId":sid,
            "spiderX":"/"
        }
    else:
        outbound["streamSettings"]["security"]="tls"
        outbound["streamSettings"]["tlsSettings"]={"serverName":sni,"allowInsecure":True}

    if network=="ws":
        outbound["streamSettings"]["wsSettings"]={"path":path,"headers":{"Host":sni}}

    if network=="grpc":
        outbound["streamSettings"]["grpcSettings"]={"serviceName":service or "grpc"}

    if network=="tcp":
        outbound["streamSettings"]["tcpSettings"]={"header":{"type":"none"}}

    return {
        "log":{"loglevel":"warning"},
        "inbounds":[{"port":local_port,"listen":"127.0.0.1","protocol":"socks"}],
        "outbounds":[outbound]
    }

# ---------------- SPEED ----------------
async def speedtest(port):
    start=time.time()
    try:
        timeout=aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(TEST_URL,proxy=f"socks5://127.0.0.1:{port}") as r:
                await r.read()
        return (10/(time.time()-start))*8
    except:
        return 0

# ---------------- CHECK ----------------
class Node:
    def __init__(self,link):
        self.link=link
        self.speed=0
        self.country="XX"

async def check_node(node,sem):
    async with sem:
        port=random.randint(20000,40000)
        cfg=f"tmp_{port}.json"

        try:
            with open(cfg,"w") as f:
                json.dump(build_config(node.link,port),f)

            proc=subprocess.Popen([XRAY_PATH,"run","-c",cfg],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            await asyncio.sleep(2)

            if proc.poll() is not None:
                return None

            sp=await speedtest(port)
            proc.kill()

            if sp>SPEED_LIMIT:
                node.speed=sp
                return node
        finally:
            if os.path.exists(cfg): os.remove(cfg)

# ---------------- LOAD ----------------
async def load_links():
    all=[]
    async with aiohttp.ClientSession() as s:
        for src in SOURCES:
            try:
                async with s.get(src,timeout=15) as r:
                    all+=re.findall(r'vless://[^\s"]+',await r.text())
            except: pass
    return list(set(all))[:MAX_CHECK]

# ---------------- MAIN ----------------
async def main():
    print("loading...")
    links=await load_links()
    nodes=[Node(l) for l in links]

    sem=asyncio.Semaphore(CONCURRENCY)
    res=[r for r in await asyncio.gather(*(check_node(n,sem) for n in nodes)) if r]

    res.sort(key=lambda x:-x.speed)
    final=res[:FINAL_LIMIT]

    async with aiohttp.ClientSession() as s:
        for n in final:
            try:
                host=urlparse(n.link).hostname
                async with s.get(f"http://ip-api.com/json/{host}?fields=countryCode",timeout=5) as r:
                    n.country=(await r.json()).get("countryCode","XX")
            except: pass

    TOTAL_BYTES=200*1024*1024*1024
    header=f"""#profile-title: 🚀 GRAY VPN [Тариф: 200ГБ в месяц]
#profile-update-interval: 60
#profile-web-page-url: https://grayvpn.ru
#profile-icon-url: https://grayvpn.ru/logo.png
#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={month_expire()}

"""

    with open(OUTPUT_FILE,"w",encoding="utf-8") as f:
        f.write(header)
        for n in final:
            base=n.link.split("#")[0]
            name=f"{flag_emoji(n.country)} {n.country} [GRAY VPN]"
            f.write(f"{base}#{name}\n")

    print("done",len(final))

asyncio.run(main())