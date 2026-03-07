import asyncio
import aiohttp
import aiofiles
import json
import re
import os
import time
import random
import logging
import tempfile
import socket
import geoip2.database
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from typing import List, Optional, Tuple

OUTPUT_FILE = "best_nodes.txt"
XRAY_PATH = "./core/xray"

MAX_CHECK = 3000
FINAL_LIMIT = 50
CONCURRENCY = 40

SPEED_LIMIT = float(os.getenv("SPEED_LIMIT", 0.4))

TEST_URL = "https://speed.cloudflare.com/__down?bytes=1500000"

TCP_PING_TIMEOUT = 5

MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
MMDB_PATH = "Country.mmdb"

EUROPE_COUNTRIES = {
'AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT',
'LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE','GB','IS','NO',
'CH','MD','UA','BY','RS','BA','AL','MK','ME','XK','AD','LI','MC','SM','VA'
}

logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(message)s",datefmt="%H:%M:%S")
logger=logging.getLogger("checker")

SOURCES=[
"https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/PL.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/DE.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/LT.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/LV.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/SE.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/EE.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/FI.txt"
]

def flag_emoji(cc:str)->str:
    if len(cc)!=2:return "🏳️"
    return chr(127397+ord(cc[0].upper()))+chr(127397+ord(cc[1].upper()))

def month_expire()->int:
    now=datetime.utcnow()
    m=now.month%12+1
    y=now.year+(now.month==12)
    return int(datetime(y,m,1).timestamp())

def normalize_host_port(parsed)->Tuple[str,int]:
    host=parsed.hostname
    if not host:
        netloc=parsed.netloc.split('@')[-1]
        host=netloc.split(':')[0]
    port=parsed.port or 443
    return host,port

def validate_vless_link(link:str)->Optional[dict]:
    try:
        parsed=urlparse(link)
        if parsed.scheme!="vless":return None
        uuid=parsed.username
        if not uuid:return None
        host,port=normalize_host_port(parsed)
        q=parse_qs(parsed.query)
        return {'uuid':uuid,'host':host,'port':port,'query':q,'fragment':parsed.fragment,'raw':link}
    except:
        return None

async def tcp_ping(host,port,timeout=TCP_PING_TIMEOUT):
    try:
        await asyncio.wait_for(asyncio.open_connection(host,port),timeout)
        return True
    except:
        return False

async def check_xray():
    try:
        proc=await asyncio.create_subprocess_exec(XRAY_PATH,"version",stdout=asyncio.subprocess.PIPE)
        out,_=await proc.communicate()
        logger.info(out.decode().strip())
        return proc.returncode==0
    except:
        logger.error("Xray not found")
        return False

def build_config(valid_link,local_port):

    q=valid_link['query']

    security=q.get('security',['tls'])[0]
    network=q.get('type',['tcp'])[0]

    sni=q.get('sni',[valid_link['host']])[0]
    flow=q.get('flow',[''])[0]

    pbk=q.get('pbk',q.get('publicKey',['']))[0]
    sid=q.get('sid',q.get('shortId',['']))[0]

    outbound={
    "protocol":"vless",
    "settings":{
    "vnext":[{
    "address":valid_link['host'],
    "port":valid_link['port'],
    "users":[{
    "id":valid_link['uuid'],
    "encryption":"none",
    "flow":flow if flow else None
    }]
    }]
    },
    "streamSettings":{"network":network}
    }

    if security=="reality" and pbk:
        outbound["streamSettings"]["security"]="reality"
        outbound["streamSettings"]["realitySettings"]={
        "serverName":sni,
        "publicKey":pbk,
        "shortId":sid,
        "fingerprint":"chrome"
        }
    else:
        outbound["streamSettings"]["security"]="tls"
        outbound["streamSettings"]["tlsSettings"]={"serverName":sni,"allowInsecure":True}

    return {
    "log":{"loglevel":"none"},
    "inbounds":[{"port":local_port,"listen":"127.0.0.1","protocol":"socks"}],
    "outbounds":[outbound]
    }

async def load_links(session):
    all_links=set()

    for url in SOURCES:
        try:
            async with session.get(url,timeout=15) as resp:
                text=await resp.text()
                found=re.findall(r'vless://[^\s]+',text)
                all_links.update(found)
        except:
            pass

    links=list(all_links)[:MAX_CHECK]
    logger.info(f"Loaded {len(links)} nodes")
    return links

class Node:
    __slots__=('link','valid','speed','country','ping')

    def __init__(self,link):
        self.link=link
        self.valid=validate_vless_link(link)
        self.speed=0
        self.ping=9999
        self.country="XX"

    @property
    def is_valid(self):return self.valid is not None

async def speed_test(port):

    from aiohttp_socks import ProxyConnector

    try:
        connector=ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")

        async with aiohttp.ClientSession(connector=connector,timeout=aiohttp.ClientTimeout(total=20)) as s:

            start=time.time()
            async with s.get(TEST_URL) as r:
                await r.read()

        elapsed=time.time()-start
        return 16/elapsed
    except:
        return 0

async def ping_test(port):

    from aiohttp_socks import ProxyConnector

    try:
        connector=ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")

        start=time.time()

        async with aiohttp.ClientSession(connector=connector,timeout=aiohttp.ClientTimeout(total=5)) as s:
            async with s.head("http://1.1.1.1") as r:
                if r.status==200:
                    return (time.time()-start)*1000
    except:
        pass

    return 9999

async def check_node(node,temp_dir):

    if not node.is_valid:return None

    host=node.valid['host']
    port=node.valid['port']

    if not await tcp_ping(host,port):
        return None

    local_port=random.randint(20000,40000)

    cfg=build_config(node.valid,local_port)

    fd,cfg_path=tempfile.mkstemp(suffix='.json',dir=temp_dir)

    with os.fdopen(fd,'w') as f:
        json.dump(cfg,f)

    try:

        proc=await asyncio.create_subprocess_exec(XRAY_PATH,"run","-c",cfg_path)

        await asyncio.sleep(4)

        ping=await ping_test(local_port)

        if ping>1500:
            proc.kill()
            return None

        node.ping=ping

        speed=await speed_test(local_port)

        proc.kill()

        if speed>SPEED_LIMIT:
            node.speed=speed
            return node

    except:
        pass

    finally:
        os.unlink(cfg_path)

    return None

async def run_checks(nodes,temp_dir):

    sem=asyncio.Semaphore(CONCURRENCY)

    results=[]

    async def run(n):
        async with sem:
            r=await check_node(n,temp_dir)
            if r:results.append(r)

    await asyncio.gather(*[run(n) for n in nodes])

    return results

def resolve_country(nodes):

    if not os.path.exists(MMDB_PATH):return

    with geoip2.database.Reader(MMDB_PATH) as reader:

        for node in nodes:

            try:

                ip=socket.gethostbyname(node.valid['host'])

                cc=reader.country(ip).country.iso_code

                if cc:node.country=cc

            except:
                pass

async def write_output(nodes):

    header=f"""#profile-title: 🌐 GRAY VPN
#profile-update-interval: 60

"""

    async with aiofiles.open(OUTPUT_FILE,'w') as f:

        await f.write(header)

        for n in nodes:

            name=f"{flag_emoji(n.country)} {n.country} [GRAY VPN]"

            base=n.link.split('#')[0]

            await f.write(f"{base}#{name}\n")

async def main():

    if not await check_xray():return

    async with aiohttp.ClientSession() as session:

        links=await load_links(session)

    nodes=[Node(l) for l in links]

    with tempfile.TemporaryDirectory() as tmp:

        good=await run_checks(nodes,tmp)

    resolve_country(good)

    eu=[n for n in good if n.country in EUROPE_COUNTRIES]

    eu.sort(key=lambda x:(x.ping,-x.speed))

    best=eu[:FINAL_LIMIT]

    await write_output(best)

    logger.info(f"Saved {len(best)} nodes")

if __name__=="__main__":
    asyncio.run(main())