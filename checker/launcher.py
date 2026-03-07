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

# ------------------ Конфигурация ------------------
OUTPUT_FILE = "best_nodes.txt"
XRAY_PATH = "./core/xray"
MAX_CHECK = 8000
FINAL_LIMIT = 50
CONCURRENCY = 40
SPEED_LIMIT = 0.1  # Лояльный порог скорости
TEST_URL = "https://speed.cloudflare.com/__down?bytes=1500000"
TCP_PING_TIMEOUT = 3
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
MMDB_PATH = "Country.mmdb"

EUROPE_COUNTRIES = {
    'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT',
    'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE', 'GB', 'IS', 'NO',
    'CH', 'MD', 'UA', 'BY', 'RS', 'BA', 'AL', 'MK', 'ME', 'XK', 'AD', 'LI', 'MC', 'SM', 'VA'
}

# ------------------ Источники нод ------------------
SOURCES = [
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

# ------------------ Логирование ------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("checker")

# ------------------ Утилиты ------------------
def flag_emoji(cc: str) -> str:
    if len(cc) != 2:
        return "🏳️"
    return chr(127397 + ord(cc[0].upper())) + chr(127397 + ord(cc[1].upper()))

def month_expire() -> int:
    now = datetime.utcnow()
    m = now.month % 12 + 1
    y = now.year + (now.month == 12)
    return int(datetime(y, m, 1).timestamp())

def is_port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False

def get_free_port(start=20000, end=40000) -> int:
    for _ in range(100):
        port = random.randint(start, end)
        if is_port_free(port):
            return port
    raise RuntimeError("Не удалось найти свободный порт")

def normalize_host_port(parsed: urlparse) -> Tuple[str, int]:
    host = parsed.hostname
    if not host:
        netloc = parsed.netloc.split('@')[-1]
        if netloc.startswith('['):
            host = netloc.split(']')[0][1:]
        else:
            host = netloc.split(':')[0]
    port = parsed.port or 443
    return host, port

def validate_vless_link(link: str) -> Optional[dict]:
    try:
        parsed = urlparse(link)
        if parsed.scheme != 'vless':
            return None
        uuid = parsed.username
        if not uuid or len(uuid) != 36:
            return None
        host, port = normalize_host_port(parsed)
        if not host:
            return None
        q = parse_qs(parsed.query)
        return {
            'uuid': uuid,
            'host': host,
            'port': port,
            'query': q,
            'fragment': parsed.fragment,
            'raw': link
        }
    except Exception:
        return None

# ------------------ TCP Ping ------------------
async def tcp_ping(host: str, port: int, timeout: float = TCP_PING_TIMEOUT) -> bool:
    try:
        await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        return True
    except Exception:
        return False

# ------------------ Node ------------------
class Node:
    __slots__ = ('link', 'valid', 'speed', 'ping', 'country')
    def __init__(self, link: str):
        self.link = link
        self.valid = validate_vless_link(link)
        self.speed = 0.0
        self.ping = 9999
        self.country = "XX"

    @property
    def is_valid(self) -> bool:
        return self.valid is not None

# ------------------ Speed & Ping ------------------
async def speed_test(port: int) -> float:
    from aiohttp_socks import ProxyConnector
    start = time.time()
    try:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
            async with sess.get(TEST_URL) as resp:
                await resp.read()
        elapsed = time.time() - start
        return 80 / elapsed
    except:
        return 0.0

async def ping_test(port: int) -> float:
    from aiohttp_socks import ProxyConnector
    try:
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=5)
        start = time.time()
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
            async with sess.head("http://1.1.1.1") as resp:
                if resp.status == 200:
                    return (time.time() - start) * 1000
    except:
        pass
    return 9999

# ------------------ Build Config ------------------
def build_config(valid_link: dict, local_port: int) -> dict:
    uuid = valid_link['uuid']
    host = valid_link['host']
    port = valid_link['port']
    q = valid_link['query']

    security = q.get('security', ['tls'])[0]
    network = q.get('type', ['tcp'])[0]
    sni = q.get('sni', [host])[0]
    flow = q.get('flow', [''])[0]
    pbk = q.get('pbk', [''])[0]
    sid = q.get('sid', [''])[0]
    fp = q.get('fp', ['chrome'])[0]
    path = q.get('path', ['/'])[0]
    service = q.get('serviceName', [''])[0]

    outbound = {
        "protocol": "vless",
        "settings": {"vnext":[{"address":host,"port":port,"users":[{"id":uuid,"encryption":"none","flow":flow if flow else None}]}]},
        "streamSettings":{"network":network}
    }

    if security=="reality":
        outbound["streamSettings"]["security"]="reality"
        outbound["streamSettings"]["realitySettings"]={
            "serverName":sni,"fingerprint":fp,"publicKey":pbk,"shortId":sid,"spiderX":"/"
        }
    else:
        outbound["streamSettings"]["security"]="tls"
        outbound["streamSettings"]["tlsSettings"]={"serverName":sni,"allowInsecure":True}

    if network=="ws":
        outbound["streamSettings"]["wsSettings"]={"path":path,"headers":{"Host":sni}}
    elif network=="grpc":
        outbound["streamSettings"]["grpcSettings"]={"serviceName":service or "grpc"}
    elif network=="tcp":
        outbound["streamSettings"]["tcpSettings"]={"header":{"type":"none"}}

    return {
        "log":{"loglevel":"none"},
        "inbounds":[{"port":local_port,"listen":"127.0.0.1","protocol":"socks"}],
        "outbounds":[outbound]
    }

# ------------------ Write Output ------------------
async def write_output(nodes: List[Node]):
    TOTAL_BYTES = 200 * 1024 * 1024 * 1024
    header = f"""#profile-title: 🌐 GRAY VPN — Максимальная скорость 🚀
#profile-update-interval: 60
#profile-web-page-url: https://t.me/grayvpnbot
#profile-icon-url: https://ibb.co/Dg4KjSfQ
#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={int(time.time()) + 60*24*3600}

"""
    async with aiofiles.open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        await f.write(header)
        for n in nodes:
            flag = flag_emoji(n.country)
            name = f"{flag} {n.country} [GRAY VPN]"
            base_link = n.link.split('#')[0]
            await f.write(f"{base_link}#{name}\n")
    logger.info(f"Записано {len(nodes)} нод в {OUTPUT_FILE}")