import asyncio
import aiohttp
import ssl
import time
import json
import re
import socket
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
import os

OUTPUT_FILE = "best_nodes.txt"
HISTORY_FILE = "node_history.json"

MAX_CHECK = 300
FINAL_LIMIT = 25
CONCURRENCY = 80

TCP_TIMEOUT = 2
TLS_TIMEOUT = 2

PRIORITY_COUNTRIES = ["DE", "NL", "PL", "LT", "LV", "SE"]

SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Country/DE.txt",
    "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Splitted-By-Country/NL.txt",
]

class Node:
    def __init__(self, link):
        self.link = link
        self.host = None
        self.port = None
        self.sni = None
        self.country = "XX"
        self.tcp_ping = None
        self.tls_ping = None
        self.score = 9999

    def compute_score(self):
        tcp = self.tcp_ping or 9999
        tls = self.tls_ping or tcp
        self.score = tcp * 0.6 + tls * 0.4


async def tcp_test(node, sem):
    async with sem:
        try:
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(node.host, node.port),
                timeout=TCP_TIMEOUT
            )
            node.tcp_ping = int((time.time() - start) * 1000)
            writer.close()
            await writer.wait_closed()
        except:
            pass


async def tls_test(node, sem):
    async with sem:
        try:
            if not node.sni:
                return

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    node.host,
                    node.port,
                    ssl=ctx,
                    server_hostname=node.sni
                ),
                timeout=TLS_TIMEOUT
            )
            node.tls_ping = int((time.time() - start) * 1000)
            writer.close()
            await writer.wait_closed()
        except:
            pass


async def detect_country(session, ip):
    try:
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode",
            timeout=2
        ) as r:
            data = await r.json()
            return data.get("countryCode", "XX")
    except:
        return "XX"


async def main():
    all_links = []

    async with aiohttp.ClientSession() as session:
        for src in SOURCES:
            try:
                async with session.get(src, timeout=10) as r:
                    text = await r.text()
                    links = re.findall(r'vless://[^\s"]+', text)
                    all_links.extend(links)
            except:
                pass

    unique = list(set(all_links))[:MAX_CHECK]

    nodes = []

    for link in unique:
        if "🔒" in link:
            continue

        try:
            p = urlparse(link)
            params = parse_qs(p.query)

            if not p.hostname:
                continue

            node = Node(link)
            node.host = p.hostname
            node.port = p.port or 443
            node.sni = params.get("sni", [p.hostname])[0]

            nodes.append(node)
        except:
            continue

    sem = asyncio.Semaphore(CONCURRENCY)

    await asyncio.gather(*(tcp_test(n, sem) for n in nodes))
    nodes = [n for n in nodes if n.tcp_ping]

    await asyncio.gather(*(tls_test(n, sem) for n in nodes))

    async with aiohttp.ClientSession() as session:
        for n in nodes:
            try:
                ip = socket.gethostbyname(n.host)
                n.country = await detect_country(session, ip)
            except:
                n.country = "XX"

    for n in nodes:
        n.compute_score()

    def priority(n):
        return (0 if n.country in PRIORITY_COUNTRIES else 1)

    nodes.sort(key=lambda n: (priority(n), n.score))

    final = nodes[:FINAL_LIMIT]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("#profile-title: 🚀 GRAY VPN\n\n")
        for n in final:
            name = f"{n.country} | {int(n.score)}ms"
            base = n.link.split("#")[0]
            f.write(f"{base}#{name}\n")

    print("DONE:", len(final))


if __name__ == "__main__":
    asyncio.run(main())