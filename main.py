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
from datetime import datetime

OUTPUT_FILE = "best_nodes.txt"
HISTORY_FILE = "node_history.json"

MAX_CHECK = 600
FINAL_LIMIT = 30
SNI_LIMIT = 2
COUNTRY_LIMIT = 10

CONCURRENCY = 150

TCP_TIMEOUT = 2
TLS_TIMEOUT = 2
HEAD_TIMEOUT = 2

PRIORITY_COUNTRIES = ["DE", "NL", "PL", "LT", "LV", "SE"]

SOURCES = [
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
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/23.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/main/githubmirror/26.txt"
]


def get_month_expire():
    now = datetime.utcnow()
    year = now.year
    month = now.month

    if month == 12:
        next_month = datetime(year + 1, 1, 1)
    else:
        next_month = datetime(year, month + 1, 1)

    return int(next_month.timestamp())


class Node:
    def __init__(self, link):
        self.link = link
        self.host = None
        self.port = None
        self.sni = None
        self.country = "XX"
        self.tcp_ping = None
        self.tls_ping = None
        self.head_ping = None
        self.score = 9999
        self.stability_bonus = 0

    def compute_score(self):
        tcp = self.tcp_ping or 9999
        tls = self.tls_ping or tcp
        head = self.head_ping if self.head_ping else 300
        base = tcp * 0.5 + tls * 0.3 + head * 0.2
        self.score = base - self.stability_bonus


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return {}
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)


def save_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f)


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


async def head_test(node, session, sem):
    if "security=reality" in node.link:
        return
    async with sem:
        try:
            start = time.time()
            async with session.head(
                f"https://{node.sni}",
                timeout=HEAD_TIMEOUT
            ):
                node.head_ping = int((time.time() - start) * 1000)
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


async def assign_country(node, session):
    try:
        ip = socket.gethostbyname(node.host)
        node.country = await detect_country(session, ip)
    except:
        node.country = "XX"


async def main():
    print("Loading sources...")

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

            node_type = params.get("type", ["tcp"])[0]
            if node_type not in ["ws", "tcp", "raw"]:
                continue

            if "reality" in link:
                if not all(x in link for x in ["pbk=", "sni=", "fp="]):
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
        await asyncio.gather(*(assign_country(n, session) for n in nodes))
        await asyncio.gather(*(head_test(n, session, sem) for n in nodes))

    history = load_history()

    for n in nodes:
        key = f"{n.host}:{n.port}"
        record = history.get(key, {"success": 0})
        record["success"] += 1
        history[key] = record

        n.stability_bonus = min(record["success"] * 5, 50)

        if n.host.startswith(("104.", "172.", "188.", "185.")):
            n.stability_bonus -= 15

        n.compute_score()

    save_history(history)

    def priority(n):
        return (0 if n.country in PRIORITY_COUNTRIES else 1)

    nodes.sort(key=lambda n: (priority(n), n.score))

    final = []
    sni_count = defaultdict(int)
    country_count = defaultdict(int)

    for n in nodes:
        if len(final) >= FINAL_LIMIT:
            break
        if sni_count[n.sni] >= SNI_LIMIT:
            continue
        if country_count[n.country] >= COUNTRY_LIMIT:
            continue

        final.append(n)
        sni_count[n.sni] += 1
        country_count[n.country] += 1

    final.sort(key=lambda n: n.score)

    # ====== SUBSCRIPTION HEADER ======
    TOTAL_GB = 200
    TOTAL_BYTES = TOTAL_GB * 1024 * 1024 * 1024
    expire_ts = get_month_expire()

    subscription_info = f"upload=0; download=0; total={TOTAL_BYTES}; expire={expire_ts}"

    header = f"""#profile-title: 🚀 GRAY VPN [Тариф: Для Близких]
#profile-update-interval: 60
#profile-web-page-url: https://grayvpn.ru
#profile-icon-url: https://grayvpn.ru/logo.png
#subscription-userinfo: {subscription_info}

"""

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for n in final:
            base = n.link.split("#")[0]
            name = f"{n.country} | {int(n.score)}ms"
            f.write(f"{base}#{name}\n")

    print("DONE. Nodes:", len(final))


if __name__ == "__main__":
    asyncio.run(main())
