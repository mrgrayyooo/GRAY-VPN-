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
MAX_CHECK = 3000
FINAL_LIMIT = 10
CONCURRENCY = 15
SPEED_LIMIT = float(os.getenv("SPEED_LIMIT", 0.5))
TEST_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
TCP_PING_TIMEOUT = 3
MMDB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
MMDB_PATH = "Country.mmdb"

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("checker")

# ------------------ Источники ------------------
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt"
]

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

# ------------------ Проверка Xray ------------------
async def check_xray() -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            XRAY_PATH, "version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            logger.info(f"Xray version: {stdout.decode().strip().split()[1]}")
            return True
        else:
            logger.error(f"Xray check failed: {stderr.decode()}")
            return False
    except FileNotFoundError:
        logger.error(f"Xray not found at {XRAY_PATH}")
        return False
    except Exception as e:
        logger.error(f"Xray check error: {e}")
        return False

# ------------------ Построение конфига Xray ------------------
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
        "settings": {
            "vnext": [{
                "address": host,
                "port": port,
                "users": [{
                    "id": uuid,
                    "encryption": "none",
                    "flow": flow if flow else None
                }]
            }]
        },
        "streamSettings": {"network": network}
    }

    if security == "reality":
        outbound["streamSettings"]["security"] = "reality"
        outbound["streamSettings"]["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": "/"
        }
    else:
        outbound["streamSettings"]["security"] = "tls"
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": sni,
            "allowInsecure": True
        }

    if network == "ws":
        outbound["streamSettings"]["wsSettings"] = {
            "path": path,
            "headers": {"Host": sni}
        }
    elif network == "grpc":
        outbound["streamSettings"]["grpcSettings"] = {
            "serviceName": service or "grpc"
        }
    elif network == "tcp":
        outbound["streamSettings"]["tcpSettings"] = {
            "header": {"type": "none"}
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks"
        }],
        "outbounds": [outbound]
    }

# ------------------ Загрузка ссылок ------------------
async def load_links(session: aiohttp.ClientSession) -> List[str]:
    all_links = set()
    logger.info(f"Загружаем ссылки из {len(SOURCES)} источников...")
    for url in SOURCES:
        try:
            async with session.get(url, timeout=15) as resp:
                if resp.status != 200:
                    continue
                text = await resp.text()
                found = re.findall(r'vless://[a-f0-9-]{36}@[^\s"\'<>]+', text)
                all_links.update(found)
        except Exception:
            pass

    links = list(all_links)[:MAX_CHECK]
    logger.info(f"Всего уникальных ссылок: {len(links)}")
    return links

# ------------------ Класс Node ------------------
class Node:
    __slots__ = ('link', 'valid', 'speed', 'country', 'ping')
    def __init__(self, link: str):
        self.link = link
        self.valid = validate_vless_link(link)
        self.speed = 0.0
        self.ping = 9999
        self.country = "XX"

    @property
    def is_valid(self) -> bool:
        return self.valid is not None

# ------------------ Speed test ------------------
async def speed_test(port: int) -> float:
    start = time.time()
    try:
        from aiohttp_socks import ProxyConnector
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
            async with sess.get(TEST_URL) as resp:
                await resp.read()
        elapsed = time.time() - start
        return 80 / elapsed
    except Exception:
        return 0.0

async def ping_test(port: int) -> float:
    try:
        from aiohttp_socks import ProxyConnector
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=5)
        start = time.time()
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
            async with sess.head("http://www.google.com") as resp:
                if resp.status == 200:
                    return (time.time() - start) * 1000
                return 9999
    except Exception:
        return 9999

# ------------------ Проверка одной ноды ------------------
async def check_node(node: Node, temp_dir: str, stats: dict) -> Optional[Node]:
    if not node.is_valid:
        stats['invalid'] += 1
        return None

    host = node.valid['host']
    port = node.valid['port']

    if not await tcp_ping(host, port):
        stats['tcp_fail'] += 1
        return None
    stats['tcp_ok'] += 1

    local_port = get_free_port()
    config = build_config(node.valid, local_port)

    fd, cfg_path = tempfile.mkstemp(suffix='.json', dir=temp_dir)
    with os.fdopen(fd, 'w') as f:
        json.dump(config, f)

    try:
        proc = await asyncio.create_subprocess_exec(
            XRAY_PATH, "run", "-c", cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )

        await asyncio.sleep(2)

        if proc.returncode is not None:
            stats['xray_fail'] += 1
            return None

        ping = await ping_test(local_port)
        if ping > 500: # Пинг более строгий
            stats['ping_high'] += 1
            node.ping = ping
        else:
             node.ping = ping
             
        # Тестируем скорость только если пинг адекватный
        if ping < 9999:
            speed = await speed_test(local_port)
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                proc.kill()
            
            if speed > SPEED_LIMIT:
                node.speed = speed
                stats['speed_ok'] += 1
                return node
            else:
                stats['speed_low'] += 1
                return None
        else:
            proc.terminate()
            return None

    except Exception:
        stats['error'] += 1
        return None
    finally:
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

# ------------------ Пул воркеров ------------------
async def worker(queue: asyncio.Queue, results: list, temp_dir: str, sem: asyncio.Semaphore, stats: dict):
    while True:
        node = await queue.get()
        if node is None:
            queue.task_done()
            break
        async with sem:
            result = await check_node(node, temp_dir, stats)
            if result:
                results.append(result)
        queue.task_done()

async def run_checks(nodes: List[Node], temp_dir: str) -> List[Node]:
    queue = asyncio.Queue()
    for n in nodes:
        await queue.put(n)

    results = []
    sem = asyncio.Semaphore(CONCURRENCY)
    stats = {'invalid': 0, 'tcp_fail': 0, 'tcp_ok': 0, 'xray_fail': 0, 'speed_low': 0, 'speed_ok': 0, 'error': 0, 'ping_high': 0}

    workers = [asyncio.create_task(worker(queue, results, temp_dir, sem, stats))
               for _ in range(CONCURRENCY)]

    for _ in workers:
        await queue.put(None)

    await queue.join()
    for w in workers:
        w.cancel()
    
    logger.info(f"Статистика: TCP OK: {stats['tcp_ok']}, Скорость OK: {stats['speed_ok']}")
    return results

# ------------------ Определение стран (GEOIP2) ------------------
async def ensure_mmdb(session: aiohttp.ClientSession):
    if os.path.exists(MMDB_PATH):
        return
    logger.info("Скачиваем базу GeoLite2-Country...")
    try:
        async with session.get(MMDB_URL) as resp:
            if resp.status == 200:
                async with aiofiles.open(MMDB_PATH, 'wb') as f:
                    await f.write(await resp.read())
                logger.info("База успешно скачана")
    except Exception as e:
        logger.error(f"Ошибка скачивания базы: {e}")

def resolve_country(nodes: List[Node]):
    if not os.path.exists(MMDB_PATH):
        logger.error("База GeoIP не найдена")
        return

    logger.info("Определяем страны через локальную базу...")
    try:
        with geoip2.database.Reader(MMDB_PATH) as reader:
            for node in nodes:
                try:
                    host = node.valid['host']
                    # Если host это домен, резолвим его (синхронно, но быстро)
                    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                         try:
                             ip = socket.gethostbyname(host)
                         except:
                             ip = host # Если не удалось, пробуем как есть
                    else:
                        ip = host
                    
                    response = reader.country(ip)
                    cc = response.country.iso_code
                    if cc:
                        node.country = cc
                except Exception:
                    continue 
    except Exception as e:
        logger.error(f"Ошибка при чтении базы GeoIP: {e}")

# ------------------ Запись вывода ------------------
async def write_output(nodes: List[Node]):
    TOTAL_BYTES = 200 * 1024 * 1024 * 1024
    header = f"""#profile-title: 🚀 GRAY VPN [Тариф: 200ГБ в месяц]
#profile-update-interval: 60
#profile-web-page-url: https://grayvpn.ru
#profile-icon-url: https://ibb.co/Dg4KjSfQ
#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={month_expire()}

"""
    async with aiofiles.open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        await f.write(header)
        for n in nodes:
            # Формируем имя: 🇱🇹 LT [GRAY VPN]
            flag = flag_emoji(n.country)
            name = f"{flag} {n.country} [GRAY VPN]"
            
            # Удаляем фрагмент (часть после #) из оригинальной ссылки и добавляем новый
            base_link = n.link.split('#')[0]
            await f.write(f"{base_link}#{name}\n")
            
    logger.info(f"Записано {len(nodes)} нод в {OUTPUT_FILE}")

# ------------------ Главная ------------------
async def main():
    logger.info("=" * 50)
    logger.info("🚀 START CHEKING...")

    if not await check_xray():
        return

    with tempfile.TemporaryDirectory(prefix="xray_") as temp_dir:
        async with aiohttp.ClientSession() as session:
            # 1. Скачиваем базу стран
            await ensure_mmdb(session)
            
            # 2. Грузим ссылки
            raw_links = await load_links(session)
            nodes = [Node(link) for link in raw_links if validate_vless_link(link)]
            
            if not nodes:
                logger.error("Нет ссылок")
                return

            # 3. Чекаем
            logger.info(f"Проверка {len(nodes)} нод...")
            good_nodes = await run_checks(nodes, temp_dir)
            
            # 4. Сортируем и режем
            good_nodes.sort(key=lambda x: (x.ping, -x.speed))
            best_nodes = good_nodes[:FINAL_LIMIT]

            # 5. Ставим флаги (ЛОКАЛЬНО)
            if best_nodes:
                resolve_country(best_nodes)
                await write_output(best_nodes)
            else:
                 logger.warning("Нет рабочих нод")
                 # Можно записать пустой файл или оставить старый

    logger.info("✅ DONE")

if __name__ == "__main__":
    asyncio.run(main())