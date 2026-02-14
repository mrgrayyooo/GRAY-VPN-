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
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from typing import List, Optional, Tuple

# ------------------ Конфигурация ------------------
OUTPUT_FILE = "best_nodes.txt"
XRAY_PATH = "./core/xray"
MAX_CHECK = 3000
FINAL_LIMIT = 150
CONCURRENCY = 30
SPEED_LIMIT = float(os.getenv("SPEED_LIMIT", 0.3))  # Мбит/с
TEST_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
IPAPI_BATCH_URL = "http://ip-api.com/batch?fields=countryCode"
TCP_PING_TIMEOUT = 3

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("checker")

# ------------------ Источники (ПОЛНЫЙ СПИСОК) ------------------
SOURCES = [
    "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/Splitted-By-Country/PL.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt"
]

# ------------------ Утилиты ------------------
def flag_emoji(cc: str) -> str:
    if len(cc) != 2:
        return "🏳"
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
    """Проверяет работоспособность Xray и выводит версию."""
    try:
        proc = await asyncio.create_subprocess_exec(
            XRAY_PATH, "version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode == 0:
            logger.info(f"Xray version: {stdout.decode().strip()}")
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
        "log": {"loglevel": "warning"},
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
                    logger.warning(f"HTTP {resp.status} для {url}")
                    continue
                text = await resp.text()
                found = re.findall(r'vless://[a-f0-9-]{36}@[^\s"\'<>]+', text)
                all_links.update(found)
                logger.info(f"Загружено {len(found)} ссылок из {url}")
        except Exception as e:
            logger.warning(f"Ошибка загрузки {url}: {e}")

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
    except Exception as e:
        logger.debug(f"Speed test error: {e}")
        return 0.0

async def ping_test(port: int) -> float:
    """Измеряет RTT до google.com через прокси, возвращает время в мс."""
    try:
        from aiohttp_socks import ProxyConnector
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=5)
        start = time.time()
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
            async with sess.head("http://www.google.com") as resp:
                if resp.status == 200:
                    elapsed = (time.time() - start) * 1000  # в миллисекундах
                    return elapsed
                else:
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
            stderr=asyncio.subprocess.PIPE
        )

        await asyncio.sleep(2)

        if proc.returncode is not None:
            _, stderr = await proc.communicate()
            logger.debug(f"Xray died: {stderr.decode()}")
            stats['xray_fail'] += 1
            return None

        # Измеряем пинг
        ping = await ping_test(local_port)
        if ping > 200:
            stats['ping_high'] += 1
            logger.debug(f"High ping: {ping:.0f} ms for {host}:{port}")
        node.ping = ping

        # Измеряем скорость
        speed = await speed_test(local_port)
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

        if speed > SPEED_LIMIT:
            node.speed = speed
            stats['speed_ok'] += 1
            return node
        else:
            stats['speed_low'] += 1
            return None

    except Exception as e:
        logger.debug(f"Ошибка при проверке {node.link[:60]}: {e}")
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
    await asyncio.gather(*workers, return_exceptions=True)

    logger.info(f"Статистика проверки: всего {len(nodes)}")
    logger.info(f"  невалидных: {stats['invalid']}")
    logger.info(f"  TCP fail: {stats['tcp_fail']}, TCP ok: {stats['tcp_ok']}")
    logger.info(f"  Xray fail: {stats['xray_fail']}")
    logger.info(f"  скорость ниже порога: {stats['speed_low']}, выше: {stats['speed_ok']}")
    logger.info(f"  ошибки: {stats['error']}")
    logger.info(f"  пинг >200 мс: {stats['ping_high']}")

    return results

# ------------------ Получение стран ------------------
async def fetch_countries_batch(nodes: List[Node], session: aiohttp.ClientSession):
    if not nodes:
        return

    hosts = []
    node_by_host = {}
    for n in nodes:
        host = n.valid['host']
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        hosts.append(host)
        node_by_host.setdefault(host, []).append(n)

    unique_hosts = list(set(hosts))
    batch_size = 100
    for i in range(0, len(unique_hosts), batch_size):
        batch = unique_hosts[i:i+batch_size]
        try:
            async with session.post(IPAPI_BATCH_URL, json=batch, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        if entry.get('status') == 'success':
                            host = entry.get('query')
                            cc = entry.get('countryCode', 'XX')
                            for node in node_by_host.get(host, []):
                                node.country = cc
                else:
                    logger.warning(f"ip-api вернул {resp.status}")
        except Exception as e:
            logger.warning(f"Ошибка получения стран: {e}")

        if i + batch_size < len(unique_hosts):
            await asyncio.sleep(1)

# ------------------ Запись вывода ------------------
async def write_output(nodes: List[Node]):
    TOTAL_BYTES = 200 * 1024 * 1024 * 1024
    header = f"""#profile-title: 🚀 GRAY VPN [Тариф: 200ГБ в месяц]
#profile-update-interval: 60
#profile-web-page-url: https://grayvpn.ru
#profile-icon-url: https://grayvpn.ru/logo.png
#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={month_expire()}

"""
    async with aiofiles.open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        await f.write(header)
        for n in nodes:
            base = n.link.split('#')[0]
            name = f"{flag_emoji(n.country)} {n.country} [GRAY VPN]"
            await f.write(f"{base}#{name}\n")
    logger.info(f"Записано {len(nodes)} нод в {OUTPUT_FILE}")

# ------------------ Главная ------------------
async def main():
    logger.info("=" * 50)
    logger.info("Запуск проверщика VLESS нод")
    logger.info(f"Порог скорости: {SPEED_LIMIT} Мбит/с")
    logger.info(f"TCP Ping таймаут: {TCP_PING_TIMEOUT} сек")

    if not await check_xray():
        logger.error("Xray не работает, прерываем")
        return

    with tempfile.TemporaryDirectory(prefix="xray_") as temp_dir:
        logger.info(f"Временная папка: {temp_dir}")

        async with aiohttp.ClientSession() as session:
            raw_links = await load_links(session)
            if not raw_links:
                logger.error("Нет ссылок для проверки")
                return

            nodes = [Node(link) for link in raw_links]
            valid_nodes = [n for n in nodes if n.is_valid]
            logger.info(f"Валидных ссылок: {len(valid_nodes)} / {len(nodes)}")

            if not valid_nodes:
                logger.error("Нет валидных ссылок")
                return

            logger.info("Начинаем проверку (TCP Ping + Speedtest + Ping)...")
            good_nodes = await run_checks(valid_nodes, temp_dir)
            logger.info(f"Найдено нод со скоростью >{SPEED_LIMIT} Мбит/с: {len(good_nodes)}")

            good_nodes.sort(key=lambda x: (x.ping, -x.speed))
            best_nodes = good_nodes[:FINAL_LIMIT]

            logger.info("Определяем страны...")
            if best_nodes:
                await fetch_countries_batch(best_nodes, session)
                await write_output(best_nodes)
            else:
                # Если нет нод, запишем только заголовок
                TOTAL_BYTES = 200 * 1024 * 1024 * 1024
                header = f"""#profile-title: 🚀 GRAY VPN [Тариф: 200ГБ в месяц]
#profile-update-interval: 60
#profile-web-page-url: https://grayvpn.ru
#profile-icon-url: https://ibb.co/Dg4KjSfQ
#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={month_expire()}

"""
                async with aiofiles.open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                    await f.write(header)
                logger.info("Записан пустой файл подписки (только заголовок)")

    logger.info("Работа завершена")

if __name__ == "__main__":
    asyncio.run(main())