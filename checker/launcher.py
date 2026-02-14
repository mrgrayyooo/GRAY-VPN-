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
MAX_CHECK = 6000
FINAL_LIMIT = 30
CONCURRENCY = 20  # уменьшим для стабильности
SPEED_LIMIT = float(os.getenv("SPEED_LIMIT", 1.0))  # временно 1 Мбит/с
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

# ------------------ Источники (без изменений) ------------------
SOURCES = SOURCES = [
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
]  # оставь как есть

# ------------------ Утилиты (без изменений) ------------------
def flag_emoji(cc: str) -> str:
    ...

def month_expire() -> int:
    ...

def is_port_free(port: int) -> bool:
    ...

def get_free_port(start=20000, end=40000) -> int:
    ...

def normalize_host_port(parsed: urlparse) -> Tuple[str, int]:
    ...

def validate_vless_link(link: str) -> Optional[dict]:
    ...

# ------------------ TCP Ping ------------------
async def tcp_ping(host: str, port: int, timeout: float = TCP_PING_TIMEOUT) -> bool:
    try:
        await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        return True
    except Exception:
        return False

# ------------------ Проверка Xray ------------------
async def check_xray() -> bool:
    """Проверяет, что Xray работает и выводит версию."""
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
    ...  # без изменений

# ------------------ Загрузка ссылок ------------------
async def load_links(session: aiohttp.ClientSession) -> List[str]:
    ...  # без изменений

# ------------------ Класс Node ------------------
class Node:
    __slots__ = ('link', 'valid', 'speed', 'country')
    def __init__(self, link: str):
        self.link = link
        self.valid = validate_vless_link(link)
        self.speed = 0.0
        self.country = "XX"

    @property
    def is_valid(self) -> bool:
        return self.valid is not None

# ------------------ Speed test с aiohttp_socks ------------------
async def speed_test(port: int) -> float:
    """Загружает тестовый файл через SOCKS5 прокси, возвращает скорость в Мбит/с."""
    start = time.time()
    try:
        # Используем aiohttp_socks для поддержки socks5
        from aiohttp_socks import ProxyConnector
        connector = ProxyConnector.from_url(f"socks5://127.0.0.1:{port}")
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
            async with sess.get(TEST_URL) as resp:
                await resp.read()
        elapsed = time.time() - start
        speed = 80 / elapsed  # 10 MB = 80 Mbit
        return speed
    except Exception as e:
        logger.debug(f"Speed test error: {e}")
        return 0.0

# ------------------ Проверка одной ноды ------------------
async def check_node(node: Node, temp_dir: str, stats: dict) -> Optional[Node]:
    if not node.is_valid:
        stats['invalid'] += 1
        return None

    host = node.valid['host']
    port = node.valid['port']

    # TCP Ping
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
        # Запускаем Xray с выводом ошибок (перенаправим stderr в PIPE для логирования)
        proc = await asyncio.create_subprocess_exec(
            XRAY_PATH, "run", "-c", cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE
        )

        await asyncio.sleep(2)

        if proc.returncode is not None:
            # Процесс сразу умер — читаем stderr
            _, stderr = await proc.communicate()
            logger.debug(f"Xray died: {stderr.decode()}")
            stats['xray_fail'] += 1
            return None

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
    stats = {'invalid': 0, 'tcp_fail': 0, 'tcp_ok': 0, 'xray_fail': 0, 'speed_low': 0, 'speed_ok': 0, 'error': 0}

    workers = [asyncio.create_task(worker(queue, results, temp_dir, sem, stats))
               for _ in range(CONCURRENCY)]

    for _ in workers:
        await queue.put(None)

    await queue.join()
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    # Выводим статистику
    logger.info(f"Статистика проверки: всего {len(nodes)}")
    logger.info(f"  невалидных: {stats['invalid']}")
    logger.info(f"  TCP fail: {stats['tcp_fail']}, TCP ok: {stats['tcp_ok']}")
    logger.info(f"  Xray fail: {stats['xray_fail']}")
    logger.info(f"  скорость ниже порога: {stats['speed_low']}, выше: {stats['speed_ok']}")
    logger.info(f"  ошибки: {stats['error']}")

    return results

# ------------------ Получение стран ------------------
async def fetch_countries_batch(nodes: List[Node], session: aiohttp.ClientSession):
    ...  # без изменений

# ------------------ Запись вывода ------------------
async def write_output(nodes: List[Node]):
    ...  # без изменений

# ------------------ Главная ------------------
async def main():
    logger.info("=" * 50)
    logger.info("Запуск проверщика VLESS нод")
    logger.info(f"Порог скорости: {SPEED_LIMIT} Мбит/с")
    logger.info(f"TCP Ping таймаут: {TCP_PING_TIMEOUT} сек")

    # Проверим Xray
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

            logger.info("Начинаем проверку (TCP Ping + Speedtest)...")
            good_nodes = await run_checks(valid_nodes, temp_dir)
            logger.info(f"Найдено нод со скоростью >{SPEED_LIMIT} Мбит/с: {len(good_nodes)}")

            if not good_nodes:
                logger.warning("Нет нод, удовлетворяющих условию")
                # Создадим пустой файл (чтобы коммит не было изменений, но можно оставить как есть)
                # return

            good_nodes.sort(key=lambda x: -x.speed)
            best_nodes = good_nodes[:FINAL_LIMIT]

            logger.info("Определяем страны...")
            if best_nodes:
                await fetch_countries_batch(best_nodes, session)
                await write_output(best_nodes)
            else:
                # Если нет нод, запишем только заголовок (или ничего)
                async with aiofiles.open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                    TOTAL_BYTES = 200 * 1024 * 1024 * 1024
                    header = f"""#profile-title: 🚀 GRAY VPN [Тариф: 200ГБ в месяц]
#profile-update-interval: 60
#profile-web-page-url: https://grayvpn.ru
#profile-icon-url: https://grayvpn.ru/logo.png
#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={month_expire()}

"""
                    await f.write(header)
                logger.info("Записан пустой файл подписки (только заголовок)")

    logger.info("Работа завершена")

if __name__ == "__main__":
    asyncio.run(main())