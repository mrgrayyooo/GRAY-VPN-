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
from ipaddress import ip_address, IPv6Address
from typing import List, Optional, Tuple
import subprocess

# ------------------ Конфигурация ------------------
OUTPUT_FILE = "best_nodes.txt"
XRAY_PATH = "./core/xray"
MAX_CHECK = 6000                # максимум ссылок для проверки
FINAL_LIMIT = 30                 # сколько лучших оставить
CONCURRENCY = 40                 # параллельных проверок
SPEED_LIMIT = float(os.getenv("SPEED_LIMIT", 5))   # Мбит/с, читаем из env
TEST_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
IPAPI_BATCH_URL = "http://ip-api.com/batch?fields=countryCode"

# Настройка логирования (в GitHub Actions всё попадёт в вывод)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("checker")

# ------------------ Источники (можно вынести в отдельный файл) ------------------
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

# ------------------ Утилиты ------------------
def flag_emoji(cc: str) -> str:
    """Возвращает флаг по двухбуквенному коду страны"""
    if len(cc) != 2:
        return "🏳"
    return chr(127397 + ord(cc[0].upper())) + chr(127397 + ord(cc[1].upper()))

def month_expire() -> int:
    """Unix timestamp первого числа следующего месяца"""
    now = datetime.utcnow()
    m = now.month % 12 + 1
    y = now.year + (now.month == 12)
    return int(datetime(y, m, 1).timestamp())

def is_port_free(port: int) -> bool:
    """Проверяет, свободен ли TCP порт"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False

def get_free_port(start=20000, end=40000) -> int:
    """Возвращает свободный порт в заданном диапазоне"""
    for _ in range(100):
        port = random.randint(start, end)
        if is_port_free(port):
            return port
    raise RuntimeError("Не удалось найти свободный порт")

def normalize_host_port(parsed: urlparse) -> Tuple[str, int]:
    """
    Извлекает хост и порт из parsed URL.
    Поддерживает IPv6 (с квадратными скобками и без).
    """
    # Если есть hostname — используем его (urllib уже разобрал IPv6 правильно)
    host = parsed.hostname
    if not host:
        # редкий случай — берём из netloc
        netloc = parsed.netloc.split('@')[-1]
        # убираем квадратные скобки для IPv6, если они есть
        if netloc.startswith('['):
            host = netloc.split(']')[0][1:]
        else:
            host = netloc.split(':')[0]
    port = parsed.port or 443
    return host, port

def validate_vless_link(link: str) -> Optional[dict]:
    """
    Пытается разобрать VLESS ссылку и вернуть словарь с компонентами.
    Если не получается — возвращает None.
    """
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

# ------------------ Построение конфига Xray ------------------
def build_config(valid_link: dict, local_port: int) -> dict:
    """
    Строит конфиг Xray для переданного валидного компонента ссылки.
    """
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

# ------------------ Загрузка ссылок из источников ------------------
async def load_links(session: aiohttp.ClientSession) -> List[str]:
    """
    Загружает все ссылки из SOURCES, возвращает уникальный список,
    обрезанный до MAX_CHECK.
    """
    all_links = set()
    for url in SOURCES:
        try:
            async with session.get(url, timeout=15) as resp:
                text = await resp.text()
                # Более точная регулярка: vless://uuid@host...
                found = re.findall(r'vless://[a-f0-9-]{36}@[^\s"\'<>]+', text)
                all_links.update(found)
                logger.info(f"Загружено {len(found)} ссылок из {url}")
        except Exception as e:
            logger.warning(f"Ошибка загрузки {url}: {e}")

    links = list(all_links)[:MAX_CHECK]
    logger.info(f"Всего уникальных ссылок: {len(links)}")
    return links

# ------------------ Проверка одной ноды ------------------
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

async def check_node(node: Node, temp_dir: str) -> Optional[Node]:
    """
    Запускает Xray с конфигом ноды, проверяет скорость.
    Возвращает узел, если скорость > SPEED_LIMIT.
    """
    if not node.is_valid:
        return None

    port = get_free_port()
    config = build_config(node.valid, port)

    # Пишем конфиг во временный файл
    fd, cfg_path = tempfile.mkstemp(suffix='.json', dir=temp_dir)
    with os.fdopen(fd, 'w') as f:
        json.dump(config, f)

    # Проверим конфиг через Xray (опционально)
    try:
        check_proc = await asyncio.create_subprocess_exec(
            XRAY_PATH, "check", "-c", cfg_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await check_proc.communicate()
        if check_proc.returncode != 0:
            logger.debug(f"Конфиг невалиден: {node.link[:60]}...")
            return None
    except Exception as e:
        logger.debug(f"Ошибка проверки конфига: {e}")
        # продолжаем, возможно xray не поддерживает check

    # Запускаем Xray
    try:
        proc = await asyncio.create_subprocess_exec(
            XRAY_PATH, "run", "-c", cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )

        # Даём время на инициализацию
        await asyncio.sleep(2)

        if proc.returncode is not None:
            # Процесс уже умер
            return None

        # Тест скорости
        speed = await speed_test(port)
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

        if speed > SPEED_LIMIT:
            node.speed = speed
            return node
        else:
            return None

    except Exception as e:
        logger.debug(f"Ошибка при проверке {node.link[:60]}: {e}")
        return None
    finally:
        # Удаляем временный файл
        try:
            os.unlink(cfg_path)
        except OSError:
            pass

async def speed_test(port: int) -> float:
    """Загружает тестовый файл через SOCKS5 прокси на порту, возвращает скорость в Мбит/с."""
    start = time.time()
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        connector = aiohttp.TCPConnector()
        proxy = f"socks5://127.0.0.1:{port}"
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as sess:
            async with sess.get(TEST_URL, proxy=proxy) as resp:
                await resp.read()
        elapsed = time.time() - start
        # 10 МБ = 80 Мбит, делим на время в секундах, получаем Мбит/с
        return 80 / elapsed
    except Exception:
        return 0.0

# ------------------ Пул воркеров ------------------
async def worker(queue: asyncio.Queue, results: list, temp_dir: str, sem: asyncio.Semaphore):
    """Воркер берёт ноду из очереди и проверяет её."""
    while True:
        node = await queue.get()
        if node is None:
            queue.task_done()
            break
        async with sem:   # ограничиваем параллельные процессы Xray
            result = await check_node(node, temp_dir)
            if result:
                results.append(result)
        queue.task_done()

async def run_checks(nodes: List[Node], temp_dir: str) -> List[Node]:
    """Запускает проверку всех нод через пул воркеров."""
    queue = asyncio.Queue()
    for n in nodes:
        await queue.put(n)

    results = []
    # Семафор для ограничения числа одновременно запущенных Xray (чтобы не упасть по памяти)
    sem = asyncio.Semaphore(CONCURRENCY)

    workers = [asyncio.create_task(worker(queue, results, temp_dir, sem))
               for _ in range(CONCURRENCY)]

    # Добавляем стоп-сигналы
    for _ in workers:
        await queue.put(None)

    await queue.join()
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

    return results

# ------------------ Получение стран для лучших нод (пакетный режим) ------------------
async def fetch_countries_batch(nodes: List[Node], session: aiohttp.ClientSession):
    """
    Определяет страны для списка нод через ip-api.com/batch.
    Заменяет country у каждого узла.
    """
    if not nodes:
        return

    # Собираем уникальные хосты (если хост — IP, оставляем как есть; если домен — надо резолвить)
    # Для простоты будем передавать хосты как есть, ip-api принимает домены и IP.
    hosts = []
    node_by_host = {}
    for n in nodes:
        host = n.valid['host']
        # ip-api не любит IPv6 адреса в квадратных скобках, уберём их
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        hosts.append(host)
        node_by_host.setdefault(host, []).append(n)

    # Удаляем дубликаты хостов
    unique_hosts = list(set(hosts))

    # Разбиваем на батчи по 100 (ограничение ip-api)
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
                        # если неуспешно — остаётся XX
                else:
                    logger.warning(f"ip-api вернул {resp.status}")
        except Exception as e:
            logger.warning(f"Ошибка получения стран: {e}")

        # Небольшая задержка между батчами для соблюдения лимитов
        if i + batch_size < len(unique_hosts):
            await asyncio.sleep(1)

# ------------------ Генерация файла подписки ------------------
async def write_output(nodes: List[Node]):
    """Записывает лучшие ноды в файл подписки."""
    TOTAL_BYTES = 200 * 1024 * 1024 * 1024  # 200 ГБ
    header = f"""#profile-title: 🚀 GRAY VPN [Тариф: 200ГБ в месяц]
#profile-update-interval: 60
#profile-web-page-url: https://grayvpn.ru
#profile-icon-url: https://grayvpn.ru/logo.png
#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={month_expire()}

"""
    async with aiofiles.open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        await f.write(header)
        for n in nodes:
            base = n.link.split('#')[0]   # убираем старое имя
            name = f"{flag_emoji(n.country)} {n.country} [GRAY VPN]"
            await f.write(f"{base}#{name}\n")
    logger.info(f"Записано {len(nodes)} нод в {OUTPUT_FILE}")

# ------------------ Главная функция ------------------
async def main():
    logger.info("=" * 50)
    logger.info("Запуск проверщика VLESS нод")
    logger.info(f"Порог скорости: {SPEED_LIMIT} Мбит/с")

    # Временная директория для конфигов
    with tempfile.TemporaryDirectory(prefix="xray_") as temp_dir:
        logger.info(f"Временная папка: {temp_dir}")

        async with aiohttp.ClientSession() as session:
            # 1. Загрузка ссылок
            raw_links = await load_links(session)
            if not raw_links:
                logger.error("Нет ссылок для проверки")
                return

            # 2. Создаём объекты Node и фильтруем валидные
            nodes = [Node(link) for link in raw_links]
            valid_nodes = [n for n in nodes if n.is_valid]
            logger.info(f"Валидных ссылок: {len(valid_nodes)} / {len(nodes)}")

            if not valid_nodes:
                logger.error("Нет валидных ссылок")
                return

            # 3. Проверка скорости
            logger.info("Начинаем проверку скорости...")
            good_nodes = await run_checks(valid_nodes, temp_dir)
            logger.info(f"Найдено нод со скоростью >{SPEED_LIMIT} Мбит/с: {len(good_nodes)}")

            if not good_nodes:
                logger.warning("Нет нод, удовлетворяющих условию")
                return

            # 4. Сортируем и берём лучшие
            good_nodes.sort(key=lambda x: -x.speed)
            best_nodes = good_nodes[:FINAL_LIMIT]

            # 5. Определяем страны (пакетно)
            logger.info("Определяем страны...")
            await fetch_countries_batch(best_nodes, session)

            # 6. Запись результата
            await write_output(best_nodes)

    logger.info("Работа завершена")

if __name__ == "__main__":
    asyncio.run(main())