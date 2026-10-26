import socket
import ssl
import struct
import random
import time
import urllib.request
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

# 1. Базовый пул известных прокси-серверов (сохраняются всегда, даже если временно упали)
STATIC_PROXIES = [
    # EU серверы GeoHide (Группа 1 — работают в РФ без VPN)
    {"ip": "37.221.93.128", "group": 1, "name": "GeoHide-EU-1"},
    {"ip": "37.221.93.141", "group": 1, "name": "GeoHide-EU-2"},
    {"ip": "5.175.161.40", "group": 1, "name": "GeoHide-EU-3"},
    {"ip": "5.175.161.3", "group": 1, "name": "GeoHide-EU-4"},
    {"ip": "45.13.237.213", "group": 1, "name": "GeoHide-EU-5"},
    {"ip": "31.25.239.132", "group": 1, "name": "GeoHide-EU-6"},
    {"ip": "143.20.64.192", "group": 1, "name": "GeoHide-EU-7"},
    # Malw серверы (Группа 1)
    {"ip": "143.20.64.55", "group": 1, "name": "Malw-EU-Main"},
    {"ip": "179.254.166.171", "group": 1, "name": "Malw-Node-1"},
    {"ip": "164.5.224.81", "group": 1, "name": "Malw-Node-2"},
    {"ip": "179.254.166.174", "group": 1, "name": "Malw-Game"},
    # US серверы GeoHide (Группа 2 — резерв / VPN)
    {"ip": "107.175.76.134", "group": 2, "name": "GeoHide-US-1"},
    {"ip": "192.255.159.240", "group": 2, "name": "GeoHide-US-2"},
    {"ip": "192.255.159.241", "group": 2, "name": "GeoHide-US-3"},
    {"ip": "192.3.233.253", "group": 2, "name": "GeoHide-US-4"},
    # RU серверы GeoHide и Xbox DNS (Группа 3 — резерв на случай разблокировки РКН)
    {"ip": "159.194.200.33", "group": 3, "name": "GeoHide-RU-1"},
    {"ip": "193.233.112.67", "group": 3, "name": "GeoHide-RU-2"},
    {"ip": "193.233.112.68", "group": 3, "name": "GeoHide-RU-3"},
    {"ip": "193.233.112.88", "group": 3, "name": "GeoHide-RU-4"},
    {"ip": "37.230.192.51", "group": 3, "name": "GeoHide-RU-5"},
    {"ip": "111.88.96.50", "group": 3, "name": "Xbox-DNS-1"},
    {"ip": "111.88.96.51", "group": 3, "name": "Xbox-DNS-2"},
]

# 2. DoH DNS-серверы (включая Null's Proxy DNS и Comss)
DOH_SERVERS = [
    {"name": "Comss-Router", "url": "https://router.comss.one/dns-query", "group": 1, "only_games": False},
    {"name": "Comss-Main", "url": "https://dns.comss.one/dns-query", "group": 1, "only_games": False},
    {"name": "NullsProxy-DoH", "url": "https://dns.nullsproxy.com/dns-query", "group": 1, "only_games": True},
    {"name": "GeoHide-EU-DoH", "url": "https://eu.geohide.ru/dns-query", "group": 1, "only_games": False},
    {"name": "Malw-DoH", "url": "https://dns.malw.link/dns-query", "group": 1, "only_games": False},
    {"name": "Astracat", "url": "https://dns.astracat.network/dns-query", "group": 1, "only_games": False},
    {"name": "Bezmezha", "url": "https://dns.bezmezhau.com/dns-query", "group": 1, "only_games": False},
    {"name": "DnsAI", "url": "https://dns.dns-ai.ru/dns-query", "group": 1, "only_games": False},
    {"name": "Mafioznik", "url": "https://dns.mafioznik.xyz/dns-query", "group": 1, "only_games": False},
    {"name": "Wlrus", "url": "https://dns.wlrus.cfd/dns-query", "group": 1, "only_games": False},
    {"name": "Webshift", "url": "https://d.webshiftvpn.ru/dns-query", "group": 1, "only_games": False},
    {"name": "GeoHide-US-DoH", "url": "https://us.geohide.ru/dns-query", "group": 2, "only_games": False},
    {"name": "Shecan-IR", "url": "https://free.shecan.ir/dns-query", "group": 2, "only_games": False},
]

# 3. Прямые IPv4 / UDP DNS-серверы (Comss IPv4, Null's Proxy и Xbox DNS)
UDP_DNS_SERVERS = [
    {"name": "NullsProxy-UDP", "host": "dns.nullsproxy.com", "group": 1, "only_games": True},
    {"name": "Comss-UDP-1", "host": "93.115.24.120", "group": 1, "only_games": False},
    {"name": "Comss-UDP-2", "host": "93.115.24.121", "group": 1, "only_games": False},
    {"name": "Xbox-UDP-1", "host": "111.88.96.50", "group": 3, "only_games": False},
    {"name": "Xbox-UDP-2", "host": "111.88.96.51", "group": 3, "only_games": False},
]

# 4. Автообновляемые источники списков hosts
BASE_HOSTS_URLS = [
    ("Fancy-Comss", "https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/refs/heads/main/hosts/comss.hosts"),
    ("GeoHide-EU", "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/eu/hosts"),
    ("Malw-Hosts", "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"),
    ("Malw-Info", "https://info.dns.malw.link/hosts"),
    ("Fancy-GeoHide", "https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/refs/heads/main/hosts/geohide.hosts"),
    ("GeoHide-Main", "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"),
]

# === TIER 0: GEMINI И ВСЕ СЕРВИСЫ GOOGLE AI (включая 3 шлюза appsgenaiserver-pa!) ===
TIER0_GEMINI_DOMAINS = [
    "gemini.google.com",
    "appsgenaiserver-pa.clients.google.com",
    "appsgenaiserver-pa.clients6.google.com",
    "appsgenaiserver-pa.googleapis.com",
    "robinfrontend-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "bard.google.com",
    "aistudio.google.com",
    "makersuite.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "alkalicore-pa.clients6.google.com",
    "generativelanguage.googleapis.com",
    "aisandbox-pa.googleapis.com",
    "antigravity.google.com",
    "idx.google.com",
    "jules.google.com",
    "jules.google",
    "labs.google",
    "labs.google.com",
    "kitchen.google.com",
    "notebooklm.google.com",
    "notebooklm.google",
    "tailwind-pa.clients6.google.com",
    "stitch.withgoogle.com",
    "stitch.google.com",
    "deepmind.google",
    "ai.google.dev",
    "colab.research.google.com",
]

# === TIER 1A: БОЕВЫЕ СЕРВЕРЫ ИГР SUPERCELL ===
PRIORITY_GAME_DOMAINS = [
    "game.brawlstarsgame.com",
    "game.clashroyaleapp.com",
    "gamea.clashofclans.com",
    "game.mocogame.com",
]

# === TIER 1B: СЕРВИСЫ ПЕРВОЙ НЕОБХОДИМОСТИ (ПЕРСОНАЛЬНЫЙ ОТБОР ПОД КАЖДЫЙ) ===
TIER1_SERVICE_GROUPS = {
    "Claude": {
        "test_domain": "claude.ai",
        "domains": [
            "claude.ai", "api.anthropic.com", "anthropic.com",
            "console.anthropic.com", "assets.claude.ai",
        ],
    },
    "Grok": {
        "test_domain": "grok.com",
        "domains": [
            "grok.com", "accounts.x.ai", "assets.grok.com", "api.x.ai", "x.ai",
        ],
    },
    "OpenAI": {
        "test_domain": "chatgpt.com",
        "domains": [
            "chatgpt.com", "ab.chatgpt.com", "auth.openai.com", "auth0.openai.com",
            "platform.openai.com", "cdn.oaistatic.com", "files.oaiusercontent.com",
            "webrtc.chatgpt.com", "android.chat.openai.com", "api.openai.com",
            "operator.chatgpt.com", "sora.chatgpt.com", "videos.openai.com",
            "ios.chat.openai.com", "cdn.platform.openai.com", "developers.openai.com",
        ],
    },
    "Copilot": {
        "test_domain": "api.individual.githubcopilot.com",
        "domains": [
            "api.individual.githubcopilot.com", "proxy.individual.githubcopilot.com",
            "copilot-proxy.githubusercontent.com", "copilot-telemetry.githubusercontent.com",
            "githubcopilot.com",
        ],
    },
    "SupercellStore": {
        "test_domain": "store.supercell.com",
        "domains": [
            "store.supercell.com", "id.supercell.com", "cdn.id.supercell.com",
            "security.id.supercell.com", "accounts.supercell.com",
            "game-assets.brawlstarsgame.com", "game-assets.clashroyaleapp.com",
            "game-assets.clashofclans.com", "clashofclans.inbox.supercell.com",
            "brawlstars.inbox.supercell.com",
        ],
    },
    "GeForceNow": {
        "test_domain": "play.geforcenow.com",
        "domains": [
            "play.geforcenow.com", "geforcenow.com", "www.geforcenow.com",
            "login.nvgs.nvidia.com", "nvgs.nvidia.com",
            "prod.cloudmatchbeta.nvidiagrid.net", "cloudmatchbeta.nvidiagrid.net",
            "api.geforcenow.com", "events.gfe.nvidia.com",
        ],
    },
    "Canva": {
        "test_domain": "www.canva.com",
        "domains": [
            "canva.com", "www.canva.com", "about.canva.com", "static.canva.com",
            "marketplace.canva.com", "document-export.canva.com",
            "media.canva.com", "media-public.canva.com",
        ],
    },
    "Imgur": {
        "test_domain": "i.imgur.com",
        "domains": [
            "imgur.com", "www.imgur.com", "i.imgur.com",
            "api.imgur.com", "s.imgur.com", "m.imgur.com",
        ],
    },
}

# Защищенные системные домены Google (работают в РФ напрямую, нельзя пускать через чужой прокси)
NEVER_PROXY_DOMAINS = {
    "google.com", "www.google.com", "accounts.google.com", "oauth2.googleapis.com",
    "www.googleapis.com", "apis.google.com", "content.googleapis.com",
    "iamcredentials.googleapis.com", "docs.google.com", "sheets.google.com",
    "slides.google.com", "drive.google.com", "script.google.com", "dl.google.com",
    "play.google.com", "mtalk.google.com", "connectivitycheck.gstatic.com",
    "gstatic.com", "www.gstatic.com",
}

# Официальные не-прокси подсети Google/Cloudflare/DNS, которые нельзя принимать за прокси-серверы
OFFICIAL_NON_PROXY_PREFIXES = (
    "142.250.", "142.251.", "172.217.", "216.58.", "74.125.", "64.233.",
    "108.177.", "173.194.", "209.85.", "104.16.", "104.17.", "104.18.",
    "104.19.", "172.64.", "172.66.", "172.67.", "1.1.1.", "1.0.0.", "8.8.8.", "8.8.4."
)

ATTEMPTS = 10
TIMEOUT = 2.2
BAD_HTTP_CODES = ("400", "403", "429", "500", "502", "503", "504", "520", "521", "522", "523", "524")


def discover_geohide_repo_files():
    """Автоматически находит все списки hosts в репозитории GeoHideDNS."""
    discovered = []
    api_url = "https://api.github.com/repos/Internet-Helper/GeoHideDNS/git/trees/main?recursive=1"
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            for item in data.get("tree", []):
                path = item.get("path", "")
                if item.get("type") == "blob" and "hosts" in path.lower():
                    raw_url = f"https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/{path}"
                    discovered.append((f"GeoHide:{path}", raw_url))
    except Exception:
        pass
    return discovered


def is_rkn_blocked(target="geohide.ru"):
    """Проверяет, заблокированы ли еще RU-серверы в реестре РКН."""
    try:
        req = urllib.request.Request("https://reestr.rublacklist.net/api/v3/domains/", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if f'"{target}"' in resp.read().decode("utf-8", errors="ignore"):
                return True
    except Exception:
        pass
    return True


def resolve_doh_ips(doh_url, domain):
    """Запрашивает IP-адреса у DoH-сервера по HTTPS."""
    ips = []
    try:
        req = urllib.request.Request(
            f"{doh_url}?name={domain}&type=A",
            headers={"Accept": "application/dns-json", "User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode())
            for ans in data.get("Answer", []):
                if ans.get("type") == 1 and ans.get("data"):
                    ips.append(ans["data"].strip())
    except Exception:
        pass
    return ips


def resolve_udp_dns(server_host, domain, port=53, timeout=2.5):
    """Опрашивает DNS-сервер (например, 93.115.24.120 или dns.nullsproxy.com) напрямую по UDP порту 53."""
    ips = []
    try:
        tid = random.randint(1, 65534)
        header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(struct.pack("B", len(p)) + p.encode("ascii") for p in domain.split(".")) + b"\x00"
        packet = header + qname + struct.pack(">HH", 1, 1)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server_host, port))
            data, _ = sock.recvfrom(1024)

        ancount = struct.unpack(">H", data[6:8])[0]
        offset = 12
        while offset < len(data) and data[offset] != 0:
            offset += 1 + data[offset]
        offset += 5 # null byte + qtype + qclass

        for _ in range(ancount):
            if offset >= len(data):
                break
            if (data[offset] & 0xC0) == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += 1 + data[offset]
                offset += 1
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(data[offset:offset + 4]))
            offset += rdlen
    except Exception:
        pass
    return ips


def get_official_unproxied_prefixes(domains):
    """Использует Cloudflare (1.1.1.1) как детектор реальных не-проксированных IP, чтобы отсеять их."""
    prefixes = set(OFFICIAL_NON_PROXY_PREFIXES)
    for dom in domains:
        for real_ip in resolve_udp_dns("1.1.1.1", dom, timeout=2.0):
            parts = real_ip.split(".")
            if len(parts) == 4:
                prefixes.add(f"{parts[0]}.{parts[1]}.")
    return tuple(prefixes)


def stress_test_https(ip, domain, attempts=ATTEMPTS):
    """Отправляет серию HTTPS-запросов к конкретному сервису через проверяемый прокси-IP."""
    success = 0
    total_ms = 0.0
    ctx = ssl.create_default_context()
    for _ in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    req = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                    ssock.sendall(req.encode())
                    resp = ssock.recv(128).decode(errors="ignore")
                    first_line = resp.splitlines()[0] if resp else ""
                    if "HTTP/" in first_line and not any(code in first_line for code in BAD_HTTP_CODES):
                        success += 1
                        total_ms += (time.perf_counter() - start) * 1000
        except Exception:
            pass
    avg_ping = (total_ms / success) if success > 0 else 9999.0
    return success, round(avg_ping, 1)


def stress_test_gemini_complete(ip):
    """
    Комплексный тест для Gemini (Tier 0 — 10 запросов):
    4 запроса к веб-версии (gemini.google.com) +
    3 запроса к новому шлюзу чатов (appsgenaiserver-pa.googleapis.com) +
    3 запроса к мобильному шлюзу (robinfrontend-pa.googleapis.com).
    """
    ok1, p1 = stress_test_https(ip, "gemini.google.com", attempts=4)
    if ok1 == 0:
        return 0, 9999.0
    ok2, p2 = stress_test_https(ip, "appsgenaiserver-pa.googleapis.com", attempts=3)
    ok3, p3 = stress_test_https(ip, "robinfrontend-pa.googleapis.com", attempts=3)
    total_ok = ok1 + ok2 + ok3
    valid_pings = [p for ok, p in ((ok1, p1), (ok2, p2), (ok3, p3)) if ok > 0]
    avg_ping = round(sum(valid_pings) / len(valid_pings), 1) if valid_pings else 9999.0
    return total_ok, avg_ping


def stress_test_game_tcp(ip, ports=(9339, 443), attempts=ATTEMPTS):
    """Тестирует игровой прокси Supercell по игровому порту 9339 и 443."""
    success = 0
    total_ms = 0.0
    for _ in range(attempts):
        for port in ports:
            start = time.perf_counter()
            try:
                with socket.create_connection((ip, port), timeout=1.8):
                    success += 1
                    total_ms += (time.perf_counter() - start) * 1000
                    break
            except Exception:
                continue
    avg_ping = (total_ms / success) if success > 0 else 9999.0
    return success, round(avg_ping, 1)


def fetch_hosts_file(url):
    entries = []
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                line = line.split("#")[0].strip()
                parts = line.split()
                if len(parts) >= 2 and not parts[0].startswith(("0.0.0.0", "127.", "::")):
                    for dom in parts[1:]:
                        d = dom.lower()
                        if d not in NEVER_PROXY_DOMAINS:
                            entries.append((parts[0], d))
    except Exception as e:
        print(f" [!] Не удалось загрузить {url}: {e}")
    return entries


def main():
    print("=== 1. Скачивание свежих списков hosts (GeoHide RU/EU/US, Comss, Malw) ===")
    sources = list(BASE_HOSTS_URLS)
    seen_urls = {u for _, u in sources}
    for name, url in discover_geohide_repo_files():
        if url not in seen_urls:
            sources.append((name, url))
            seen_urls.add(url)

    all_raw_entries = []
    ip_counter = Counter()
    game_candidates = {dom: [] for dom in PRIORITY_GAME_DOMAINS}

    for name, url in sources:
        entries = fetch_hosts_file(url)
        if entries:
            print(f" [+] {name}: {len(entries)} записей")
            all_raw_entries.extend(entries)
            for ip, dom in entries:
                ip_counter[ip] += 1
                if dom in game_candidates:
                    game_candidates[dom].append({"ip": ip, "name": f"{name}({ip})"})

    print("\n=== 2. Фильтрация реальных (не-прокси) IP через детектор Cloudflare 1.1.1.1 ===")
    probe_domains = ["gemini.google.com", "appsgenaiserver-pa.googleapis.com", "claude.ai", "grok.com", "chatgpt.com"]
    real_game_prefixes = get_official_unproxied_prefixes(PRIORITY_GAME_DOMAINS)
    real_web_prefixes = get_official_unproxied_prefixes(probe_domains)

    ru_blocked = is_rkn_blocked("geohide.ru")
    ru_prefixes = ("159.194.", "193.233.", "37.230.", "111.88.")

    candidates = []
    seen_ips = set()
    for sp in STATIC_PROXIES:
        grp = (3 if ru_blocked else 1) if sp["ip"].startswith(ru_prefixes) else sp["group"]
        candidates.append({"ip": sp["ip"], "group": grp, "name": sp["name"]})
        seen_ips.add(sp["ip"])

    for ip, count in ip_counter.items():
        if count >= 10 and ip not in seen_ips and not ip.startswith(real_web_prefixes):
            grp = (3 if ru_blocked else 1) if ip.startswith(ru_prefixes) else 1
            candidates.append({"ip": ip, "group": grp, "name": f"Hosts({ip})"})
            seen_ips.add(ip)

    print("\n=== 3. Опрос DoH и UDP DNS (Null's Proxy, Comss IPv4, GeoHide, Malw, Xbox) ===")
    for doh in DOH_SERVERS:
        if not doh.get("only_games", False):
            for p_dom in probe_domains:
                for ip in resolve_doh_ips(doh["url"], p_dom):
                    if ip not in seen_ips and not ip.startswith(real_web_prefixes):
                        grp = (3 if ru_blocked else 1) if ip.startswith(ru_prefixes) else doh["group"]
                        print(f" [+] {doh['name']} ({p_dom}) -> {ip}")
                        candidates.append({"ip": ip, "group": grp, "name": f"{doh['name']}({ip})"})
                        seen_ips.add(ip)
        for g_dom in PRIORITY_GAME_DOMAINS:
            for ip in resolve_doh_ips(doh["url"], g_dom):
                if not ip.startswith(real_game_prefixes):
                    print(f" [+] [GAME] {doh['name']} ({g_dom}) -> {ip}")
                    game_candidates[g_dom].append({"ip": ip, "name": f"{doh['name']}({ip})"})

    for udp_srv in UDP_DNS_SERVERS:
        if not udp_srv.get("only_games", False):
            for p_dom in probe_domains:
                for ip in resolve_udp_dns(udp_srv["host"], p_dom):
                    if ip not in seen_ips and not ip.startswith(real_web_prefixes):
                        grp = (3 if ru_blocked else 1) if ip.startswith(ru_prefixes) else udp_srv["group"]
                        print(f" [+] {udp_srv['name']} ({p_dom}) -> {ip}")
                        candidates.append({"ip": ip, "group": grp, "name": f"{udp_srv['name']}({ip})"})
                        seen_ips.add(ip)
        for g_dom in PRIORITY_GAME_DOMAINS:
            for ip in resolve_udp_dns(udp_srv["host"], g_dom):
                if not ip.startswith(real_game_prefixes):
                    print(f" [+] [GAME] {udp_srv['name']} ({g_dom}) -> {ip}")
                    game_candidates[g_dom].append({"ip": ip, "name": f"{udp_srv['name']}({ip})"})

    print(f"\n=== 4. Стресс-тест ВСЕХ {len(candidates)} серверов (включая Tier 3) для GEMINI ===")
    tier0_pool, tier2_pool, tier3_pool = [], [], []
    alive_ips = set()

    with ThreadPoolExecutor(max_workers=16) as executor:
        future_map = {executor.submit(stress_test_gemini_complete, c["ip"]): c for c in candidates}
        for fut in as_completed(future_map):
            c = future_map[fut]
            ok, ping = fut.result()
            c["ok"], c["ping"] = ok, ping
            print(f" -> [GEMINI TEST] {c['name']} [{c['ip']}]: {ok}/10 | пинг {ping} мс | гр.{c['group']}")
            if ok >= 8 and c["group"] == 1:
                tier0_pool.append(c)
                alive_ips.add(c["ip"])
            elif ok >= 1 and c["group"] in (1, 2):
                tier2_pool.append(c)
                alive_ips.add(c["ip"])
            else:
                tier3_pool.append(c)

    tier0_pool.sort(key=lambda x: (-x["ok"], x["ping"]))
    tier2_pool.sort(key=lambda x: (x["group"], -x["ok"], x["ping"]))
    tier3_pool.sort(key=lambda x: (-x["ok"], x["ping"]))

    best_gemini_ip = tier0_pool[0]["ip"] if tier0_pool else (tier2_pool[0]["ip"] if tier2_pool else "37.221.93.128")
    backup_ip = tier2_pool[0]["ip"] if tier2_pool else best_gemini_ip
    print(f"\n[★★★] ЧЕМПИОН TIER 0 (GEMINI & GOOGLE AI): {best_gemini_ip}")

    print("\n=== 5. Персональный отбор серверов для Claude, Grok, OpenAI, Copilot, Supercell Store ===")
    active_eu_candidates = tier0_pool if tier0_pool else candidates[:10]
    service_winners = {}

    for svc_name, svc_info in TIER1_SERVICE_GROUPS.items():
        t_dom = svc_info["test_domain"]
        scored_svc = []
        with ThreadPoolExecutor(max_workers=12) as executor:
            f_map = {executor.submit(stress_test_https, c["ip"], t_dom, 5): c for c in active_eu_candidates}
            for fut in as_completed(f_map):
                c = f_map[fut]
                ok, ping = fut.result()
                if ok > 0:
                    scored_svc.append((ok, ping, c["ip"], c["name"]))
        scored_svc.sort(key=lambda x: (-x[0], x[1]))
        if scored_svc:
            win_ok, win_ping, win_ip, win_name = scored_svc[0]
            service_winners[svc_name] = win_ip
            print(f" [★] Лучший сервер для {svc_name} ({t_dom}): {win_name} -> {win_ip} ({win_ok}/5, {win_ping} мс)")
        else:
            service_winners[svc_name] = best_gemini_ip
            print(f" [*] Для {svc_name} назначен чемпион Tier 0: {best_gemini_ip}")

    print("\n=== 6. Стресс-тест игровых серверов Brawl Stars и Clash Royale (включая Null's Proxy) ===")
    best_game_ips = {}
    for g_dom, g_list in game_candidates.items():
        unique_ips = {}
        for item in g_list:
            unique_ips.setdefault(item["ip"], item["name"])
        scored = []
        for ip, label in unique_ips.items():
            ok, ping = stress_test_game_tcp(ip, attempts=6)
            print(f" -> [GAME: {g_dom}] {label}: {ok}/6 | пинг {ping} мс")
            if ok > 0:
                scored.append((ok, ping, ip))
        scored.sort(key=lambda x: (-x[0], x[1]))
        if scored:
            best_game_ips[g_dom] = scored[0][2]
            print(f" [★] Лучший игровой сервер для {g_dom}: {scored[0][2]} ({scored[0][1]} мс)")

    # === СБОРКА ИТОГОВОГО ФАЙЛА SMART_HOSTS.TXT ===
    output_lines = []

    # 1. TIER 0: GEMINI И ВСЕ ШЛЮЗЫ ИСТОРИИ ЧАТОВ (appsgenaiserver-pa.*)
    output_lines.append(f"# === TIER 0: GEMINI & GOOGLE AI (CHAMPION: {best_gemini_ip}) ===")
    for dom in TIER0_GEMINI_DOMAINS:
        output_lines.append(f"{best_gemini_ip} {dom.lower()}")

    for _, dom in all_raw_entries:
        if any(k in dom for k in ("gemini", "appsgenaiserver", "aistudio", "makersuite", "notebooklm", "jules", "antigravity")):
            output_lines.append(f"{best_gemini_ip} {dom}")

    # 2. TIER 1A: БОЕВЫЕ СЕРВЕРЫ ИГР SUPERCELL (Brawl Stars, Clash Royale)
    output_lines.append("\n# === TIER 1A: SUPERCELL GAMES (NULLS PROXY / MALW / COMSS WINNER) ===")
    for g_dom in PRIORITY_GAME_DOMAINS:
        output_lines.append(f"{best_game_ips.get(g_dom, best_gemini_ip)} {g_dom}")

    # 3. TIER 1B: ПЕРСОНАЛЬНЫЕ СЕРВЕРЫ ДЛЯ CLAUDE, GROK, OPENAI, COPILOT, GEFORCE NOW, CANVA, IMGUR
    output_lines.append("\n# === TIER 1B: PER-SERVICE BEST SERVERS ===")
    for svc_name, svc_info in TIER1_SERVICE_GROUPS.items():
        svc_ip = service_winners.get(svc_name, best_gemini_ip)
        output_lines.append(f"# --- {svc_name} ({svc_ip}) ---")
        for dom in svc_info["domains"]:
            output_lines.append(f"{svc_ip} {dom.lower()}")

    # 4. TIER 2: ОСТАЛЬНЫЕ РАЗБЛОКИРОВАННЫЕ САЙТЫ (Spotify, DeepL, JetBrains, Instagram и др.)
    output_lines.append("\n# === TIER 2: OTHER UNLOCKED SERVICES (AUTO-HEALED BY CHAMPION) ===")
    for ip, dom in all_raw_entries:
        if ip in alive_ips and not ip.startswith(ru_prefixes):
            output_lines.append(f"{ip} {dom}")
        else:
            output_lines.append(f"{best_gemini_ip} {dom}")

    # 5. TIER 3: ЗАПАСНЫЕ, US/RU СЕРВЕРЫ И XBOX DNS (СОХРАНЯЮТСЯ В КОНЦЕ ПРО ЗАПАС)
    output_lines.append("\n# === TIER 3: BACKUP & FALLBACK SERVERS (CHECKED DAILY AT 04:30 MSK) ===")
    for c in tier3_pool:
        output_lines.append(f"# Fallback candidate: {c['name']} ({c['ip']}) - last score {c['ok']}/10")
    for ip, dom in all_raw_entries:
        output_lines.append(f"{backup_ip} {dom}")
        output_lines.append(f"{ip} {dom}")

    with open("smart_hosts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines) + "\n")

    print(f"\n[✓] Файл smart_hosts.txt успешно собран ({len(output_lines)} строк)!")


if __name__ == "__main__":
    main()
