import base64
import json
import random
import socket
import ssl
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# 1. Проверенные серверы специально для GEMINI и GOOGLE AI (GeoHide EU/US + профильный узел Malw для Gemini)
GEMINI_PROXIES = [
    {"ip": "5.175.161.40", "group": 1, "name": "GeoHide-EU-3"},
    {"ip": "37.221.93.128", "group": 1, "name": "GeoHide-EU-1"},
    {"ip": "37.221.93.141", "group": 1, "name": "GeoHide-EU-2"},
    {"ip": "143.20.64.192", "group": 1, "name": "GeoHide-EU-7"},
    {"ip": "45.13.237.213", "group": 1, "name": "GeoHide-EU-5"},
    {"ip": "5.175.161.3", "group": 1, "name": "GeoHide-EU-4"},
    {"ip": "31.25.239.132", "group": 1, "name": "GeoHide-EU-6"},
    {"ip": "179.254.166.174", "group": 1, "name": "Malw-Gemini-Node"},
    # Быстрые US-узлы GeoHide (используются для мобильных шлюзов robinfrontend-pa / aisandbox-pa)
    {"ip": "192.255.159.240", "group": 1, "name": "GeoHide-US-2"},
    {"ip": "107.175.76.134", "group": 1, "name": "GeoHide-US-1"},
    {"ip": "192.3.233.253", "group": 2, "name": "GeoHide-US-4"},
    {"ip": "192.255.159.241", "group": 2, "name": "GeoHide-US-3"},
    # Резерв RU (Tier 3 — проверяются каждую ночь на случай снятия блокировки РКН)
    {"ip": "159.194.200.33", "group": 3, "name": "GeoHide-RU-1"},
    {"ip": "193.233.112.67", "group": 3, "name": "GeoHide-RU-2"},
    {"ip": "193.233.112.68", "group": 3, "name": "GeoHide-RU-3"},
    {"ip": "193.233.112.88", "group": 3, "name": "GeoHide-RU-4"},
    {"ip": "37.230.192.51", "group": 3, "name": "GeoHide-RU-5"},
]

# 2. Проверенные игровые прокси-серверы для Supercell (из лога со счетом 6/6, БЕЗ Amazon AWS!)
STATIC_GAME_PROXIES = {
    "game.brawlstarsgame.com": [
        {"ip": "179.254.166.174", "name": "Malw-BS(179.254.166.174)"},
        {"ip": "62.233.36.84", "name": "GeoHide-EU-BS(62.233.36.84)"},
        {"ip": "62.233.36.83", "name": "GeoHide-EU-BS(62.233.36.83)"},
    ],
    "game.clashroyaleapp.com": [
        {"ip": "179.254.166.171", "name": "Malw-CR(179.254.166.171)"},
        {"ip": "81.17.20.82", "name": "GeoHide-EU-CR(81.17.20.82)"},
    ],
    "gamea.clashofclans.com": [
        {"ip": "81.17.20.86", "name": "GeoHide-EU-CoC(81.17.20.86)"},
        {"ip": "164.5.224.81", "name": "Malw-CoC(164.5.224.81)"},
    ],
    "game.mocogame.com": [
        {"ip": "179.254.166.171", "name": "Malw-Moco(179.254.166.171)"},
    ],
}

# 3. DNS-серверы для живого опроса по бинарному DoH (RFC 8484) и DoT (Порт 853, как в Android!)
SMART_DNS_PROVIDERS = [
    {
        "name": "Comss-Router",
        "dot_host": "router.comss.one",
        "doh_url": "https://router.comss.one/dns-query",
        "udp_host": "93.115.24.120",
        "only_games": False,
    },
    {
        "name": "Comss-Main",
        "dot_host": "dns.comss.one",
        "doh_url": "https://dns.comss.one/dns-query",
        "udp_host": "93.115.24.121",
        "only_games": False,
    },
    {
        "name": "Malw-DNS",
        "dot_host": "dns.malw.link",
        "doh_url": "https://dns.malw.link/dns-query",
        "udp_host": "179.254.166.171",
        "only_games": False,
    },
    {
        "name": "Malw-CF-Gateway",
        "dot_host": "5u35p8m9i7.cloudflare-gateway.com",
        "doh_url": "https://5u35p8m9i7.cloudflare-gateway.com/dns-query",
        "udp_host": "164.5.224.81",
        "only_games": False,
    },
    {
        "name": "GeoHide-EU",
        "dot_host": "eu.geohide.ru",
        "doh_url": "https://eu.geohide.ru/dns-query",
        "udp_host": None,
        "only_games": False,
    },
    {
        "name": "GeoHide-US",
        "dot_host": "us.geohide.ru",
        "doh_url": "https://us.geohide.ru/dns-query",
        "udp_host": None,
        "only_games": False,
    },
    {
        "name": "NullsProxy-Game",
        "dot_host": "dns.nullsproxy.com",
        "doh_url": "https://dns.nullsproxy.com/dns-query",
        "udp_host": "dns.nullsproxy.com",
        "only_games": True,
    },
]

# 4. Рабочие списки hosts на GitHub (без битых ссылок 404/403)
BASE_HOSTS_URLS = [
    ("GeoHide-EU", "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/eu/hosts"),
    ("Malw-Hosts", "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"),
    ("GeoHide-US", "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/us/hosts"),
    ("GeoHide-Main", "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"),
]

# === TIER 0A: ВЕБ-ШЛЮЗЫ И ИСТОРИЯ ЧАТОВ GEMINI ===
TIER0_GEMINI_WEB_DOMAINS = [
    "gemini.google.com",
    "appsgenaiserver-pa.clients.google.com",
    "appsgenaiserver-pa.clients6.google.com",
    "appsgenaiserver-pa.googleapis.com",
    "bard.google.com",
    "aistudio.google.com",
    "makersuite.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "alkalicore-pa.clients6.google.com",
    "webchannel-alkalimakersuite-pa.clients6.google.com",
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
# === TIER 0B: СПЕЦИАЛЬНЫЕ МОБИЛЬНЫЕ ШЛЮЗЫ ПРИЛОЖЕНИЯ GEMINI НА ANDROID ===
# Для них скрипт опрашивает router.comss.one и us/eu.geohide.ru индивидуально!
TIER0_ANDROID_APP_DOMAINS = [
    "robinfrontend-pa.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "waa-pa.clients6.google.com",
    "geminiweb-pa.googleapis.com",
    "geminiweb-pa.clients6.google.com",
]

# === TIER 1A: БОЕВЫЕ СЕРВЕРЫ ИГР SUPERCELL ===
PRIORITY_GAME_DOMAINS = [
    "game.brawlstarsgame.com",
    "game.clashroyaleapp.com",
    "gamea.clashofclans.com",
    "game.mocogame.com",
]

# === TIER 1B: НЕЙРОСЕТИ И СЕРВИСЫ ПЕРВОЙ НЕОБХОДИМОСТИ ===
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

# Системные домены Google, которые работают в РФ напрямую и не должны перехватываться
NEVER_PROXY_DOMAINS = {
    "google.com", "www.google.com", "accounts.google.com", "oauth2.googleapis.com",
    "www.googleapis.com", "apis.google.com", "content.googleapis.com",
    "iamcredentials.googleapis.com", "docs.google.com", "sheets.google.com",
    "slides.google.com", "drive.google.com", "script.google.com", "dl.google.com",
    "play.google.com", "mtalk.google.com", "connectivitycheck.gstatic.com",
    "gstatic.com", "www.gstatic.com",
}

# Черный список НЕ-прокси подсетей (Прямые сервера Amazon AWS Supercell, Google, Cloudflare и заблокированные RU-узлы)
FORBIDDEN_PREFIXES = (
    "0.", "127.", "10.", "1.1.1.", "1.0.0.", "8.8.8.", "8.8.4.",
    # Amazon AWS (из-за которых Clash Royale зависал на 96% на 35.91.220.220 и 44.200.12.7!)
    "34.", "35.", "44.", "52.", "54.", "18.", "3.", "13.", "15.", "98.", "99.", "75.", "16.",
    # Прямые подсети Google и Cloudflare
    "142.250.", "142.251.", "172.217.", "216.58.", "74.125.", "64.233.",
    "108.177.", "173.194.", "209.85.", "104.16.", "104.17.", "104.18.",
    "104.19.", "172.64.", "172.66.", "172.67.",
    # Заблокированные в РФ подсети GeoHide-RU и Xbox
    "159.194.", "193.233.", "37.230.", "111.88.",
)
TIMEOUT = 2.4
BAD_HTTP_CODES = ("400", "403", "421", "429", "500", "502", "503", "504", "520", "521", "522", "523", "524")


def is_valid_proxy_ip(ip):
    if not ip or "." not in ip:
        return False
    return not ip.startswith(FORBIDDEN_PREFIXES)


def build_dns_query_packet(domain):
    tid = random.randint(1, 65534)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(struct.pack("B", len(p)) + p.encode("ascii") for p in domain.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1)


def parse_dns_response_packet(data):
    ips = []
    try:
        ancount = struct.unpack(">H", data[6:8])[0]
        offset = 12
        while offset < len(data) and data[offset] != 0:
            offset += 1 + data[offset]
        offset += 5
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
                ip = socket.inet_ntoa(data[offset:offset + 4])
                if is_valid_proxy_ip(ip):
                    ips.append(ip)
            offset += rdlen
    except Exception:
        pass
    return ips


def resolve_dot_853(dot_host, domain, timeout=3.0):
    """Опрашивает сервер по протоколу DNS-over-TLS (порт 853) — точно так же, как Android Частный DNS!"""
    if not dot_host:
        return []
    try:
        packet = build_dns_query_packet(domain)
        tcp_msg = struct.pack(">H", len(packet)) + packet
        ctx = ssl.create_default_context()
        with socket.create_connection((dot_host, 853), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=dot_host) as ssock:
                ssock.sendall(tcp_msg)
                len_bytes = ssock.recv(2)
                if len(len_bytes) < 2:
                    return []
                resp_len = struct.unpack(">H", len_bytes)[0]
                data = b""
                while len(data) < resp_len:
                    chunk = ssock.recv(resp_len - len(data))
                    if not chunk:
                        break
                    data += chunk
                return parse_dns_response_packet(data)
    except Exception:
        return []


def resolve_doh_rfc8484(doh_url, domain, timeout=3.5):
    """Опрашивает DoH-сервер по бинарному стандарту RFC 8484 (application/dns-message), который понимают Comss, Malw и GeoHide."""
    if not doh_url:
        return []
    try:
        packet = build_dns_query_packet(domain)
        b64_dns = base64.urlsafe_b64encode(packet).decode("ascii").rstrip("=")
        req = urllib.request.Request(
            f"{doh_url}?dns={b64_dns}",
            headers={"Accept": "application/dns-message", "User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return parse_dns_response_packet(resp.read())
    except Exception:
        return []


def resolve_udp_53(udp_host, domain, timeout=2.0):
    if not udp_host:
        return []
    try:
        packet = build_dns_query_packet(domain)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (udp_host, 53))
            data, _ = sock.recvfrom(1024)
        return parse_dns_response_packet(data)
    except Exception:
        return []


def resolve_smart_provider(provider, domain):
    """Пробует получить прокси-IP у провайдера сначала через DoT (853), затем через бинарный DoH (443), затем через UDP (53)."""
    ips = resolve_dot_853(provider.get("dot_host"), domain)
    if not ips:
        ips = resolve_doh_rfc8484(provider.get("doh_url"), domain)
    if not ips and provider.get("udp_host"):
        ips = resolve_udp_53(provider.get("udp_host"), domain)
    return ips


def stress_test_https_get(ip, domain, require_google_headers=False, attempts=5):
    """Отправляет реальные GET-запросы и проверяет подлинность ответа целевого сервера."""
    success = 0
    total_ms = 0.0
    ctx = ssl.create_default_context()
    for _ in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    req = (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {domain}\r\n"
                        f"User-Agent: Mozilla/5.0 (Linux; Android 14)\r\n"
                        f"Connection: close\r\n\r\n"
                    )
                    ssock.sendall(req.encode())
                    resp = ssock.recv(512).decode(errors="ignore")
                    first_line = resp.splitlines()[0] if resp else ""
                    if "HTTP/" in first_line and not any(code in first_line for code in BAD_HTTP_CODES):
                        if require_google_headers:
                            r_low = resp.lower()
                            # Настоящий прокси Google всегда возвращает куки/заголовки Google (esf, gws, sffe, google.com), а не чужой 301!
                            if not any(sig in r_low for sig in ("google", "esf", "gws", "sffe", "scaffolding", "__secure-")):
                                continue
                        success += 1
                        total_ms += (time.perf_counter() - start) * 1000
        except Exception:
            pass
    avg_ping = (total_ms / success) if success > 0 else 9999.0
    return success, round(avg_ping, 1)


def stress_test_gemini_dual(ip):
    """
    Честный тест для Gemini (10 запросов без ложной отбраковки на 7/10!):
    6 реальных GET-запросов к gemini.google.com (с проверкой подписи Google) +
    4 запроса к шлюзу истории чатов appsgenaiserver-pa.googleapis.com.
    """
    ok_web, ping_web = stress_test_https_get(ip, "gemini.google.com", require_google_headers=True, attempts=6)
    if ok_web == 0:
        return 0, 9999.0

    # Для API-шлюза appsgenaiserver-pa проверяем, что TLS-рукопожатие проходит и сервер Google ESF отвечает (даже 404 на корень / означает живой API-шлюз!)
    ok_api = 0
    ping_api_total = 0.0
    ctx = ssl.create_default_context()
    for _ in range(4):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname="appsgenaiserver-pa.googleapis.com") as ssock:
                    req = "GET / HTTP/1.1\r\nHost: appsgenaiserver-pa.googleapis.com\r\nConnection: close\r\n\r\n"
                    ssock.sendall(req.encode())
                    resp = ssock.recv(256).decode(errors="ignore")
                    if "HTTP/" in resp and not any(c in resp.splitlines()[0] for c in ("403", "502", "503", "504")):
                        ok_api += 1
                        ping_api_total += (time.perf_counter() - start) * 1000
        except Exception:
            pass

    total_ok = ok_web + ok_api
    avg_api = (ping_api_total / ok_api) if ok_api > 0 else ping_web
    avg_ping = round((ping_web * 0.6) + (avg_api * 0.4), 1)
    return total_ok, avg_ping


def stress_test_game_tcp(ip, ports=(9339, 443), attempts=6):
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
    print("=== 1. Скачивание актуальных списков hosts (GeoHide EU/US/Main, Malw) ===")
    all_raw_entries = []
    domain_to_hosts_ips = {}
    game_candidates = {dom: list(STATIC_GAME_PROXIES.get(dom, [])) for dom in PRIORITY_GAME_DOMAINS}

    for name, url in BASE_HOSTS_URLS:
        entries = fetch_hosts_file(url)
        if entries:
            print(f" [+] {name}: загружено {len(entries)} записей")
            all_raw_entries.extend(entries)
            for ip, dom in entries:
                if is_valid_proxy_ip(ip):
                    domain_to_hosts_ips.setdefault(dom, []).append((ip, name))
                    if dom in game_candidates:
                        game_candidates[dom].append({"ip": ip, "name": f"{name}({ip})"})

    print("\n=== 2. Живой опрос DNS по DoT (853) и бинарному DoH (router.comss.one, Malw, GeoHide, Null's Proxy) ===")
    gemini_candidates = []
    seen_gemini_ips = set()
    android_gateway_ips = {dom: [] for dom in TIER0_ANDROID_APP_DOMAINS}

    for prov in SMART_DNS_PROVIDERS:
        if not prov["only_games"]:
            # Опрашиваем провайдеры специально по главным шлюзам Gemini
            for g_dom in ("gemini.google.com", "appsgenaiserver-pa.googleapis.com"):
                for ip in resolve_smart_provider(prov, g_dom):
                    if ip not in seen_gemini_ips:
                        print(f" [+] [GEMINI-DNS] {prov['name']} ({g_dom}) -> {ip}")
                        gemini_candidates.append({"ip": ip, "group": 1, "name": f"{prov['name']}({ip})", "bonus": True})
                        seen_gemini_ips.add(ip)

            # Опрашиваем индивидуально мобильные шлюзы Android-приложения Gemini
            for app_dom in TIER0_ANDROID_APP_DOMAINS:
                for ip in resolve_smart_provider(prov, app_dom):
                    print(f" [+] [ANDROID-APP] {prov['name']} ({app_dom}) -> {ip}")
                    android_gateway_ips[app_dom].append((ip, prov["name"]))

        # Опрашиваем игровые серверы Supercell
        for game_dom in PRIORITY_GAME_DOMAINS:
            for ip in resolve_smart_provider(prov, game_dom):
                print(f" [+] [GAME-DNS] {prov['name']} ({game_dom}) -> {ip}")
                game_candidates[game_dom].append({"ip": ip, "name": f"{prov['name']}({ip})"})

    # Добавляем проверенные серверы Gemini из статического пула (НЕ включая сюда 143.20.64.55!)
    for sp in GEMINI_PROXIES:
        if sp["ip"] not in seen_gemini_ips:
            gemini_candidates.append({
                "ip": sp["ip"],
                "group": sp["group"],
                "name": sp["name"],
                "bonus": sp["group"] == 1,
            })
            seen_gemini_ips.add(sp["ip"])

    print(f"\n=== 3. Стресс-тест {len(gemini_candidates)} профильных серверов для GEMINI (с проверкой подписи Google) ===")
    tier0_pool, tier3_pool = [], []
    with ThreadPoolExecutor(max_workers=12) as executor:
        f_map = {executor.submit(stress_test_gemini_dual, c["ip"]): c for c in gemini_candidates}
        for fut in as_completed(f_map):
            c = f_map[fut]
            ok, ping = fut.result()
            c["ok"], c["ping"] = ok, ping
            print(f" -> [GEMINI TEST] {c['name']} [{c['ip']}]: {ok}/10 | пинг {ping} мс | гр.{c['group']}")
            if ok >= 6 and c["group"] == 1:
                tier0_pool.append(c)
            else:
                tier3_pool.append(c)

    tier0_pool.sort(key=lambda x: (-x["ok"], x["ping"]))
    best_gemini_ip = tier0_pool[0]["ip"] if tier0_pool else "5.175.161.40"
    print(f"\n[★★★] ЧЕМПИОН TIER 0 ДЛЯ GEMINI: {best_gemini_ip}")

    # Подбираем лучшие рабочие IP для каждого мобильного шлюза приложения Gemini на Android
    best_android_app_ips = {}
    for app_dom in TIER0_ANDROID_APP_DOMAINS:
        cand_list = android_gateway_ips.get(app_dom, []) + domain_to_hosts_ips.get(app_dom, [])
        if cand_list:
            best_android_app_ips[app_dom] = cand_list[0][0]
        else:
            best_android_app_ips[app_dom] = best_gemini_ip

    print("\n=== 4. Персональный отбор серверов для Claude, Grok, OpenAI, Copilot, Supercell Store ===")
    general_ai_candidates = {c["ip"]: c["name"] for c in tier0_pool}
    general_ai_candidates["143.20.64.55"] = "Malw-EU-Main(143.20.64.55)"
    general_ai_candidates["179.254.166.174"] = "Malw-Node(179.254.166.174)"
    service_winners = {}

    for svc_name, svc_info in TIER1_SERVICE_GROUPS.items():
        t_dom = svc_info["test_domain"]
        svc_pool = dict(general_ai_candidates)
        for ip, src_name in domain_to_hosts_ips.get(t_dom, []):
            svc_pool.setdefault(ip, f"{src_name}({ip})")
        for prov in SMART_DNS_PROVIDERS[:5]:
            for ip in resolve_smart_provider(prov, t_dom):
                svc_pool.setdefault(ip, f"{prov['name']}({ip})")

        scored_svc = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            f_map = {executor.submit(stress_test_https_get, ip, t_dom, False, 5): (ip, label) for ip, label in svc_pool.items()}
            for fut in as_completed(f_map):
                ip, label = f_map[fut]
                ok, ping = fut.result()
                if ok > 0:
                    scored_svc.append((ok, ping, ip, label))
        scored_svc.sort(key=lambda x: (-x[0], x[1]))
        if scored_svc:
            win_ok, win_ping, win_ip, win_name = scored_svc[0]
            service_winners[svc_name] = win_ip
            print(f" [★] Лучший сервер для {svc_name} ({t_dom}): {win_name} -> {win_ip} ({win_ok}/5, {win_ping} мс)")
        else:
            service_winners[svc_name] = best_gemini_ip

    print("\n=== 5. Стресс-тест игровых прокси Brawl Stars и Clash Royale (Без прямых серверов AWS!) ===")
    best_game_ips = {}
    for g_dom, g_list in game_candidates.items():
        unique_ips = {}
        for item in g_list:
            if is_valid_proxy_ip(item["ip"]):
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
            print(f" [★] Победитель для {g_dom}: {scored[0][2]} ({scored[0][1]} мс)")

    # === ФОРМИРОВАНИЕ ИТОГОВОГО ФАЙЛА SMART_HOSTS.TXT ===
    output_lines = []
    assigned_domains = set()

    # 1. TIER 0A: GEMINI И ШЛЮЗЫ ИСТОРИИ ЧАТОВ (appsgenaiserver-pa.*)
    output_lines.append(f"# === TIER 0A: GEMINI WEB & CHAT GATEWAYS (CHAMPION: {best_gemini_ip}) ===")
    for dom in TIER0_GEMINI_WEB_DOMAINS:
        d = dom.lower()
        output_lines.append(f"{best_gemini_ip} {d}")
        assigned_domains.add(d)

    # 2. TIER 0B: МОБИЛЬНЫЕ ШЛЮЗЫ ПРИЛОЖЕНИЯ GEMINI НА ANDROID
    output_lines.append("\n# === TIER 0B: GEMINI ANDROID APP GATEWAYS ===")
    for app_dom, app_ip in best_android_app_ips.items():
        d = app_dom.lower()
        output_lines.append(f"{app_ip} {d}")
        assigned_domains.add(d)

    # 3. TIER 1A: БОЕВЫЕ СЕРВЕРЫ ИГР SUPERCELL
    output_lines.append("\n# === TIER 1A: SUPERCELL GAME SERVERS ===")
    for g_dom in PRIORITY_GAME_DOMAINS:
        g_ip = best_game_ips.get(g_dom, "179.254.166.171")
        output_lines.append(f"{g_ip} {g_dom}")
        assigned_domains.add(g_dom)

    # 4. TIER 1B: ПЕРСОНАЛЬНЫЕ СЕРВЕРЫ ДЛЯ CLAUDE, GROK, OPENAI, COPILOT, GEFORCE NOW, CANVA, IMGUR
    output_lines.append("\n# === TIER 1B: PRIORITY AI & SERVICES ===")
    for svc_name, svc_info in TIER1_SERVICE_GROUPS.items():
        svc_ip = service_winners.get(svc_name, best_gemini_ip)
        output_lines.append(f"# --- {svc_name} ({svc_ip}) ---")
        for dom in svc_info["domains"]:
            d = dom.lower()
            if d not in assigned_domains and d not in NEVER_PROXY_DOMAINS:
                output_lines.append(f"{svc_ip} {d}")
                assigned_domains.add(d)

    # 5. TIER 2: ОСТАЛЬНЫЕ РАЗБЛОКИРОВАННЫЕ САЙТЫ (сохраняют свои профильные рабочие IP из баз GeoHide/Malw)
    output_lines.append("\n# === TIER 2: OTHER UNLOCKED SERVICES ===")
    for ip, dom in all_raw_entries:
        if dom not in assigned_domains and dom not in NEVER_PROXY_DOMAINS:
            if is_valid_proxy_ip(ip):
                output_lines.append(f"{ip} {dom}")
                assigned_domains.add(dom)
            else:
                output_lines.append(f"{best_gemini_ip} {dom}")
                assigned_domains.add(dom)

    # 6. TIER 3: РЕЗЕРВНЫЕ И ОЖИДАЮЩИЕ РАЗБЛОКИРОВКИ СЕРВЕРЫ
    output_lines.append("\n# === TIER 3: FALLBACK & RESERVE SERVERS ===")
    for c in tier3_pool:
        output_lines.append(f"# Fallback candidate: {c['name']} ({c['ip']}) - score {c['ok']}/10")

    with open("smart_hosts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines) + "\n")

    print(f"\n[✓] Готово! Собрано {len(assigned_domains)} чистых правил для NextDNS.")


if __name__ == "__main__":
    main()
