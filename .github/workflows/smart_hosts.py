import socket
import ssl
import time
import urllib.request
import json
from collections import Counter

# 1. Базовый пул известных прокси-серверов GeoHide (EU — приоритет 1, US — приоритет 2)
STATIC_PROXIES = [
    {"ip": "5.175.161.3", "group": 1, "name": "GeoHide-EU-1"},
    {"ip": "5.175.161.40", "group": 1, "name": "GeoHide-EU-2"},
    {"ip": "37.221.93.141", "group": 1, "name": "GeoHide-EU-3"},
    {"ip": "37.221.93.128", "group": 1, "name": "GeoHide-EU-4"},
    {"ip": "45.13.237.213", "group": 1, "name": "GeoHide-EU-5"},
    {"ip": "31.25.239.132", "group": 1, "name": "GeoHide-EU-6"},
    {"ip": "143.20.64.192", "group": 1, "name": "GeoHide-EU-7"},
    {"ip": "143.20.64.55", "group": 1, "name": "Malw-EU-Main"},
    {"ip": "107.175.76.134", "group": 2, "name": "GeoHide-US-1"},
    {"ip": "192.255.159.240", "group": 2, "name": "GeoHide-US-2"},
    {"ip": "192.255.159.241", "group": 2, "name": "GeoHide-US-3"},
    {"ip": "192.3.233.253", "group": 2, "name": "GeoHide-US-4"},
]

# 2. Все DoH DNS-маршрутизаторы (скрипт сам достанет из них внутренние прокси-серверы)
DOH_SERVERS = [
    {"name": "GeoHide-EU-DoH", "url": "https://eu.geohide.ru/dns-query", "group": 1},
    {"name": "Comss-Main", "url": "https://dns.comss.one/dns-query", "group": 1},
    {"name": "Comss-Router", "url": "https://router.comss.one/dns-query", "group": 1},
    {"name": "Malw-DoH", "url": "https://dns.malw.link/dns-query", "group": 1},
    {"name": "Astracat", "url": "https://dns.astracat.network/dns-query", "group": 1},
    {"name": "Bezmezha", "url": "https://dns.bezmezhau.com/dns-query", "group": 1},
    {"name": "DnsAI", "url": "https://dns.dns-ai.ru/dns-query", "group": 1},
    {"name": "Mafioznik", "url": "https://dns.mafioznik.xyz/dns-query", "group": 1},
    {"name": "Wlrus", "url": "https://dns.wlrus.cfd/dns-query", "group": 1},
    {"name": "Webshift", "url": "https://d.webshiftvpn.ru/dns-query", "group": 1},
    {"name": "GeoHide-US-DoH", "url": "https://us.geohide.ru/dns-query", "group": 2},
    {"name": "Shecan-IR", "url": "https://free.shecan.ir/dns-query", "group": 2},
]

# 3. Автообновляемые источники списков hosts
BASE_HOSTS_URLS = [
    ("GeoHide-EU", "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/eu/hosts"),
    ("GeoHide-Main", "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"),
    ("Malw-Hosts", "https://raw.githubusercontent.com/ImMALWARE/dns.malw.link/refs/heads/master/hosts"),
    ("Malw-Info", "https://info.dns.malw.link/hosts"),
    ("Fancy-GeoHide", "https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/refs/heads/main/hosts/geohide.hosts"),
    ("Fancy-Comss", "https://raw.githubusercontent.com/Noktomezo/RussiaFancyLists/refs/heads/main/hosts/comss.hosts"),
]

# 4. СПИСОК САЙТОВ ПЕРВОЙ НЕОБХОДИМОСТИ (Всегда получают лучший 10/10 сервер с минимальным пингом)
PRIORITY_GAME_DOMAINS = [
    "game.brawlstarsgame.com",
    "game.clashroyaleapp.com",
    "gamea.clashofclans.com",
    "game.mocogame.com",
]

PRIORITY_WEB_DOMAINS = [
    # --- Google AI: Gemini, AI Studio, Antigravity, Jules, Labs, NotebookLM, Stitch ---
    "gemini.google.com",
    "bard.google.com",
    "aistudio.google.com",
    "makersuite.google.com",
    "alkalimakersuite-pa.clients6.google.com",
    "alkalicore-pa.clients6.google.com",
    "generativelanguage.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "robinfrontend-pa.googleapis.com",
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

    # --- Google CLI, Cloud SDK & Все сервисы Google (Таблицы, Документы, Диск, Colab) ---
    "cloud.google.com",
    "console.cloud.google.com",
    "sdk.cloud.google.com",
    "cloudshell.adeo.google.com",
    "ssh.cloud.google.com",
    "dl.google.com",
    "developers.google.com",
    "apis.google.com",
    "oauth2.googleapis.com",
    "iamcredentials.googleapis.com",
    "www.googleapis.com",
    "content.googleapis.com",
    "docs.google.com",
    "sheets.google.com",
    "slides.google.com",
    "drive.google.com",
    "script.google.com",
    "colab.research.google.com",
    "firebase.google.com",
    "console.firebase.google.com",

    # --- Claude (Anthropic) ---
    "claude.ai",
    "api.anthropic.com",
    "anthropic.com",
    "console.anthropic.com",
    "assets.claude.ai",

    # --- Grok (xAI) ---
    "grok.com",
    "accounts.x.ai",
    "assets.grok.com",
    "api.x.ai",
    "x.ai",

    # --- OpenAI / ChatGPT ---
    "chatgpt.com",
    "ab.chatgpt.com",
    "auth.openai.com",
    "auth0.openai.com",
    "platform.openai.com",
    "cdn.oaistatic.com",
    "files.oaiusercontent.com",
    "webrtc.chatgpt.com",
    "android.chat.openai.com",
    "api.openai.com",
    "operator.chatgpt.com",
    "sora.chatgpt.com",
    "videos.openai.com",
    "ios.chat.openai.com",
    "cdn.platform.openai.com",
    "developers.openai.com",

    # --- GitHub & GitHub Copilot ---
    "api.github.com",
    "api.individual.githubcopilot.com",
    "proxy.individual.githubcopilot.com",
    "copilot-proxy.githubusercontent.com",
    "copilot-telemetry.githubusercontent.com",
    "githubcopilot.com",
    "github.com",
    "gist.github.com",

    # --- Supercell Store & Supercell ID ---
    "store.supercell.com",
    "id.supercell.com",
    "cdn.id.supercell.com",
    "security.id.supercell.com",
    "accounts.supercell.com",
    "game-assets.brawlstarsgame.com",
    "game-assets.clashroyaleapp.com",
    "game-assets.clashofclans.com",
    "clashofclans.inbox.supercell.com",
    "brawlstars.inbox.supercell.com",

    # --- NVIDIA GeForce NOW ---
    "play.geforcenow.com",
    "geforcenow.com",
    "www.geforcenow.com",
    "login.nvgs.nvidia.com",
    "nvgs.nvidia.com",
    "prod.cloudmatchbeta.nvidiagrid.net",
    "cloudmatchbeta.nvidiagrid.net",
    "api.geforcenow.com",
    "events.gfe.nvidia.com",

    # --- Canva ---
    "canva.com",
    "www.canva.com",
    "about.canva.com",
    "static.canva.com",
    "marketplace.canva.com",
    "document-export.canva.com",
    "media.canva.com",
    "media-public.canva.com",

    # --- Imgur ---
    "imgur.com",
    "www.imgur.com",
    "i.imgur.com",
    "api.imgur.com",
    "s.imgur.com",
    "m.imgur.com",
]

# Ключевые домены, по которым скрипт опрашивает сторонние DoH DNS для поиска специализированных прокси
DOH_PROBE_DOMAINS = [
    "gemini.google.com",
    "claude.ai",
    "grok.com",
    "chatgpt.com",
    "api.individual.githubcopilot.com",
    "store.supercell.com",
    "play.geforcenow.com",
    "www.canva.com",
    "i.imgur.com",
]

ATTEMPTS = 10
TIMEOUT = 2.5


def discover_geohide_repo_files():
    """Автоматически находит все файлы hosts в репозитории GeoHideDNS (RU/EU/US и новые)."""
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
    """Проверяет, заблокирован ли еще российский домен geohide.ru Роскомнадзором."""
    try:
        url = "https://reestr.rublacklist.net/api/v3/domains/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if f'"{target}"' in body:
                return True
    except Exception:
        pass
    try:
        req = urllib.request.Request("https://geohide.ru", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            if resp.status == 200:
                return False
    except Exception:
        return True
    return True


def resolve_doh_ips(doh_url, domain):
    """Запрашивает все прокси-IP у DoH-сервера для указанного домена."""
    ips = []
    try:
        req = urllib.request.Request(
            f"{doh_url}?name={domain}&type=A",
            headers={"Accept": "application/dns-json", "User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            for ans in data.get("Answer", []):
                if ans.get("type") == 1 and ans.get("data"):
                    ips.append(ans["data"])
    except Exception:
        pass
    return ips


def stress_test_https(ip, domain="gemini.google.com", attempts=ATTEMPTS):
    """Проводит 10 реальных HTTPS-запросов через прокси и замеряет успешность и средний пинг."""
    success = 0
    total_ms = 0.0
    ctx = ssl.create_default_context()
    for _ in range(attempts):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    req = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n"
                    ssock.sendall(req.encode())
                    resp = ssock.recv(128).decode(errors="ignore")
                    if "HTTP/" in resp and "403" not in resp.splitlines()[0]:
                        success += 1
                        total_ms += (time.perf_counter() - start) * 1000
        except Exception:
            pass
    avg_ping = (total_ms / success) if success > 0 else 9999.0
    return success, round(avg_ping, 1)


def stress_test_game_tcp(ip, ports=(9339, 443), attempts=ATTEMPTS):
    """Проводит 10 замеров скорости отклика игрового сервера Supercell по игровым портам."""
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
                        entries.append((parts[0], dom.lower()))
    except Exception as e:
        print(f" [!] Не удалось скачать {url}: {e}")
    return entries


def main():
    print("=== 1. Автопоиск и скачивание всех свежих баз hosts ===")
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
            print(f" [+] {name}: загружено {len(entries)} записей")
            all_raw_entries.extend(entries)
            for ip, dom in entries:
                ip_counter[ip] += 1
                if dom in game_candidates:
                    game_candidates[dom].append({"ip": ip, "name": f"{name}({ip})"})

    print("\n=== 2. Проверка статуса RU-серверов GeoHide ===")
    ru_blocked = is_rkn_blocked("geohide.ru")
    ru_group = 3 if ru_blocked else 1
    print(f" -> RU-серверы GeoHide: {'В БЛОКЕ РКН (в резерве)' if ru_blocked else 'РАЗБЛОКИРОВАНЫ (в 1 эшелоне)'}")

    candidates = list(STATIC_PROXIES)
    seen_ips = {c["ip"] for c in candidates}

    # Добавляем универсальные прокси из скачанных файлов hosts
    for ip, count in ip_counter.items():
        if count >= 15 and ip not in seen_ips:
            grp = ru_group if ip.startswith(("159.194.", "193.233.", "37.230.")) else 1
            candidates.append({"ip": ip, "group": grp, "name": f"Hosts-Proxy({ip})"})
            seen_ips.add(ip)

    print("\n=== 3. Опрос и расчленение DoH DNS (Comss, Malw, GeoHide и др.) ===")
    category_specific_ips = {}
    for doh in DOH_SERVERS:
        # Опрашиваем по ключевым сервисам первой необходимости
        for probe_dom in DOH_PROBE_DOMAINS:
            ips = resolve_doh_ips(doh["url"], probe_dom)
            for ip in ips:
                category_specific_ips.setdefault(probe_dom, set()).add(ip)
                if ip not in seen_ips:
                    print(f" [+] {doh['name']} -> {probe_dom}: найден прокси {ip}")
                    candidates.append({"ip": ip, "group": doh["group"], "name": f"{doh['name']}({ip})"})
                    seen_ips.add(ip)

        # Опрашиваем отдельно по боевым игровым серверам Supercell
        for g_dom in PRIORITY_GAME_DOMAINS:
            for ip in resolve_doh_ips(doh["url"], g_dom):
                game_candidates[g_dom].append({"ip": ip, "name": f"{doh['name']}-Game({ip})"})

    print(f"\n=== 4. Стресс-тест серверов первой необходимости ({ATTEMPTS} запросов) ===")
    tier1, tier2, tier3 = [], [], []
    alive_ips = set()

    for c in candidates:
        ok, ping = stress_test_https(c["ip"], "gemini.google.com")
        c["ok"], c["ping"] = ok, ping
        print(f" -> {c['name']} [{c['ip']}]: успешно {ok}/{ATTEMPTS} | пинг {ping} мс | группа {c['group']}")
        if ok >= 9 and c["group"] == 1:
            tier1.append(c)
            alive_ips.add(c["ip"])
        elif ok >= 1 and c["group"] in (1, 2):
            tier2.append(c)
            alive_ips.add(c["ip"])
        else:
            tier3.append(c)

    tier1.sort(key=lambda x: (-x["ok"], x["ping"]))
    tier2.sort(key=lambda x: (x["group"], -x["ok"], x["ping"]))

    best_primary_ip = tier1[0]["ip"] if tier1 else (tier2[0]["ip"] if tier2 else "5.175.161.3")
    backup_ip = tier2[0]["ip"] if tier2 else best_primary_ip
    print(f"\n[★] ЛУЧШИЙ СЕРВЕР ДЛЯ ПРИОРИТЕТНЫХ САЙТОВ: {best_primary_ip}")

    print("\n=== 5. Стресс-тест игровых серверов Brawl Stars и Clash Royale ===")
    best_game_ips = {}
    for g_dom, g_list in game_candidates.items():
        unique_ips = {}
        for item in g_list:
            unique_ips.setdefault(item["ip"], item["name"])
        scored = []
        for ip, label in unique_ips.items():
            ok, ping = stress_test_game_tcp(ip)
            print(f" -> [{g_dom}] {label}: {ok}/{ATTEMPTS} | пинг {ping} мс")
            if ok > 0:
                scored.append((ok, ping, ip))
        scored.sort(key=lambda x: (-x[0], x[1]))
        if scored:
            best_game_ips[g_dom] = scored[0][2]
            print(f" [★] Лучший игровой сервер для {g_dom}: {scored[0][2]} ({scored[0][1]} мс)")

    # Формируем итоговый список (DnsConf берет ПЕРВЫЙ встреченный IP для каждого домена)
    output_lines = []

    # 1. ИГРЫ SUPERCELL (Боевые серверы с минимальным пингом)
    output_lines.append("# === 1. PRIORITY: SUPERCELL GAME SERVERS ===")
    for g_dom in PRIORITY_GAME_DOMAINS:
        g_ip = best_game_ips.get(g_dom, best_primary_ip)
        output_lines.append(f"{g_ip} {g_dom}")
