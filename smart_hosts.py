import base64
import os
import random
import socket
import ssl
import struct
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SERVERS_FILE = "servers.txt"

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

# === TIER 0B: МОБИЛЬНЫЕ ШЛЮЗЫ ПРИЛОЖЕНИЯ GEMINI НА ANDROID ===
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

NEVER_PROXY_DOMAINS = {
    "google.com", "www.google.com", "accounts.google.com", "oauth2.googleapis.com",
    "www.googleapis.com", "apis.google.com", "content.googleapis.com",
    "iamcredentials.googleapis.com", "docs.google.com", "sheets.google.com",
    "slides.google.com", "drive.google.com", "script.google.com", "dl.google.com",
    "play.google.com", "mtalk.google.com", "connectivitycheck.gstatic.com",
    "gstatic.com", "www.gstatic.com",
}
# Черный список НЕ-прокси подсетей (Прямые сервера Amazon AWS Supercell, Google, Cloudflare, AdGuard)
FORBIDDEN_PREFIXES = (
    "0.", "127.", "10.", "1.1.1.", "1.0.0.", "8.8.8.", "8.8.4.", "94.140.",
    "34.", "35.", "44.", "52.", "54.", "18.", "3.", "13.", "15.", "98.", "99.", "75.", "16.",
    "142.250.", "142.251.", "172.217.", "216.58.", "74.125.", "64.233.",
    "108.177.", "173.194.", "209.85.", "104.16.", "104.17.", "104.18.",
    "104.19.", "172.64.", "172.66.", "172.67.",
    "111.88.",
)

RU_FALLBACK_PREFIXES = ("159.194.", "193.233.", "37.230.")
TIMEOUT = 2.4
BAD_HTTP_CODES = ("400", "403", "421", "429", "500", "502", "503", "504", "520", "521", "522", "523", "524")


def is_valid_proxy_ip(ip):
    if not ip or "." not in ip:
        return False
    return not ip.startswith(FORBIDDEN_PREFIXES)


def normalize_dns_donor(raw_host_or_url, udp_host=None, only_games=False):
    """Автоматически превращает любую строку (домен или ссылку) в полный профиль DoT + DoH + UDP."""
    clean = raw_host_or_url.strip()
    if clean.startswith("https://"):
        doh_url = clean if "/" in clean[8:] else f"{clean}/dns-query"
        dot_host = clean.split("https://")[1].split("/")[0]
    else:
        dot_host = clean.split("/")[0]
        doh_url = f"https://{dot_host}/dns-query"
    return {
        "name": dot_host,
        "dot_host": dot_host,
        "doh_url": doh_url,
        "udp_host": udp_host if udp_host and udp_host != "-" else None,
        "only_games": only_games,
    }


def load_servers_config(filepath=SERVERS_FILE):
    """Читает файл servers.txt и раскладывает серверы по категориям."""
    gemini_proxies = []
    ai_only_proxies = {}
    static_game_proxies = {dom: [] for dom in PRIORITY_GAME_DOMAINS}
    smart_dns_providers = []
    base_hosts_urls = []

    if not os.path.exists(filepath):
        print(f" [!] Файл {filepath} не найден!")
        return gemini_proxies, ai_only_proxies, static_game_proxies, smart_dns_providers, base_hosts_urls

    section = "EU"
    with open(filepath, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue

            # Поддержка заголовков вида [EU] или комментариев вида # сервера eu
            low = line.lower()
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip().upper()
                continue
            if line.startswith("#"):
                if "сервера eu" in low or "серверы eu" in low:
                    section = "EU"
                elif "сервера us" in low or "серверы us" in low:
                    section = "US"
                elif "сервера ru" in low or "серверы ru" in low:
                    section = "RU"
                continue

            # Отрезаем комментарии в конце строки, если они есть
            clean_line = line.split("#")[0].strip()
            if not clean_line:
                continue
            parts = clean_line.split()

            if section in ("EU", "US", "RU"):
                ip = parts[0]
                label = parts[1] if len(parts) > 1 else f"{section}({ip})"
                grp = 1 if section in ("EU", "US") else 3
                gemini_proxies.append({"ip": ip, "group": grp, "name": label})

            elif section == "AI_ONLY":
                ip = parts[0]
                label = parts[1] if len(parts) > 1 else f"AI({ip})"
                ai_only_proxies[ip] = f"{label}({ip})"

            elif section == "GAMES":
                if len(parts) >= 2:
                    g_dom, ip = parts[0].lower(), parts[1]
                    label = parts[2] if len(parts) > 2 else f"Game({ip})"
                    static_game_proxies.setdefault(g_dom, []).append({"ip": ip, "name": f"{label}({ip})"})

            elif section in ("DNS_DONORS", "GAME_DNS_DONORS"):
                host_or_url = parts[0]
                udp_h = parts[1] if len(parts) > 1 else None
                smart_dns_providers.append(
                    normalize_dns_donor(host_or_url, udp_h, only_games=(section == "GAME_DNS_DONORS"))
                )

            elif section == "HOSTS_URLS":
                if len(parts) >= 2:
                    base_hosts_urls.append((parts[0], parts[1]))
                elif parts[0].startswith("http"):
                    base_hosts_urls.append((f"Hosts-{len(base_hosts_urls)+1}", parts[0]))

    return gemini_proxies, ai_only_proxies, static_game_proxies, smart_dns_providers, base_hosts_urls


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
    ips = resolve_dot_853(provider.get("dot_host"), domain)
    if not ips:
        ips = resolve_doh_rfc8484(provider.get("doh_url"), domain)
    if not ips and provider.get("udp_host"):
        ips = resolve_udp_53(provider.get("udp_host"), domain)
    return ips


def stress_test_https_get(ip, domain, require_google_headers=False, attempts=5):
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
                            if not any(sig in r_low for sig in ("google", "esf", "gws", "sffe", "scaffolding", "__secure-")):
                                continue
                        success += 1
                        total_ms += (time.perf_counter() - start) * 1000
        except Exception:
            pass
    avg_ping = (total_ms / success) if success > 0 else 9999.0
    return success, round(avg_ping, 1)


def stress_test_gemini_dual(ip):
    ok_web, ping_web = stress_test_https_get(ip, "gemini.google.com", require_google_headers=True, attempts=6)
    if ok_web == 0:
        return 0, 9999.0

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
    print(f"=== 0. Загрузка конфигурации серверов из {SERVERS_FILE} ===")
    gemini_proxies, ai_only_proxies, static_game_proxies, smart_dns_providers, base_hosts_urls = load_servers_config()
    print(f" [+] Загружено узлов Gemini: {len(gemini_proxies)}, DNS-доноров: {len(smart_dns_providers)}, списков hosts: {len(base_hosts_urls)}")

    print("\n=== 1. Скачивание актуальных списков hosts ===")
    all_raw_entries = []
    domain_to_hosts_ips = {}
    game_candidates = {dom: list(static_game_proxies.get(dom, [])) for dom in PRIORITY_GAME_DOMAINS}

    for name, url in base_hosts_urls:
        entries = fetch_hosts_file(url)
        if entries:
            print(f" [+] {name}: загружено {len(entries)} записей")
            all_raw_entries.extend(entries)
            for ip, dom in entries:
                if is_valid_proxy_ip(ip):
                    domain_to_hosts_ips.setdefault(dom, []).append((ip, name))
                    if dom in game_candidates:
                        game_candidates[dom].append({"ip": ip, "name": f"{name}({ip})"})

    print("\n=== 2. Живой опрос DNS-доноров по DoT (853), бинарному DoH и UDP ===")
    gemini_candidates = []
    seen_gemini_ips = set()
    android_gateway_ips = {dom: [] for dom in TIER0_ANDROID_APP_DOMAINS}

    for prov in smart_dns_providers:
        if not prov["only_games"]:
            for g_dom in ("gemini.google.com", "appsgenaiserver-pa.googleapis.com"):
                for ip in resolve_smart_provider(prov, g_dom):
                    if ip not in seen_gemini_ips and not ip.startswith(RU_FALLBACK_PREFIXES):
                        print(f" [+] [GEMINI-DNS] {prov['name']} ({g_dom}) -> {ip}")
                        gemini_candidates.append({"ip": ip, "group": 1, "name": f"{prov['name']}({ip})", "bonus": True})
                        seen_gemini_ips.add(ip)

            for app_dom in TIER0_ANDROID_APP_DOMAINS:
                for ip in resolve_smart_provider(prov, app_dom):
                    if not ip.startswith(RU_FALLBACK_PREFIXES):
                        print(f" [+] [ANDROID-APP] {prov['name']} ({app_dom}) -> {ip}")
                        android_gateway_ips[app_dom].append((ip, prov["name"]))

        for game_dom in PRIORITY_GAME_DOMAINS:
            for ip in resolve_smart_provider(prov, game_dom):
                if not ip.startswith(RU_FALLBACK_PREFIXES):
                    print(f" [+] [GAME-DNS] {prov['name']} ({game_dom}) -> {ip}")
                    game_candidates[game_dom].append({"ip": ip, "name": f"{prov['name']}({ip})"})

    for sp in gemini_proxies:
        if sp["ip"] not in seen_gemini_ips:
            gemini_candidates.append({
                "ip": sp["ip"],
                "group": sp["group"],
                "name": sp["name"],
                "bonus": sp["group"] == 1,
            })
            seen_gemini_ips.add(sp["ip"])
    print(f"\n=== 3. Стресс-тест {len(gemini_candidates)} серверов для GEMINI ===")
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

    best_android_app_ips = {}
    for app_dom in TIER0_ANDROID_APP_DOMAINS:
        cand_list = android_gateway_ips.get(app_dom, []) + domain_to_hosts_ips.get(app_dom, [])
        clean_cands = [ip for ip, _ in cand_list if not ip.startswith(RU_FALLBACK_PREFIXES)]
        best_android_app_ips[app_dom] = clean_cands[0] if clean_cands else best_gemini_ip

    print("\n=== 4. Персональный отбор серверов для Claude, Grok, OpenAI, Copilot, Supercell Store ===")
    general_ai_candidates = {c["ip"]: c["name"] for c in tier0_pool}
    general_ai_candidates.update(ai_only_proxies)
    service_winners = {}

    for svc_name, svc_info in TIER1_SERVICE_GROUPS.items():
        t_dom = svc_info["test_domain"]
        svc_pool = dict(general_ai_candidates)
        for ip, src_name in domain_to_hosts_ips.get(t_dom, []):
            if not ip.startswith(RU_FALLBACK_PREFIXES):
                svc_pool.setdefault(ip, f"{src_name}({ip})")
        for prov in smart_dns_providers[:6]:
            if not prov["only_games"]:
                for ip in resolve_smart_provider(prov, t_dom):
                    if not ip.startswith(RU_FALLBACK_PREFIXES):
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

    print("\n=== 5. Стресс-тест игровых прокси Brawl Stars и Clash Royale ===")
    best_game_ips = {}
    for g_dom, g_list in game_candidates.items():
        unique_ips = {}
        for item in g_list:
            if is_valid_proxy_ip(item["ip"]) and not item["ip"].startswith(RU_FALLBACK_PREFIXES):
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

    output_lines = []
    assigned_domains = set()

    output_lines.append(f"# === TIER 0A: GEMINI WEB & CHAT GATEWAYS (CHAMPION: {best_gemini_ip}) ===")
    for dom in TIER0_GEMINI_WEB_DOMAINS:
        d = dom.lower()
        output_lines.append(f"{best_gemini_ip} {d}")
        assigned_domains.add(d)

    output_lines.append("\n# === TIER 0B: GEMINI ANDROID APP GATEWAYS ===")
    for app_dom, app_ip in best_android_app_ips.items():
        d = app_dom.lower()
        output_lines.append(f"{app_ip} {d}")
        assigned_domains.add(d)

    output_lines.append("\n# === TIER 1A: SUPERCELL GAME SERVERS ===")
    for g_dom in PRIORITY_GAME_DOMAINS:
        g_ip = best_game_ips.get(g_dom, "179.254.166.171")
        output_lines.append(f"{g_ip} {g_dom}")
        assigned_domains.add(g_dom)

    output_lines.append("\n# === TIER 1B: PRIORITY AI & SERVICES ===")
    for svc_name, svc_info in TIER1_SERVICE_GROUPS.items():
        svc_ip = service_winners.get(svc_name, best_gemini_ip)
        output_lines.append(f"# --- {svc_name} ({svc_ip}) ---")
        for dom in svc_info["domains"]:
            d = dom.lower()
            if d not in assigned_domains and d not in NEVER_PROXY_DOMAINS:
                output_lines.append(f"{svc_ip} {d}")
                assigned_domains.add(d)

    output_lines.append("\n# === TIER 2: OTHER UNLOCKED SERVICES ===")
    for ip, dom in all_raw_entries:
        if dom not in assigned_domains and dom not in NEVER_PROXY_DOMAINS:
            if is_valid_proxy_ip(ip) and not ip.startswith(RU_FALLBACK_PREFIXES):
                output_lines.append(f"{ip} {dom}")
                assigned_domains.add(dom)
            else:
                output_lines.append(f"{best_gemini_ip} {dom}")
                assigned_domains.add(dom)

    output_lines.append("\n# === TIER 3: FALLBACK & RESERVE SERVERS ===")
    for c in tier3_pool:
        output_lines.append(f"# Fallback candidate: {c['name']} ({c['ip']}) - score {c['ok']}/10")

    with open("smart_hosts.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines) + "\n")

    print(f"\n[✓] Готово! Собрано {len(assigned_domains)} чистых правил для NextDNS.")


if __name__ == "__main__":
    main()
