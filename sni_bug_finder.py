#!/usr/bin/env python3
# ================================================================
#   PRO SNI BUG HOST FINDER v4.2
#   ─────────────────────────────────────────────────────────────
#   FIXES v4.1 → v4.2:
#     [1] check_ech() UnboundLocalError — dns global shadowing fixed
#     [2] bytes.lower() AttributeError  — Python 3 bytes fix
#     [3] asyncio.get_event_loop() → get_running_loop() (3.10+)
#     [4] detect_all_methods() empty CDN → real CDN pass
#     [5] Domain itself always in scan list
#     [6] export_results missing def fixed
#     [7] single_host_menu corrupted input() fixed
#     [8] aiodns query() deprecated → query_dns() with fallback
#   SPEED v4.2:
#     [S1] auto_detect_sni_mismatch: 31×5s serial → 16 threads
#          parallel, 2s timeout, stop after 3 found (~3s max)
#     [S2] auto_domain_fronting: 6×5s serial → 6 threads parallel
#          2s timeout, stop on first found (~3s max)
#   NEW v4.2:
#     [+] BufferOver.run + RapidDNS subdomain sources
#     [+] 3x-ui VPN Config Advisor — protocol/transport/TLS/SNI
#          auto-recommend from scan results
#   ─────────────────────────────────────────────────────────────
#   Install: pip install aiohttp aiodns httpx[http2] curl_cffi dnspython
#   Usage  : python3 sni_bug_finder.py
# ================================================================
#   Install: pip install aiohttp aiodns httpx[http2] curl_cffi dnspython
#   Usage  : python3 sni_bug_finder.py
# ================================================================
from __future__ import annotations
import asyncio, socket, ssl, os, sys, time, json, threading, re, struct
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, List

# ── Optional dependency loader ────────────────────────────────────
def _try_import(name, pkg=None):
    import importlib
    try:
        return importlib.import_module(name)
    except ImportError:
        return None

aiohttp   = _try_import("aiohttp")
aiodns    = _try_import("aiodns")
httpx     = _try_import("httpx")
curl_cffi = _try_import("curl_cffi")
dns       = _try_import("dns")        # dnspython
requests  = _try_import("requests")

# ── Colors ────────────────────────────────────────────────────────
G='\033[92m'; R='\033[91m'; C='\033[96m'; Y='\033[93m'
B='\033[94m'; M='\033[95m'; W='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

plock = threading.Lock()
def sp(t):
    with plock: print(t)

# ================================================================
#  Config
# ================================================================
CONFIG_FILE = "sni_config.json"
DEFAULT_CFG = {
    "threads":           50,
    "timeout":           5,
    "async_concurrency": 200,
    "check_https":       True,
    "check_sni":         True,
    "check_ports":       True,
    "check_http2":       True,
    "check_http3":       False,
    "check_ws_payload":  True,
    "check_fronting":    True,
    "check_ech":         True,
    "use_crtsh":         True,
    "use_alienvault":    True,
    "tls_fingerprint":   "chrome120",
    "ports": [80,443,8080,8443,2052,2053,2082,2083,2086,2087,2095,2096],
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ],
    "tls_profiles": ["chrome120","chrome110","firefox120","safari17","edge120"],
}

def load_cfg():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return {**DEFAULT_CFG, **json.load(f)}
        except: pass
    return DEFAULT_CFG.copy()

def save_cfg(cfg):
    with open(CONFIG_FILE,'w') as f:
        json.dump(cfg, f, indent=2)
    print(G+f"[+] Saved → {CONFIG_FILE}"+W)

# ================================================================
#  CDN / WAF Signatures  (Advanced multi-signal)
# ================================================================
CDN_WAF = {
    "Cloudflare":     {
        "headers":  ["cf-ray","cf-cache-status","cf-connecting-ip","cf-ipcountry"],
        "server":   ["cloudflare"],
        "cookies":  ["__cflb","__cfduid","cf_clearance"],
        "asns":     ["AS13335"],
    },
    "Akamai":         {
        "headers":  ["x-check-cacheable","x-akamai","akamai-cache-status","x-akamai-transformed"],
        "server":   ["akamaighost","akamai"],
        "cookies":  ["ak_bmsc","bm_sz"],
        "asns":     ["AS20940"],
    },
    "AWS CloudFront": {
        "headers":  ["x-amz-cf-id","x-amz-cf-pop","x-cache"],
        "server":   ["cloudfront"],
        "cookies":  [],
        "asns":     ["AS16509"],
    },
    "Fastly":         {
        "headers":  ["x-fastly","x-served-by","x-cache-hits","fastly-restarts"],
        "server":   ["fastly"],
        "cookies":  [],
        "asns":     ["AS54113"],
    },
    "Google CDN":     {
        "headers":  ["x-goog-generation","x-guploader-uploadid","x-google-backends"],
        "server":   ["gws","sffe","google"],
        "cookies":  [],
        "asns":     ["AS15169"],
    },
    "Azure CDN":      {
        "headers":  ["x-azure-ref","x-msedge-ref","x-ec-custom-error","x-fd-int-proxy-id"],
        "server":   ["microsoft-iis","azure"],
        "cookies":  [],
        "asns":     ["AS8075"],
    },
    "Gcore":          {
        "headers":  ["x-id","x-cache"],
        "server":   ["gcore"],
        "cookies":  [],
        "asns":     ["AS199524"],
    },
    "Sucuri WAF":     {
        "headers":  ["x-sucuri-id","x-sucuri-cache"],
        "server":   ["sucuri"],
        "cookies":  ["sucuri_cloudproxy_uuid"],
        "asns":     [],
    },
    "Imperva/Incapsula": {
        "headers":  ["x-iinfo","x-cdn"],
        "server":   ["incapsula"],
        "cookies":  ["incap_ses","visid_incap"],
        "asns":     [],
    },
    "Varnish":        {
        "headers":  ["x-varnish","via"],
        "server":   ["varnish"],
        "cookies":  [],
        "asns":     [],
    },
    "Nginx":          {"headers":[],"server":["nginx"],"cookies":[],"asns":[]},
    "Apache":         {"headers":[],"server":["apache"],"cookies":[],"asns":[]},
    "LiteSpeed":      {"headers":[],"server":["litespeed"],"cookies":[],"asns":[]},
    "OpenResty":      {"headers":[],"server":["openresty"],"cookies":[],"asns":[]},
}

def detect_cdn_advanced(headers: dict, cookies: str = "", ip: str = "") -> List[str]:
    found = []
    h_str = json.dumps(headers).lower()
    c_str = cookies.lower()
    srv   = headers.get("server","").lower()

    for cdn, sigs in CDN_WAF.items():
        matched = False
        for hk in sigs["headers"]:
            if hk in h_str: matched = True; break
        if not matched:
            for sv in sigs["server"]:
                if sv in srv: matched = True; break
        if not matched:
            for ck in sigs["cookies"]:
                if ck in c_str: matched = True; break
        if matched:
            found.append(cdn)
    return list(set(found))

# ================================================================
#  SNI Candidates
# ================================================================
SNI_CANDIDATES = [
    "free.facebook.com","zero.facebook.com","m.facebook.com","web.facebook.com",
    "media.whatsapp.com","static.whatsapp.net","mmg.whatsapp.net",
    "www.google.com","googleapis.com","gstatic.com","clients1.google.com",
    "wap.opera.mini.net","compress.opera-mini.net",
    "en.m.wikipedia.org","www.wikipedia.org",
    "www.speedtest.net","fast.com",
    "cloudflare.com","cdn.cloudflare.com","1.1.1.1",
    "www.youtube.com","www.instagram.com",
    "t.me","telegram.org","web.telegram.org",
    "twitter.com","mobile.twitter.com",
    "zoom.us","api.zoom.us",
    "discord.com","gateway.discord.gg",
]

METHOD_LABELS = {
    "direct_sni":         "Direct-SNI",
    "sni_mismatch":       "SNI-Mismatch",
    "sni_empty":          "Empty-SNI",
    "http_upgrade":       "WS-Upgrade",
    "ws_real_payload":    "WS-Payload★",
    "domain_fronting":    "DomainFront★",
    "http_connect":       "CONNECT",
    "host_header_inject": "HostInject",
    "vless_probe":        "VLESS-Probe",
}

# ================================================================
#  TLS Fingerprint Spoofing  (curl_cffi)
# ================================================================
CURL_CFFI_PROFILES = {
    "chrome120": "chrome120",
    "chrome110": "chrome110",
    "firefox120": "firefox120",
    "safari17":  "safari17_0",
    "edge120":   "edge120",
}

def _get_cffi_session(profile="chrome120"):
    if not curl_cffi: return None
    try:
        from curl_cffi import requests as cffi_req
        impersonate = CURL_CFFI_PROFILES.get(profile, "chrome120")
        return cffi_req.Session(impersonate=impersonate)
    except: return None

# ── Thread-local sessions ─────────────────────────────────────────
_sess_local = threading.local()

def get_session(cfg):
    """curl_cffi → requests fallback, thread-local"""
    if not hasattr(_sess_local, 's'):
        profile = cfg.get("tls_fingerprint", "chrome120")
        cffi_s = _get_cffi_session(profile)
        if cffi_s:
            _sess_local.s      = cffi_s
            _sess_local.is_cffi = True
        elif requests:
            s = requests.Session()
            s.headers['User-Agent'] = _get_ua(cfg)
            a = requests.adapters.HTTPAdapter(
                pool_connections=10, pool_maxsize=20, max_retries=1)
            s.mount('http://', a); s.mount('https://', a)
            _sess_local.s      = s
            _sess_local.is_cffi = False
        else:
            _sess_local.s       = None
            _sess_local.is_cffi = False
    return _sess_local.s, getattr(_sess_local, 'is_cffi', False)

def _get_ua(cfg):
    import random
    return random.choice(cfg.get("user_agents", DEFAULT_CFG["user_agents"]))

# ================================================================
#  HTTP/2 Client  (httpx)
# ================================================================
def http2_get(hostname, timeout=5):
    """httpx HTTP/2 request — protocol negotiate"""
    if not httpx: return None, False
    try:
        with httpx.Client(http2=True, verify=False,
                          timeout=timeout,
                          follow_redirects=True) as client:
            r = client.get(f"https://{hostname}")
            is_h2 = r.http_version == "HTTP/2"
            return r.status_code, is_h2
    except: return None, False

# ================================================================
#  Async DNS Resolver (FIXED FOR TERMUX)
# ================================================================
async def async_resolve(hostname, resolver=None):
    try:
        if resolver:
            # FIX: query() deprecated newer aiodns → query_dns() with fallback
            try:
                result = await resolver.query_dns(hostname, 'A')
                hosts  = [r.host for r in result.get('A', [])]
                return hosts[0] if hosts else None
            except (AttributeError, TypeError):
                result = await resolver.query(hostname, 'A')
                return result[0].host if result else None
        else:
            loop = asyncio.get_running_loop()   # FIX: get_event_loop() deprecated 3.10+
            res  = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            return res[0][4][0] if res else None
    except: return None

async def async_batch_resolve(hostnames, concurrency=100):
    resolved = {}
    resolver = None
    if aiodns:
        try:
            # Termux සඳහා අනිවාර්යයෙන්ම Public DNS ලබා දිය යුතුය
            resolver = aiodns.DNSResolver(nameservers=['8.8.8.8', '1.1.1.1'])
        except: pass

    sem = asyncio.Semaphore(concurrency)

    async def one(h):
        async with sem:
            ip = await async_resolve(h, resolver)
            # aiodns fail වුනොත් සාමාන්‍ය Python DNS වලින් try කිරීම (Fallback)
            if not ip:
                try:
                    loop = asyncio.get_running_loop()   # FIX: get_event_loop deprecated
                    res  = await loop.getaddrinfo(h, None, family=socket.AF_INET)
                    ip   = res[0][4][0] if res else None
                except: pass
            
            if ip:
                resolved[h] = ip

    await asyncio.gather(*[one(h) for h in hostnames])
    return resolved

# ================================================================
#  Wildcard + Filter
# ================================================================
async def detect_wildcard_async(domain):
    import random, string
    rand = ''.join(random.choices(string.ascii_lowercase, k=14)) + '.' + domain
    ip = await async_resolve(rand)
    return ip  # None if no wildcard

def filter_subdomains(subdomains, domain, ip_cache, wildcard_ip):
    filtered, rm_dead, rm_wild = [], 0, 0
    for h in subdomains:
        ip = ip_cache.get(h)
        if not ip:
            rm_dead += 1; continue
        if wildcard_ip and ip == wildcard_ip:
            rm_wild += 1; continue
        filtered.append(h)
    sp(G+f"  [+] Filter: dead={rm_dead}  wildcard={rm_wild}  usable={len(filtered)}"+W)
    return filtered

# ================================================================
#  Port Scanner (async)
# ================================================================
async def async_port_scan(hostname, ports, timeout):
    open_ports = {}
    async def check(p):
        try:
            t0 = time.time()
            _, w = await asyncio.wait_for(
                asyncio.open_connection(hostname, p), timeout=timeout)
            lat = int((time.time()-t0)*1000)
            w.close()
            open_ports[p] = lat
        except: pass
    await asyncio.gather(*[check(p) for p in ports])
    return open_ports

# ================================================================
#  SNI Method 1: Direct SNI
# ================================================================
def method_direct_sni(hostname, port, timeout):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_OPTIONAL
        t0 = time.time()
        with socket.create_connection((hostname,port),timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                lat  = int((time.time()-t0)*1000)
                cert = ss.getpeercert() or {}
                subj = dict(x[0] for x in cert.get('subject',[]))
                san  = [v for t,v in cert.get('subjectAltName',[]) if t=='DNS']
                cip  = ss.cipher()
                return {
                    "works":True,"tls":ss.version(),
                    "cn":subj.get('commonName','?'),
                    "san":san[:4],"expiry":cert.get('notAfter','?'),
                    "cipher":cip[0] if cip else '?',
                    "bits":cip[2] if cip and len(cip)>2 else '?',
                    "latency":lat,
                }
    except: pass
    return {"works":False}

# ================================================================
#  SNI Method 2: SNI Mismatch Auto-detect
# ================================================================
def method_sni_mismatch(real_host, sni_host, port, timeout):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        t0 = time.time()
        with socket.create_connection((real_host,port),timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni_host) as ss:
                lat  = int((time.time()-t0)*1000)
                cert = ss.getpeercert(binary_form=False) or {}
                subj = dict(x[0] for x in cert.get('subject',[])) if cert else {}
                return {"works":True,"tls":ss.version(),
                        "cn":subj.get('commonName','?'),"latency":lat}
    except: pass
    return {"works":False}

def auto_detect_sni_mismatch(hostname, port, timeout):
    """
    SPEED FIX: Serial 31×5s=155s → Parallel 16 threads, 2s timeout, stop after 3 found.
    """
    working = []
    w_lock  = threading.Lock()
    stop_ev = threading.Event()
    fast_to = min(timeout, 2)   # 2s per attempt — TLS handshake fast enough

    def try_one(candidate):
        if stop_ev.is_set(): return
        r = method_sni_mismatch(hostname, candidate, port, fast_to)
        if r.get("works"):
            r["sni"] = candidate
            with w_lock:
                working.append(r)
                if len(working) >= 3:   # 3 working SNIs enough
                    stop_ev.set()

    from concurrent.futures import ThreadPoolExecutor as _TPE, wait as _wait
    with _TPE(max_workers=16) as ex:
        futs = [ex.submit(try_one, c) for c in SNI_CANDIDATES]
        _wait(futs, timeout=fast_to + 1)   # overall max wait: 3s

    return working

# ================================================================
#  SNI Method 3: Empty SNI
# ================================================================
def method_sni_empty(hostname, port, timeout):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        t0 = time.time()
        with socket.create_connection((hostname,port),timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=None) as ss:
                return {"works":True,"tls":ss.version(),
                        "latency":int((time.time()-t0)*1000)}
    except: pass
    return {"works":False}

# ================================================================
#  SNI Method 4: WebSocket Real Payload Test  ★ NEW
# ================================================================
def method_ws_real_payload(hostname, port, timeout, sni_host=None):
    """
    සැබෑ WebSocket handshake request — 101 Switching Protocols expect.
    Plain TCP handshake ලෙස නොව, real WS payload test.
    sni_host: SNI mismatch mode ගැනීමට (domain fronting + WS combined)
    """
    import base64, hashlib
    # Random WS key
    ws_key = base64.b64encode(os.urandom(16)).decode()

    try:
        use_tls = port in [443,8443,2053,2083,2087,2096]
        t0 = time.time()

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = socket.create_connection((hostname,port),timeout=timeout)
            sni = sni_host or hostname
            sock = ctx.wrap_socket(raw, server_hostname=sni)
        else:
            sock = socket.create_connection((hostname,port),timeout=timeout)

        host_header = sni_host or hostname
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Origin: https://{host_header}\r\n\r\n"
        )
        sock.sendall(req.encode())
        sock.settimeout(timeout)
        resp = b""
        try:
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(1024)
                if not chunk: break
                resp += chunk
        except: pass
        sock.close()

        resp_str = resp.decode(errors='ignore')
        lat = int((time.time()-t0)*1000)

        if "101" in resp_str.split('\r\n')[0] if resp_str else False:
            # Verify server WS accept key
            expected = base64.b64encode(
                hashlib.sha1((ws_key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            key_ok = expected in resp_str
            return {"works":True,"latency":lat,"code":"101",
                    "key_verified":key_ok,"response":resp_str[:120]}
        elif "200" in resp_str[:20]:
            return {"works":True,"latency":lat,"code":"200","response":resp_str[:120]}
        elif resp_str:
            code = resp_str.split(' ')[1] if len(resp_str.split(' '))>1 else '?'
            return {"works":False,"code":code,"response":resp_str[:80]}
    except: pass
    return {"works":False}

# ================================================================
#  SNI Method 5: Domain Fronting  ★ NEW (Enhanced)
# ================================================================
def method_domain_fronting(real_host, front_sni, real_backend, port, timeout):
    """
    Domain Fronting:
      TCP  → real_host (CDN IP)
      SNI  → front_sni  (allowed/zero-rated domain)
      Host → real_backend (actual target server)

    CDN edges SNI දකිනවා, Host header ලෙස proxy කරනවා.
    Cloudflare, Fastly, Akamai ඉහළ CDN ඒවා support කරනවා.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        t0 = time.time()

        with socket.create_connection((real_host,port),timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=front_sni) as ss:
                req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {real_backend}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                ss.sendall(req.encode())
                ss.settimeout(timeout)
                resp = b""
                try:
                    while True:
                        c = ss.recv(2048)
                        if not c: break
                        resp += c
                        if len(resp) > 4096: break
                except: pass

        lat  = int((time.time()-t0)*1000)
        text = resp.decode(errors='ignore')
        code = text.split(' ')[1] if len(text.split(' '))>1 else '?'

        if code in ['200','301','302','307','308','101']:
            return {"works":True,"code":code,"latency":lat,
                    "front_sni":front_sni,"backend":real_backend,
                    "response_snippet":text[:100]}
    except: pass
    return {"works":False}

def auto_domain_fronting(hostname, cdn_list, port, timeout):
    """
    SPEED FIX: Serial 6×5s=30s → Parallel 6 threads, 2s timeout, stop on first found.
    """
    front_candidates = [
        "free.facebook.com","zero.facebook.com",
        "www.wikipedia.org","en.m.wikipedia.org",
        "www.google.com","www.youtube.com",
        "zoom.us","discord.com",
        "www.speedtest.net",
    ]
    fast_to  = min(timeout, 2)
    result   = {"works": False}
    r_lock   = threading.Lock()
    found_ev = threading.Event()

    def try_front(front):
        if found_ev.is_set(): return
        r = method_domain_fronting(hostname, front, hostname, port, fast_to)
        if r.get("works"):
            with r_lock:
                if not found_ev.is_set():
                    result.update(r)
                    found_ev.set()

    from concurrent.futures import ThreadPoolExecutor as _TPE, wait as _wait
    with _TPE(max_workers=6) as ex:
        futs = [ex.submit(try_front, f) for f in front_candidates[:6]]
        _wait(futs, timeout=fast_to + 1)   # max 3s total

    return result

# ================================================================
#  SNI Method 6: VLESS Protocol Probe  ★ NEW
# ================================================================
def method_vless_probe(hostname, port, timeout):
    """
    Basic VLESS handshake probe.
    VLESS v0 header: version(1) + UUID(16) + addon_len(1) + cmd(1) + port(2) + addr_type(1)
    Server respond කළොත් VLESS capable.
    """
    import uuid, struct
    try:
        use_tls = port in [443,8443,2053,2083,2087,2096]
        t0 = time.time()

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            raw  = socket.create_connection((hostname,port),timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=hostname)
        else:
            sock = socket.create_connection((hostname,port),timeout=timeout)

        # VLESS request header (version 0)
        uid   = uuid.uuid4().bytes   # 16 bytes random UUID
        # cmd=1 (TCP), port=443, addr_type=2 (domain), addr=google.com
        target_host = b"google.com"
        payload = (
            b'\x00'             # version
            + uid               # UUID
            + b'\x00'           # addon length = 0
            + b'\x01'           # cmd TCP
            + struct.pack('>H', 443)  # target port
            + b'\x02'           # addr type: domain
            + bytes([len(target_host)])
            + target_host
        )
        sock.sendall(payload)
        sock.settimeout(min(timeout, 3))

        resp = b""
        try:
            resp = sock.recv(256)
        except: pass
        sock.close()
        lat = int((time.time()-t0)*1000)

        # VLESS response: version(1) + addon_len(1)
        if len(resp) >= 2 and resp[0] == 0x00:
            return {"works":True,"latency":lat,"response_len":len(resp)}
        # Connection accept කළත් VLESS response නැත්නම් partial
        elif resp:
            return {"works":False,"partial":True,"latency":lat}
    except: pass
    return {"works":False}

# ================================================================
#  SNI Method 7: HTTP CONNECT
# ================================================================
def method_http_connect(hostname, port, timeout):
    try:
        t0 = time.time()
        s  = socket.create_connection((hostname,port),timeout=timeout)
        s.sendall(f"CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}\r\n\r\n".encode())
        resp = s.recv(256).decode(errors='ignore')
        s.close()
        if "200" in resp:
            return {"works":True,"latency":int((time.time()-t0)*1000)}
    except: pass
    return {"works":False}

# ================================================================
#  ECH (Encrypted Client Hello) Detection  ★ NEW
# ================================================================
def check_ech(hostname, timeout=5):
    """
    DNS HTTPS (type 65) / SVCB record lookup හරහා
    ECH public key ඇත්දැයි detect කරනවා.
    Bug Fix: dns global variable shadowing fixed — inner import removed.
    """
    result = {"supported":False,"ech_key":None,"alpn":[],"ipv4hint":[]}

    # Method A: dnspython  ── FIX: use global `dns`, do NOT re-import inside function
    _dns = dns   # capture global to avoid UnboundLocalError from any inner import
    if _dns:
        try:
            # Sub-modules import via attribute access only — avoids shadowing global
            dns_resolver  = _dns.resolver   if hasattr(_dns, 'resolver')  else None
            if dns_resolver is None:
                import importlib
                dns_resolver = importlib.import_module('dns.resolver')
            ans = dns_resolver.resolve(hostname, 'HTTPS', lifetime=timeout)
            for rdata in ans:
                rdata_str = str(rdata)
                if 'ech=' in rdata_str.lower():
                    result["supported"] = True
                    m = re.search(r'ech=([A-Za-z0-9+/=]+)', rdata_str, re.I)
                    if m: result["ech_key"] = m.group(1)[:40]+"..."
                if 'alpn=' in rdata_str.lower():
                    m = re.search(r'alpn="([^"]+)"', rdata_str)
                    if m: result["alpn"] = m.group(1).split(',')
            return result
        except Exception:
            pass

    # Method B: raw UDP DNS query (type 65 = HTTPS record)
    # FIX: bytes object has no .lower() in Python 3 — use plain 'in' or decode first
    try:
        def build_dns_query(name):
            qid     = os.urandom(2)
            flags   = b'\x01\x00'   # recursion desired
            qdcount = b'\x00\x01'
            zeros   = b'\x00\x00'
            header  = qid + flags + qdcount + zeros + zeros + zeros
            parts   = name.split('.')
            qname   = b''
            for p in parts:
                qname += bytes([len(p)]) + p.encode()
            qname  += b'\x00'
            qtype   = b'\x00\x41'   # type 65 = HTTPS
            qclass  = b'\x00\x01'   # IN
            return header + qname + qtype + qclass

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        udp.sendto(build_dns_query(hostname), ("8.8.8.8", 53))
        data, _ = udp.recvfrom(4096)
        udp.close()
        # FIX: bytes.lower() does not exist — decode then check
        data_lower = data.decode(errors='ignore').lower()
        if 'ech' in data_lower:
            result["supported"] = True
            # Try extract ECH key from raw bytes (base64 portion)
            m = re.search(r'ech=([A-Za-z0-9+/=]+)', data_lower)
            if m: result["ech_key"] = m.group(1)[:40]
    except Exception:
        pass

    return result

# ================================================================
#  HTTP/2 + HTTP/3 Check
# ================================================================
def check_http2_httpx(hostname, timeout=5):
    """httpx HTTP/2 — accurate ALPN-based check"""
    if httpx:
        try:
            with httpx.Client(http2=True, verify=False,
                              timeout=timeout, follow_redirects=True) as cl:
                r = cl.get(f"https://{hostname}")
                return r.status_code, r.http_version == "HTTP/2"
        except: pass

    # Fallback: ALPN via ssl
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2','http/1.1'])
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname,443),timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                is_h2 = ss.selected_alpn_protocol() == 'h2'
                return None, is_h2
    except: pass
    return None, False

def check_http3_quic(hostname, timeout=3):
    """
    HTTP/3 (QUIC) support — Alt-Svc header check.
    Full QUIC handshake requires aioquic library.
    """
    result = {"supported": False, "alt_svc": None}
    try:
        sess, _ = get_session({"tls_fingerprint":"chrome120","user_agents":DEFAULT_CFG["user_agents"]})
        if sess:
            r = sess.get(f"https://{hostname}", timeout=timeout, verify=False)
            alt = r.headers.get("alt-svc","")
            if "h3" in alt or "quic" in alt.lower():
                result["supported"] = True
                result["alt_svc"]   = alt[:80]
    except: pass
    return result

# ================================================================
#  Full Method Detection (per host)
# ================================================================
def detect_all_methods(hostname, open_ports, timeout, bug_sni, cfg, known_cdn=None):
    methods = {}
    has_443 = 443 in open_ports
    has_80  = 80  in open_ports
    tls_port = next((p for p in [443,8443,2053,2083,2087,2096] if p in open_ports), None)
    tcp_port = next((p for p in [80,8080] if p in open_ports), None)
    any_port = next(iter(open_ports), None)

    # 1. Direct SNI
    methods["direct_sni"] = method_direct_sni(hostname, 443, timeout) \
        if has_443 else method_direct_sni(hostname, tls_port, timeout) \
        if tls_port else {"works":False}

    # 2. SNI Mismatch (auto or manual)
    if tls_port:
        if bug_sni == "auto":
            found = auto_detect_sni_mismatch(hostname, tls_port, timeout)
            if found:
                best = min(found, key=lambda x: x["latency"])
                methods["sni_mismatch"] = {
                    "works":True,"tls":best["tls"],"cn":best["cn"],
                    "latency":best["latency"],"sni_used":best["sni"],
                    "all_working":found,
                }
            else:
                methods["sni_mismatch"] = {"works":False}
        else:
            r = method_sni_mismatch(hostname, bug_sni, tls_port, timeout)
            if r.get("works"): r["sni_used"] = bug_sni
            methods["sni_mismatch"] = r
    else:
        methods["sni_mismatch"] = {"works":False}

    # 3. Empty SNI
    methods["sni_empty"] = method_sni_empty(hostname, tls_port, timeout) \
        if tls_port else {"works":False}

    # 4. WebSocket Real Payload ★
    if cfg.get("check_ws_payload",True) and any_port:
        sni_host = methods["sni_mismatch"].get("sni_used") \
            if methods["sni_mismatch"].get("works") else None
        ws_port  = next((p for p in [80,8080,443,8443] if p in open_ports), None)
        if ws_port:
            methods["ws_real_payload"] = method_ws_real_payload(
                hostname, ws_port, timeout, sni_host)
        else:
            methods["ws_real_payload"] = {"works":False}
    else:
        methods["ws_real_payload"] = {"works":False}

    # 5. Domain Fronting ★
    if cfg.get("check_fronting",True) and tls_port:
        cdn = known_cdn or []   # FIX: was detect_cdn_advanced({}) — now uses real CDN list
        methods["domain_fronting"] = auto_domain_fronting(hostname, cdn, tls_port, timeout)
    else:
        methods["domain_fronting"] = {"works":False}

    # 6. HTTP CONNECT
    cp = tcp_port or (443 if has_443 else None)
    methods["http_connect"] = method_http_connect(hostname, cp, timeout) \
        if cp else {"works":False}

    # 7. Host Header Inject
    if has_80:
        front = methods["sni_mismatch"].get("sni_used","free.facebook.com")
        try:
            t0 = time.time()
            s  = socket.create_connection((hostname,80),timeout=timeout)
            s.sendall(f"GET / HTTP/1.1\r\nHost: {front}\r\nConnection: close\r\n\r\n".encode())
            resp = s.recv(512).decode(errors='ignore')
            s.close()
            parts= resp.split('\r\n')[0].split(' ') if resp else []
            code = parts[1] if len(parts)>1 else ''
            methods["host_header_inject"] = {
                "works": code in ['200','301','302','307','308'],
                "code":  code,
                "latency": int((time.time()-t0)*1000),
            }
        except:
            methods["host_header_inject"] = {"works":False}
    else:
        methods["host_header_inject"] = {"works":False}

    # 8. VLESS Probe ★
    if tls_port:
        methods["vless_probe"] = method_vless_probe(hostname, tls_port, timeout)
    else:
        methods["vless_probe"] = {"works":False}

    return methods

# ================================================================
#  Adaptive Timeout
# ================================================================
def adaptive_timeout(base, lat_ms):
    if lat_ms is None:   return base
    if lat_ms < 100:     return max(2, base-1)
    if lat_ms < 400:     return base
    return min(base+2, 10)

# ================================================================
#  Subdomain Discovery
# ================================================================
import urllib.request, urllib.parse

def _fetch(url, timeout=12):
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"SNI-BugFinder/4.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode(errors='ignore')
    except: return ""

def subs_hackertarget(domain, timeout):
    out = set()
    txt = _fetch(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout)
    for line in txt.strip().split('\n'):
        if ',' in line:
            s = line.split(',')[0].strip()
            if s: out.add(s)
    return out

def subs_crtsh(domain, timeout):
    out = set()
    txt = _fetch(f"https://crt.sh/?q=%.{domain}&output=json", timeout+5)
    try:
        for e in json.loads(txt):
            for n in e.get('name_value','').split('\n'):
                n = n.strip().lstrip('*.')
                if n and domain in n: out.add(n)
    except: pass
    return out

def subs_alienvault(domain, timeout):
    out = set()
    txt = _fetch(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",timeout)
    try:
        for rec in json.loads(txt).get('passive_dns',[]):
            h = rec.get('hostname','')
            if h and domain in h: out.add(h)
    except: pass
    return out

def subs_bufferover(domain, timeout):
    """BufferOver.run — free alternative subdomain source"""
    out = set()
    txt = _fetch(f"https://dns.bufferover.run/dns?q=.{domain}", timeout)
    try:
        data = json.loads(txt)
        for rec in data.get('FDNS_A', []) + data.get('RDNS', []):
            parts = rec.split(',')
            host  = parts[-1].strip().rstrip('.')
            if host and domain in host: out.add(host)
    except: pass
    return out

def subs_rapiddns(domain, timeout):
    """RapidDNS — additional subdomain enumeration"""
    out = set()
    txt = _fetch(f"https://rapiddns.io/subdomain/{domain}?full=1", timeout+5)
    for m in re.finditer(r'([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', txt):
        out.add(m.group(1).strip())
    return out

def collect_subdomains(domain, cfg):
    all_subs = set()
    timeout  = cfg["timeout"]
    print(C+"\n  [*] Subdomain Sources:\n"+W)

    # Always include domain itself
    all_subs.add(domain)

    print(C+"    → HackerTarget     ..."+W, end='', flush=True)
    ht = subs_hackertarget(domain, timeout)
    all_subs |= ht; print(G+f" {len(ht)} found"+W)

    if cfg["use_crtsh"]:
        print(C+"    → CRT.sh (SSL)     ..."+W, end='', flush=True)
        crt = subs_crtsh(domain, timeout)
        all_subs |= crt; print(G+f" {len(crt)} found"+W)

    if cfg["use_alienvault"]:
        print(C+"    → AlienVault OTX   ..."+W, end='', flush=True)
        av = subs_alienvault(domain, timeout)
        all_subs |= av; print(G+f" {len(av)} found"+W)

    # Extra sources
    print(C+"    → BufferOver.run   ..."+W, end='', flush=True)
    bo = subs_bufferover(domain, timeout)
    all_subs |= bo; print(G+f" {len(bo)} found"+W)

    print(C+"    → RapidDNS         ..."+W, end='', flush=True)
    rd = subs_rapiddns(domain, timeout)
    all_subs |= rd; print(G+f" {len(rd)} found"+W)

    print(G+f"\n  [+] Total unique subdomains: {len(all_subs)}"+W)
    return sorted(all_subs)

# ================================================================
#  Main Host Scanner
# ================================================================
def scan_host(hostname, cfg, bug_sni, pre_ip=None, _retry=1):
    result = {
        "host":            hostname,
        "ip":              pre_ip,
        "http_status":     None,
        "https_status":    None,
        "h2_status":       None,
        "server":          None,
        "cdn":             [],
        "open_ports":      {},
        "http2":           False,
        "http3":           {},
        "ech":             {},
        "sni_methods":     {},
        "working_methods": [],
        "bug_score":       0,
        "is_bug_host":     False,
        "redirect_to":     None,
        "latency_ms":      None,
        "tls_fingerprint": cfg.get("tls_fingerprint","requests"),
    }
    timeout  = cfg["timeout"]
    sess, is_cffi = get_session(cfg)

    # IP
    if not result["ip"]:
        try: result["ip"] = socket.gethostbyname(hostname)
        except: pass

    # Port scan
    if cfg["check_ports"]:
        result["open_ports"] = {}
        for p in cfg["ports"]:
            try:
                t0   = time.time()
                sock = socket.create_connection((hostname,p),timeout=min(timeout,3))
                lat  = int((time.time()-t0)*1000)
                sock.close()
                result["open_ports"][p] = lat
            except: pass
    else:
        result["open_ports"] = {80:0,443:0}

    op = result["open_ports"]

    # HTTP (via curl_cffi or requests)
    def _get(url, to):
        if sess:
            if is_cffi:
                return sess.get(url, timeout=to, allow_redirects=True,
                                verify=False)
            else:
                return sess.get(url, timeout=to, allow_redirects=True,
                                verify=False)
        return None

    if 80 in op or not cfg["check_ports"]:
        try:
            t0 = time.time()
            r  = _get(f"http://{hostname}", timeout)
            if r:
                result["http_status"] = r.status_code
                result["latency_ms"]  = int((time.time()-t0)*1000)
                result["server"]      = r.headers.get('Server','') or r.headers.get('server','')
                ck = r.headers.get('Set-Cookie','')
                result["cdn"]         = detect_cdn_advanced(dict(r.headers), ck, result["ip"] or "")
                if hasattr(r,'history') and r.history:
                    result["redirect_to"] = r.url
        except: pass

    # Adaptive timeout after HTTP latency
    timeout = adaptive_timeout(timeout, result["latency_ms"])

    if cfg["check_https"] and (443 in op or not cfg["check_ports"]):
        try:
            r2 = _get(f"https://{hostname}", timeout)
            if r2:
                result["https_status"] = r2.status_code
                if not result["server"]:
                    result["server"] = r2.headers.get('Server','')
                ck2 = r2.headers.get('Set-Cookie','')
                result["cdn"] = list(set(result["cdn"]
                    + detect_cdn_advanced(dict(r2.headers), ck2, result["ip"] or "")))
        except: pass

    # HTTP/2 via httpx
    if cfg.get("check_http2") and 443 in op:
        h2_code, is_h2 = check_http2_httpx(hostname, timeout)
        result["http2"]      = is_h2
        result["h2_status"]  = h2_code

    # HTTP/3 Alt-Svc check
    if cfg.get("check_http3") and 443 in op:
        result["http3"] = check_http3_quic(hostname, timeout)

    # ECH check
    if cfg.get("check_ech"):
        result["ech"] = check_ech(hostname, timeout)

    # All SNI methods
    if cfg["check_sni"]:
        result["sni_methods"]     = detect_all_methods(
            hostname, op, timeout, bug_sni, cfg, known_cdn=result["cdn"])
        result["working_methods"] = [m for m,v in result["sni_methods"].items()
                                     if v.get("works")]

    # Bug Score ──────────────────────────────────────────────────
    s = 0
    m = result["sni_methods"]
    if result["http_status"]  == 200:  s += 10
    if result["https_status"] == 200:  s += 10
    if result["http2"]:                s += 5
    if result["http3"].get("supported"):s += 3
    if result["ech"].get("supported"): s += 5
    if m.get("direct_sni",        {}).get("works"): s += 12
    if m.get("sni_mismatch",      {}).get("works"): s += 30  # highest
    if m.get("sni_empty",         {}).get("works"): s += 8
    if m.get("ws_real_payload",   {}).get("works"): s += 20  # real payload
    if m.get("domain_fronting",   {}).get("works"): s += 20  # domain fronting
    if m.get("http_connect",      {}).get("works"): s += 8
    if m.get("host_header_inject",{}).get("works"): s += 8
    if m.get("vless_probe",       {}).get("works"): s += 15  # VLESS
    if any(c in result["cdn"] for c in ["Cloudflare","Akamai","Fastly","AWS CloudFront"]): s += 4

    result["bug_score"]   = min(s, 100)
    result["is_bug_host"] = result["bug_score"] >= 50
    return result

# ================================================================
#  Progress + Milestone
# ================================================================
def progress_bar(done, total, label="", eta=""):
    if total == 0: return
    f   = int(40 * done / total)
    bar = G + "█"*f + DIM + "░"*(40-f) + W
    with plock:
        sys.stdout.write(f"\r  {C}{label}{W} [{bar}] {Y}{done}/{total}{W} {DIM}{eta}{W}  ")
        sys.stdout.flush()

def milestone_table(results, pct, total):
    bugs = [r for r in results if r["is_bug_host"]]
    sp(C + f"\n\n  ── {pct}% ({len(results)}/{total}) │ Bug hosts: {len(bugs)} ──" + W)
    for r in sorted(bugs, key=lambda x: x["bug_score"], reverse=True)[:5]:
        sc = G if r['bug_score'] >= 70 else Y
        ms = ' '.join(METHOD_LABELS.get(m,m) for m in r.get('working_methods',[]))
        sp(G + f"  ★ {r['host']:<42}" + sc + f" {r['bug_score']}%" + W
           + C + f"  [{ms}]" + W)

# ================================================================
#  Async Scan Runner
# ================================================================
async def _async_runner(subdomains, cfg, bug_sni, ip_cache):
    """
    asyncio event loop ඇතුලේ:
    1. Async DNS resolve
    2. Wildcard detect
    3. Sync scan_host thread pool ලෙස run
    """
    sem      = asyncio.Semaphore(cfg.get("async_concurrency", 200))
    results  = []
    r_lock   = asyncio.Lock()
    counter  = {"n": 0}
    total    = len(subdomains)
    t_start  = time.time()
    milestones_hit = set()

    loop = asyncio.get_running_loop()   # FIX: get_event_loop() deprecated Python 3.10+
    executor = ThreadPoolExecutor(max_workers=cfg["threads"])

    async def worker(h):
        async with sem:
            pre_ip = ip_cache.get(h)
            res = await loop.run_in_executor(
                executor, scan_host, h, cfg, bug_sni, pre_ip)
            async with r_lock:
                results.append(res)
                n = counter["n"] + 1
                counter["n"] = n
                elapsed = time.time() - t_start
                speed   = n / elapsed if elapsed > 0 else 1
                eta_s   = int((total-n)/speed) if speed > 0 else 0
                eta_str = f"ETA:{eta_s}s"
                progress_bar(n, total, "Scanning", eta_str)
                pct = int(n / total * 100)
                for mp in [25,50,75]:
                    if pct >= mp and mp not in milestones_hit:
                        milestones_hit.add(mp)
                        milestone_table(results[:], mp, total)

    await asyncio.gather(*[worker(h) for h in subdomains])
    executor.shutdown(wait=False)
    return results

def run_scan(subdomains, cfg, bug_sni, domain=""):
    total = len(subdomains)
    print(C + f"\n  Mode: {'curl_cffi TLS-Spoof' if curl_cffi else 'standard requests'}"
              f" | HTTP2: {'httpx' if httpx else 'ssl-alpn'}"
              f" | Async-concurrency: {cfg.get('async_concurrency',200)}" + W)
    print(C + f"  Threads: {cfg['threads']} | Timeout: {cfg['timeout']}s"
              f" | Bug-SNI: {bug_sni}" + W)

    # Step 1: Async DNS resolve
    print(C + "\n  [1/3] DNS pre-resolving (async)..." + W, end='', flush=True)
    ip_cache = asyncio.run(async_batch_resolve(subdomains, concurrency=150))
    print(G + f" {len(ip_cache)}/{total} resolved" + W)

    # Step 2: Wildcard + filter
    print(C + "  [2/3] Wildcard & dead host filter..." + W)
    wildcard_ip = asyncio.run(detect_wildcard_async(domain)) if domain else None
    if wildcard_ip:
        print(Y + f"  [!] Wildcard *.{domain} = {wildcard_ip} — filter කරනවා" + W)
    subdomains = filter_subdomains(subdomains, domain, ip_cache, wildcard_ip)
    total      = len(subdomains)
    if not total:
        print(R + "  [-] Usable hosts නෑ!" + W); return []

    # Step 3: Async scan
    print(C + f"  [3/3] Scanning {total} hosts (async + thread pool)...\n" + W)
    print(C + "  " + "─"*90 + W)

    results = asyncio.run(_async_runner(subdomains, cfg, bug_sni, ip_cache))
    print()

    # Dedup same-IP
    best_ip = {}
    for r in results:
        ip = r.get("ip")
        if ip:
            if ip not in best_ip or r["bug_score"] > best_ip[ip]["bug_score"]:
                best_ip[ip] = r
        else:
            best_ip[id(r)] = r  # no IP — keep as-is

    removed = len(results) - len(best_ip)
    if removed:
        print(Y + f"  [*] Dedup: {removed} same-server hosts removed" + W)

    results = sorted(best_ip.values(), key=lambda x: x["bug_score"], reverse=True)
    return list(results)

# ================================================================
#  Score color helper
# ================================================================
def sc(n):
    if n>=70: return G+BOLD
    if n>=40: return Y
    return R

# ================================================================
#  Results Display
# ================================================================
def display_results(results, domain):
    bugs      = [r for r in results if r["is_bug_host"]]
    mismatches= [r for r in results if r["sni_methods"].get("sni_mismatch",{}).get("works")]
    ws_ok     = [r for r in results if r["sni_methods"].get("ws_real_payload",{}).get("works")]
    front_ok  = [r for r in results if r["sni_methods"].get("domain_fronting",{}).get("works")]
    vless_ok  = [r for r in results if r["sni_methods"].get("vless_probe",{}).get("works")]
    ech_ok    = [r for r in results if r.get("ech",{}).get("supported")]
    h2_ok     = [r for r in results if r["http2"]]
    h3_ok     = [r for r in results if r.get("http3",{}).get("supported")]
    tls_fp    = results[0].get("tls_fingerprint","?") if results else "?"

    print(G+f"\n{'═'*75}"+W)
    print(G+f"  SCAN COMPLETE — {domain}"+W)
    print(C+f"  TLS Fingerprint : {tls_fp} ({'curl_cffi' if curl_cffi else 'ssl fallback'})"+W)
    print(C+f"  Total Scanned   : {len(results)}"+W)
    print(G+f"  Bug Hosts       : {len(bugs)}"+W)
    print(M+f"  SNI Mismatch    : {len(mismatches)}"+W)
    print(G+f"  WS Real Payload : {len(ws_ok)}"+W)
    print(Y+f"  Domain Fronting : {len(front_ok)}"+W)
    print(B+f"  VLESS Probe     : {len(vless_ok)}"+W)
    print(B+f"  HTTP/2          : {len(h2_ok)}"+W)
    print(C+f"  HTTP/3 (QUIC)   : {len(h3_ok)}"+W)
    print(M+f"  ECH Support     : {len(ech_ok)}"+W)
    print(G+f"{'═'*75}\n"+W)

    # ── Table 1: Bug Hosts ───────────────────────────────────────
    if bugs:
        print(G+BOLD+f"[★] BUG HOSTS ({len(bugs)})\n"+W)
        print(C+f"  {'HOST':<38} {'IP':<16} {'H'}>4 {'S'}>5 "
                f"{'H2':>3} {'CDN':<14} {'SCORE':>6}  METHODS"+W)
        print(C+"  "+"─"*112+W)
        for r in bugs:
            ip      = r["ip"] or "?"
            hs      = str(r["http_status"])  if r["http_status"]  else "---"
            ss      = str(r["https_status"]) if r["https_status"] else "---"
            cdn     = ','.join(r["cdn"][:2]) if r["cdn"] else "—"
            h2      = G+"✔"+W if r["http2"] else DIM+"—"+W
            methods = " ".join(G+METHOD_LABELS.get(m,m)+W for m in r["working_methods"])
            print(f"  {G}{r['host']:<38}{W} {DIM}{ip:<16}{W} "
                  f"{hs:>4} {ss:>5} {h2:>3} "
                  f"{M}{cdn:<14}{W} {sc(r['bug_score'])}{r['bug_score']:>5}%{W}  {methods}")

    # ── Table 2: SNI Mismatch Detail ─────────────────────────────
    if mismatches:
        print(M+BOLD+f"\n[SNI-MISMATCH] Detail ({len(mismatches)})\n"+W)
        print(C+f"  {'HOST':<38} {'SNI USED':<28} {'TLS':>9} {'CN':<28} {'LAT':>7}"+W)
        print(C+"  "+"─"*115+W)
        for r in mismatches:
            mm  = r["sni_methods"]["sni_mismatch"]
            all_w = mm.get("all_working",[])
            print(M+f"  {r['host']:<38}{W} {G}{mm.get('sni_used','?'):<28}{W} "
                  f"{B}{mm.get('tls','?'):>9}{W} {mm.get('cn','?'):<28} "
                  f"{Y}{mm.get('latency','?')}ms{W}")
            if len(all_w) > 1:
                print(DIM+"    ↳ All working: "
                      +", ".join(f"{x['sni']}({x.get('latency','?')}ms)" for x in all_w)+W)

    # ── Table 3: WS Real Payload ★ ────────────────────────────────
    if ws_ok:
        print(G+BOLD+f"\n[WS-PAYLOAD★] Real WebSocket Payload Works ({len(ws_ok)})\n"+W)
        print(C+f"  {'HOST':<40} {'CODE':>5} {'KEY-OK':>7} {'LAT':>7}  SNIPPET"+W)
        print(C+"  "+"─"*95+W)
        for r in ws_ok:
            w   = r["sni_methods"]["ws_real_payload"]
            ko  = G+"✔"+W if w.get("key_verified") else Y+"?"+W
            snip= w.get("response","")[:50].replace('\r','').replace('\n','│')
            print(G+f"  {r['host']:<40}{W} {w.get('code','?'):>5} {ko:>7} "
                  f"{Y}{w.get('latency','?')}ms{W}  {DIM}{snip}{W}")

    # ── Table 4: Domain Fronting ★ ────────────────────────────────
    if front_ok:
        print(Y+BOLD+f"\n[DOMAIN-FRONTING★] ({len(front_ok)})\n"+W)
        print(C+f"  {'HOST':<38} {'FRONT SNI':<28} {'CODE':>5} {'LAT':>7}"+W)
        print(C+"  "+"─"*85+W)
        for r in front_ok:
            f = r["sni_methods"]["domain_fronting"]
            print(Y+f"  {r['host']:<38}{W} {G}{f.get('front_sni','?'):<28}{W} "
                  f"{f.get('code','?'):>5} {Y}{f.get('latency','?')}ms{W}")

    # ── Table 5: VLESS Probe ★ ────────────────────────────────────
    if vless_ok:
        print(B+BOLD+f"\n[VLESS-PROBE★] ({len(vless_ok)})\n"+W)
        for r in vless_ok:
            v = r["sni_methods"]["vless_probe"]
            print(B+f"  {r['host']:<42}{W} latency:{Y}{v.get('latency','?')}ms{W}")

    # ── Table 6: ECH Detection ────────────────────────────────────
    if ech_ok:
        print(M+BOLD+f"\n[ECH] Encrypted Client Hello Support ({len(ech_ok)})\n"+W)
        print(C+f"  {'HOST':<42} {'ALPN':<15} ECH KEY"+W)
        print(C+"  "+"─"*80+W)
        for r in ech_ok:
            e = r.get("ech",{})
            alpn = ','.join(e.get("alpn",[])) or "?"
            key  = e.get("ech_key","?") or "detected"
            print(M+f"  {r['host']:<42}{W} {B}{alpn:<15}{W} {DIM}{key}{W}")

    # ── Table 7: HTTP/2 + HTTP/3 ─────────────────────────────────
    if h2_ok or h3_ok:
        print(B+BOLD+f"\n[HTTP/2+3] Modern Protocol Support\n"+W)
        print(C+f"  {'HOST':<42} {'HTTP/2':>7} {'HTTP/3 (QUIC)':>15} ALT-SVC"+W)
        print(C+"  "+"─"*85+W)
        for r in results:
            h2 = r["http2"]
            h3 = r.get("http3",{})
            if h2 or h3.get("supported"):
                alt = h3.get("alt_svc","") or ""
                print(f"  {r['host']:<42} "
                      + (G+"HTTP/2✔"+W if h2 else R+" —    "+W) + "   "
                      + (G+"QUIC/H3✔"+W if h3.get("supported") else R+"  —     "+W)
                      + f" {DIM}{alt[:30]}{W}")

    # ── Table 8: Methods Matrix ───────────────────────────────────
    M_ORDER = ["direct_sni","sni_mismatch","sni_empty","ws_real_payload",
               "domain_fronting","http_connect","host_header_inject","vless_probe"]
    M_HEAD  = ["DirectSNI","Mismatch★","EmptySNI","WS-Payload★",
               "DomainFront★","CONNECT","HostInject","VLESS★"]
    print(C+BOLD+f"\n[MATRIX] All Methods — Top 50\n"+W)
    print(C+f"  {'HOST':<38} "+"  ".join(f"{h:<13}" for h in M_HEAD)+W)
    print(C+"  "+"─"*148+W)
    for r in results[:50]:
        row = f"  {r['host']:<38} "
        for mid in M_ORDER:
            v = r["sni_methods"].get(mid,{})
            if v.get("works"):
                lat = f"({v.get('latency','?')}ms)"
                row += G + f"  ✔{lat:<11}" + W
            else:
                row += R + f"  ✘{'':11}" + W
        print(row)

    # ── Table 9: CDN/WAF Grouping ────────────────────────────────
    cdn_groups = {}
    for r in results:
        for cdn in r["cdn"]:
            cdn_groups.setdefault(cdn,[]).append(r["host"])
    if cdn_groups:
        print(B+BOLD+f"\n[CDN/WAF] Detected Services\n"+W)
        print(C+f"  {'CDN/WAF':<22} {'COUNT':>6}  SAMPLE HOSTS"+W)
        print(C+"  "+"─"*80+W)
        for cdn,hosts in sorted(cdn_groups.items(), key=lambda x:len(x[1]),reverse=True):
            sample = ", ".join(hosts[:3])
            print(M+f"  {cdn:<22}{W} {Y}{len(hosts):>6}{W}  {DIM}{sample}{W}")

    # ── ASCII Stats ───────────────────────────────────────────────
    total = len(results)
    if total:
        def bar(n,w=25):
            f=int(w*n/total) if total else 0
            return G+"█"*f+DIM+"░"*(w-f)+W+f" {n}/{total}"
        print(C+BOLD+f"\n[STATS] Overview\n"+W)
        print(C+f"  Bug Hosts       "+bar(len(bugs)))
        print(C+f"  SNI Mismatch    "+bar(len(mismatches)))
        print(C+f"  WS Payload ★    "+bar(len(ws_ok)))
        print(C+f"  Domain Front ★  "+bar(len(front_ok)))
        print(C+f"  VLESS Probe ★   "+bar(len(vless_ok)))
        print(C+f"  ECH Support     "+bar(len(ech_ok)))
        print(C+f"  HTTP/2          "+bar(len(h2_ok)))
        print(C+f"  HTTP/3 QUIC     "+bar(len(h3_ok)))

    # ── Top Summary ───────────────────────────────────────────────
    if bugs:
        print(G+BOLD+f"\n[BEST] Top Bug Hosts\n"+W)
        for i,r in enumerate(bugs[:10],1):
            methods = ", ".join(METHOD_LABELS.get(m,m) for m in r["working_methods"])
            cdn_s   = f" [{','.join(r['cdn'])}]"  if r["cdn"]           else ""
            h2_s    = " [H2]"                      if r["http2"]          else ""
            h3_s    = " [H3/QUIC]"                 if r.get("http3",{}).get("supported") else ""
            ech_s   = " [ECH]"                     if r.get("ech",{}).get("supported")   else ""
            ip_s    = f" [{r['ip']}]"              if r["ip"]             else ""
            print(G+f"  {i:>2}. {r['host']}"+W
                  +Y+ip_s+W+M+cdn_s+W+B+h2_s+h3_s+W+M+ech_s+W)
            print(C+f"      Score:{sc(r['bug_score'])}{r['bug_score']}%{W}  "
                  f"Methods:{G} {methods}{W}\n")


# ================================================================
#  3x-ui VPN Config Advisor
# ================================================================
def _best_port(open_ports, prefer_tls=True):
    """Best port select කරනවා — TLS ports priority"""
    tls_ports = [443, 8443, 2053, 2083, 2087, 2096]
    tcp_ports  = [80, 8080, 2052, 2082, 2086, 2095]
    if prefer_tls:
        for p in tls_ports:
            if p in open_ports: return p, True
        for p in tcp_ports:
            if p in open_ports: return p, False
    else:
        for p in tcp_ports:
            if p in open_ports: return p, False
        for p in tls_ports:
            if p in open_ports: return p, True
    return (list(open_ports)[0] if open_ports else 443), prefer_tls

def analyze_3xui(r):
    """
    Scan result එකෙන් best 3x-ui inbound config suggest කරනවා.
    Returns dict with all settings needed for 3x-ui panel.
    """
    m         = r["sni_methods"]
    op        = r["open_ports"]
    host      = r["host"]
    ip        = r["ip"] or host
    cdn       = r.get("cdn", [])
    has_h2    = r.get("http2", False)

    ws_ok     = m.get("ws_real_payload",   {}).get("works", False)
    mismatch  = m.get("sni_mismatch",      {})
    mismatch_ok = mismatch.get("works", False)
    front_ok  = m.get("domain_fronting",   {}).get("works", False)
    vless_ok  = m.get("vless_probe",       {}).get("works", False)
    connect_ok= m.get("http_connect",      {}).get("works", False)

    sni_host  = mismatch.get("sni_used", "") if mismatch_ok else host
    tls_ver   = mismatch.get("tls", "TLSv1.3") if mismatch_ok else "TLSv1.3"
    front_sni = m.get("domain_fronting",{}).get("front_sni","") if front_ok else ""

    # ── Transport decision tree ───────────────────────────────────
    # Priority: WS > gRPC (H2) > HTTPUpgrade > TCP
    if ws_ok:
        transport = "ws"
        port, use_tls = _best_port(op, prefer_tls=True)
    elif has_h2:
        transport = "grpc"
        port, use_tls = _best_port(op, prefer_tls=True)
    elif connect_ok:
        transport = "httpupgrade"
        port, use_tls = _best_port(op, prefer_tls=False)
    else:
        transport = "tcp"
        port, use_tls = _best_port(op, prefer_tls=True)

    # No TLS port found — fallback to 443
    if not op:
        port, use_tls = 443, True

    # ── Protocol decision ─────────────────────────────────────────
    # VLESS = lightest + best; VMess = fallback; Trojan = HTTPS-like
    if vless_ok or ws_ok or has_h2:
        protocol = "vless"
    elif front_ok:
        protocol = "trojan"   # Trojan works well with CDN fronting
    else:
        protocol = "vmess"

    # ── Security mode ─────────────────────────────────────────────
    if use_tls and mismatch_ok:
        security = "tls"
        allow_insecure = True   # SNI mismatch = cert verify skip
    elif use_tls:
        security = "tls"
        allow_insecure = False
    else:
        security = "none"
        allow_insecure = False

    # ── WS path ───────────────────────────────────────────────────
    ws_path = "/"

    # ── Fingerprint ───────────────────────────────────────────────
    fingerprint = "chrome"

    # ── CDN note ─────────────────────────────────────────────────
    cdn_note = ""
    if "Cloudflare" in cdn:
        cdn_note = "Cloudflare CDN ⚡ — Domain Fronting ✔"
    elif "Akamai" in cdn:
        cdn_note = "Akamai CDN — Fronting possible"
    elif "AWS CloudFront" in cdn:
        cdn_note = "AWS CloudFront — Fronting possible"
    elif cdn:
        cdn_note = f"CDN: {', '.join(cdn[:2])}"

    return {
        "host":           host,
        "ip":             ip,
        "port":           port,
        "protocol":       protocol,
        "transport":      transport,
        "security":       security,
        "sni":            sni_host,
        "allow_insecure": allow_insecure,
        "fingerprint":    fingerprint,
        "ws_path":        ws_path,
        "tls_version":    tls_ver,
        "front_sni":      front_sni,
        "cdn":            cdn,
        "cdn_note":       cdn_note,
        "ws_works":       ws_ok,
        "grpc_works":     has_h2,
        "vless_probe":    vless_ok,
        "fronting":       front_ok,
        "bug_score":      r["bug_score"],
    }

def display_3xui_configs(results):
    """Top bug hosts වල 3x-ui config screen-friendly format එකෙන් print"""
    bugs = [r for r in results if r["is_bug_host"]]
    if not bugs:
        print(Y+"  [!] Bug hosts නෑ — 3x-ui config generate කරන්න බෑ."+W)
        return

    print(f"\n{M}{'═'*72}{W}")
    print(M+BOLD+"  ★  3x-ui INBOUND CONFIG GUIDE  ★"+W)
    print(f"{M}{'═'*72}{W}\n")

    for i, r in enumerate(bugs[:8], 1):
        cfg = analyze_3xui(r)

        # ── Header ───────────────────────────────────────────────
        print(G+BOLD+f"  [{i}] {cfg['host']}"+W
              + DIM+f"  (IP: {cfg['ip']})"+W
              + (f"  {Y}{cfg['cdn_note']}{W}" if cfg['cdn_note'] else ""))
        print(C+"  "+f"{'─'*68}"+W)

        # ── Transport + Protocol summary ──────────────────────────
        tr_clr = G if cfg['transport']=='ws' else (B if cfg['transport']=='grpc' else Y)
        pr_clr = G if cfg['protocol']=='vless' else Y
        print(f"  {BOLD}Protocol  :{W} {pr_clr}{cfg['protocol'].upper()}{W}   "
              f"{BOLD}Transport :{W} {tr_clr}{cfg['transport'].upper()}{W}   "
              f"{BOLD}Port :{W} {G}{cfg['port']}{W}")
        print(f"  {BOLD}Security  :{W} {G if cfg['security']=='tls' else Y}{cfg['security'].upper()}{W}   "
              f"{BOLD}Fingerprint:{W} {cfg['fingerprint']}   "
              f"{BOLD}AllowInsecure:{W} {G+'true'+W if cfg['allow_insecure'] else DIM+'false'+W}")
        print(f"  {BOLD}SNI       :{W} {G}{cfg['sni']}{W}"
              + (f"   {DIM}(mismatch mode){W}" if cfg['sni'] != cfg['host'] else ""))

        if cfg['transport'] == 'ws':
            print(f"  {BOLD}WS Path   :{W} {cfg['ws_path']}")
        if cfg['transport'] == 'grpc':
            print(f"  {BOLD}gRPC Mode :{W} multi")
        if cfg['front_sni']:
            print(f"  {BOLD}Front SNI :{W} {Y}{cfg['front_sni']}{W}  {DIM}(Domain Fronting){W}")

        # ── 3x-ui panel settings box ──────────────────────────────
        print(C+f"\n  ┌─ 3x-ui Panel Settings {'─'*44}┐{W}")
        print(C+f"  │{W} Remark      : {G}{cfg['host']}{W}")
        print(C+f"  │{W} Protocol    : {G}{cfg['protocol']}{W}")
        print(C+f"  │{W} Port        : {G}{cfg['port']}{W}")
        print(C+f"  │{W} Network     : {G}{cfg['transport']}{W}")
        if cfg['transport'] == 'ws':
            print(C+f"  │{W} WS Path     : {G}{cfg['ws_path']}{W}")
            print(C+f"  │{W} WS Host     : {G}{cfg['sni']}{W}")
        elif cfg['transport'] == 'grpc':
            print(C+f"  │{W} gRPC Mode   : {G}multi{W}")
            print(C+f"  │{W} Service Name: {G}grpc{W}")
        print(C+f"  │{W} TLS         : {G if cfg['security']=='tls' else Y}{cfg['security']}{W}")
        if cfg['security'] == 'tls':
            print(C+f"  │{W} SNI         : {G}{cfg['sni']}{W}")
            print(C+f"  │{W} Fingerprint : {G}{cfg['fingerprint']}{W}")
            print(C+f"  │{W} allowInsecure: {G+'true'+W if cfg['allow_insecure'] else 'false'}")
        print(C+f"  └{'─'*50}┘{W}")

        # ── Capability badges ─────────────────────────────────────
        badges = []
        if cfg['ws_works']:   badges.append(G+"WS✔"+W)
        if cfg['grpc_works']: badges.append(B+"gRPC✔"+W)
        if cfg['vless_probe']:badges.append(G+"VLESS✔"+W)
        if cfg['fronting']:   badges.append(Y+"Fronting✔"+W)
        if badges:
            print(f"  Capabilities: "+" │ ".join(badges))

        print(f"  {BOLD}Bug Score :{W} {sc(cfg['bug_score'])}{cfg['bug_score']}%{W}\n")

    print(M+"  "+f"{'═'*70}"+W)
    print(Y+BOLD+"  NOTE: UUID/Password 3x-ui panel එකේ generate කරන්න."+W)
    print(Y+"  SNI mismatch mode: client-side ද allow_insecure=true set කරන්න."+W)
    print(M+"  "+f"{'═'*70}"+W+"\n")


def export_results(results, domain):
    """Scan results JSON + TXT format export කරනවා"""
    import datetime
    ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"sni_results_{domain.replace('.','_')}_{ts}"

    # JSON export
    json_file = base + ".json"
    export_data = []
    for r in results:
        export_data.append({
            "host":            r["host"],
            "ip":              r["ip"],
            "bug_score":       r["bug_score"],
            "is_bug_host":     r["is_bug_host"],
            "http_status":     r["http_status"],
            "https_status":    r["https_status"],
            "http2":           r["http2"],
            "cdn":             r["cdn"],
            "open_ports":      list(r["open_ports"].keys()),
            "working_methods": r["working_methods"],
            "ech_supported":   r.get("ech",{}).get("supported",False),
            "sni_used":        r["sni_methods"].get("sni_mismatch",{}).get("sni_used",""),
        })
    try:
        with open(json_file,'w') as f:
            json.dump(export_data, f, indent=2)
        print(G+f"  [✔] JSON exported → {json_file}"+W)
    except Exception as e:
        print(R+f"  [!] JSON export error: {e}"+W)

    # TXT export — bug hosts only
    txt_file = base + "_bugs.txt"
    bugs = [r for r in results if r["is_bug_host"]]
    try:
        with open(txt_file,'w') as f:
            f.write(f"# SNI Bug Hosts — {domain} — {ts}\n")
            f.write(f"# Total scanned: {len(results)}  Bug hosts: {len(bugs)}\n\n")
            for r in bugs:
                ms = ','.join(r["working_methods"])
                sni= r["sni_methods"].get("sni_mismatch",{}).get("sni_used","")
                f.write(f"{r['host']}  score:{r['bug_score']}%  methods:{ms}"
                        + (f"  sni:{sni}" if sni else "") + "\n")
        print(G+f"  [✔] Bug hosts TXT → {txt_file}"+W)
    except Exception as e:
        print(R+f"  [!] TXT export error: {e}"+W)

    return json_file, txt_file


def clear(): os.system('cls' if os.name=='nt' else 'clear')

def banner():
    clear()
    # Dep status
    deps = {
        "curl_cffi":  G+"✔"+W if curl_cffi  else R+"✘"+W,
        "httpx/H2":   G+"✔"+W if httpx      else R+"✘"+W,
        "aiohttp":    G+"✔"+W if aiohttp     else R+"✘"+W,
        "aiodns":     G+"✔"+W if aiodns      else R+"✘"+W,
        "dnspython":  G+"✔"+W if dns         else R+"✘"+W,
    }
    print(f"""
{C}╔══════════════════════════════════════════════════════════════╗
║  {G}{BOLD}SNI BUG HOST FINDER{C} v4.2  {DIM}(Speed+3xui){C}                   ║
║  {DIM}Async I/O | TLS-Spoof | WS-Payload | Domain-Front | ECH{C}    ║
╚══════════════════════════════════════════════════════════════╝{W}
  {C}curl_cffi:{W}{deps['curl_cffi']}  {C}httpx/H2:{W}{deps['httpx/H2']}  {C}aiohttp:{W}{deps['aiohttp']}  {C}aiodns:{W}{deps['aiodns']}  {C}dnspython:{W}{deps['dnspython']}
{Y}  [!] Educational & Research use only{W}
""")

def scan_domain_menu(cfg):
    banner()
    domain = input(Y+"  [+] Target Domain (e.g. dialog.lk) : "+W).strip()
    if not domain: return

    bug_sni_raw = input(Y+"  [+] SNI Mismatch host\n"
                        "      (Enter=auto | hostname type) : "+W).strip()
    bug_sni = bug_sni_raw or "auto"
    if bug_sni=="auto":
        print(G+f"  [*] Auto mode — {len(SNI_CANDIDATES)} candidates try කරනවා"+W)

    print(C+"\n  Settings (Enter=default):"+W)
    t = input(Y+f"    Threads [{cfg['threads']}]: "+W).strip()
    if t.isdigit(): cfg["threads"]=int(t)
    ac= input(Y+f"    Async concurrency [{cfg['async_concurrency']}]: "+W).strip()
    if ac.isdigit(): cfg["async_concurrency"]=int(ac)
    to= input(Y+f"    Timeout [{cfg['timeout']}s]: "+W).strip()
    if to.isdigit(): cfg["timeout"]=int(to)

    # TLS fingerprint
    if curl_cffi:
        print(C+f"\n  TLS Profiles: "+", ".join(DEFAULT_CFG["tls_profiles"])+W)
        tp = input(Y+f"  TLS profile [{cfg['tls_fingerprint']}]: "+W).strip()
        if tp in DEFAULT_CFG["tls_profiles"]: cfg["tls_fingerprint"]=tp
    else:
        print(Y+"  [!] curl_cffi না TLS fingerprint spoofing disabled"+W)

    subs = collect_subdomains(domain, cfg)
    if not subs:
        print(R+"\n  [-] Subdomains නෑ!"+W)
        input(Y+"\n  Enter..."+W); return

    t0      = time.time()
    results = run_scan(subs, cfg, bug_sni, domain=domain)
    elapsed = time.time()-t0
    print(C+f"\n  Scan time: {elapsed:.1f}s\n"+W)
    display_results(results, domain)
    display_3xui_configs(results)
    input(Y+"\n  Enter ඔබන්න..."+W)

def single_host_menu(cfg):
    banner()
    host = input(Y+"  [+] Host/Domain: "+W).strip()
    if not host: return

    bug_sni_raw = input(Y+"  [+] SNI Mismatch host (Enter=auto): "+W).strip()
    bug_sni = bug_sni_raw or "auto"

    print(C+f"\n  '{host}' scanning...\n"+W)
    res = scan_host(host, cfg, bug_sni)

    print(C+"  "+"═"*68+W)
    print(f"  {BOLD}Host        :{W} {G}{res['host']}{W}")
    print(f"  {BOLD}IP          :{W} {res['ip'] or '?'}")
    print(f"  {BOLD}HTTP        :{W} {G if res['http_status']==200 else Y}{res['http_status'] or '---'}{W}")
    print(f"  {BOLD}HTTPS       :{W} {G if res['https_status']==200 else Y}{res['https_status'] or '---'}{W}")
    print(f"  {BOLD}HTTP/2      :{W} {G+'✔'+W if res['http2'] else R+'✘'+W}")
    print(f"  {BOLD}HTTP/3      :{W} {G+'✔ '+res.get('http3',{}).get('alt_svc','?')[:30]+W if res.get('http3',{}).get('supported') else R+'✘'+W}")
    print(f"  {BOLD}ECH         :{W} {G+'✔ key:'+str(res.get('ech',{}).get('ech_key','?'))[:25]+W if res.get('ech',{}).get('supported') else R+'✘'+W}")
    print(f"  {BOLD}TLS Spoof   :{W} {G+'curl_cffi '+cfg.get('tls_fingerprint','')+W if curl_cffi else DIM+'ssl fallback'+W}")
    print(f"  {BOLD}CDN/WAF     :{W} {M+', '.join(res['cdn'])+W if res['cdn'] else 'None'}")
    if res["open_ports"]:
        ps = "  ".join(f"{G}{p}{W}({l}ms)" for p,l in sorted(res["open_ports"].items()))
        print(f"  {BOLD}Open Ports  :{W} {ps}")

    print(C+"\n  [SNI Methods]\n"+W)
    print(C+f"  {'METHOD':<24} {'STATUS':<8} {'TLS':<10} {'LAT':<10} DETAIL"+W)
    print(C+"  "+"─"*78+W)

    for mid, label in METHOD_LABELS.items():
        v = res["sni_methods"].get(mid,{})
        if v.get("works"):
            tls   = v.get("tls","")
            lat   = f"{v.get('latency','?')}ms"
            if mid=="sni_mismatch":
                detail = f"sni:{G}{v.get('sni_used','?')}{W}"
                print(f"  {label:<24} {G}WORKS{W}    {tls:<10} {lat:<10} {detail}")
                for x in v.get("all_working",[]):
                    print(G+f"    ✔ {x['sni']:<32}{W} {B}{x.get('tls','?')}{W} {Y}{x.get('latency','?')}ms{W}")
            elif mid=="ws_real_payload":
                ko = G+"key✔"+W if v.get("key_verified") else Y+"key?"+W
                detail = f"code:{v.get('code','?')} {ko}"
                print(f"  {label:<24} {G}WORKS{W}    {tls:<10} {lat:<10} {detail}")
            elif mid=="domain_fronting":
                detail = f"front:{G}{v.get('front_sni','?')}{W} code:{v.get('code','?')}"
                print(f"  {label:<24} {G}WORKS{W}    {'':10} {lat:<10} {detail}")
            else:
                detail = f"code:{v.get('code','')}  cn:{v.get('cn','')}"
                print(f"  {label:<24} {G}WORKS{W}    {tls:<10} {lat:<10} {DIM}{detail}{W}")
        else:
            print(f"  {label:<24} {R}✘{W}")

    print(C+"\n  "+"─"*68+W)
    print(f"  {BOLD}Bug Score   :{W} {sc(res['bug_score'])}{res['bug_score']}%{W}")
    verdict = G+BOLD+"★ BUG HOST"+W if res["is_bug_host"] else R+"NOT a Bug Host"+W
    print(f"  {BOLD}Verdict     :{W} {verdict}")
    if res["working_methods"]:
        ms = ", ".join(METHOD_LABELS.get(m,m) for m in res["working_methods"])
        print(Y+f"\n  Working: {G}{ms}{W}")
    print(C+"  "+"═"*68+W)
    # 3x-ui config for single host
    if res["is_bug_host"]:
        display_3xui_configs([res])
    input(Y+"\n  Enter ඔබන්න..."+W)

def batch_scan_menu(cfg):
    banner()
    fpath = input(Y+"  [+] Domain list file (one per line): "+W).strip()
    if not os.path.exists(fpath):
        print(R+f"  [-] File not found: {fpath}"+W)
        input(Y+"  Enter..."+W); return
    with open(fpath) as f:
        domains = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    bug_sni = input(Y+"  [+] Bug SNI host (Enter=auto): "+W).strip() or "auto"
    print(G+f"  [+] Domains: {len(domains)}\n"+W)
    for d in domains:
        print(C+f"\n{'═'*50}\n  Scanning: {d}\n{'═'*50}"+W)
        subs = collect_subdomains(d, cfg)
        if not subs: print(R+f"  [-] No subdomains for {d}"+W); continue
        results = run_scan(subs, cfg, bug_sni, domain=d)
        display_results(results, d)
        display_3xui_configs(results)
    input(Y+"\n  Enter ඔබන්න..."+W)

def deps_menu():
    banner()
    print(C+"  [DEPENDENCIES]\n"+W)
    deps_info = [
        ("aiohttp",    "Async HTTP scanning (ඉතාම ඉක්මන්)"),
        ("aiodns",     "Async DNS resolve"),
        ("httpx[http2]","HTTP/2 accurate check"),
        ("curl_cffi",  "TLS fingerprint spoofing (Chrome/Firefox)"),
        ("dnspython",  "ECH / DNS HTTPS record lookup"),
    ]
    missing = []
    for pkg, desc in deps_info:
        mod = 'dns' if pkg == 'dnspython' else pkg.split('[')[0].replace('-','_')
        ok  = _try_import(mod) is not None
        status = G+"✔ installed"+W if ok else R+"✘ missing"+W
        print(f"  {pkg:<20} {status}  {DIM}{desc}{W}")
        if not ok: missing.append(pkg)

    if missing:
        print(Y+f"\n  Install command:\n  {G}pip install {' '.join(missing)}{W}\n")
    else:
        print(G+"\n  ✔ All dependencies installed!\n"+W)
    input(Y+"\n  Enter ඔබන්න..."+W)

def config_menu(cfg):
    while True:
        banner()
        print(Y+"  [CONFIG EDITOR]\n"+W)
        fields = [
            ("1","threads",         "Threads",          cfg["threads"]),
            ("2","async_concurrency","Async concurrency",cfg["async_concurrency"]),
            ("3","timeout",         "Timeout (s)",      cfg["timeout"]),
            ("4","tls_fingerprint", "TLS profile",      cfg["tls_fingerprint"]),
            ("5","check_https",     "HTTPS check",      cfg["check_https"]),
            ("6","check_sni",       "SNI check",        cfg["check_sni"]),
            ("7","check_http2",     "HTTP/2 check",     cfg["check_http2"]),
            ("8","check_http3",     "HTTP/3 check",     cfg.get("check_http3",False)),
            ("9","check_ws_payload","WS Payload test",  cfg.get("check_ws_payload",True)),
            ("a","check_fronting",  "Domain Fronting",  cfg.get("check_fronting",True)),
            ("b","check_ech",       "ECH detect",       cfg.get("check_ech",True)),
            ("c","use_crtsh",       "CRT.sh subdomains",cfg["use_crtsh"]),
            ("d","use_alienvault",  "AlienVault subs",  cfg["use_alienvault"]),
        ]
        for num, key, label, val in fields:
            print(C+f"  [{num}] {label:<22}: {G if val==True else (R if val==False else Y)}{val}{W}")
        print(Y+"\n  [s] Save & Back  [q] Back"+W)
        ch = input(C+"\n  Choice: "+W).strip().lower()

        if ch=='s': save_cfg(cfg); break
        elif ch=='q': break
        else:
            found = next((f for f in fields if f[0]==ch), None)
            if found:
                _, key, label, val = found
                if isinstance(val, bool):
                    cfg[key] = not cfg[key]
                elif isinstance(val, int):
                    v = input(Y+f"  {label} [{val}]: "+W).strip()
                    if v.isdigit(): cfg[key]=int(v)
                elif isinstance(val, str):
                    v = input(Y+f"  {label} [{val}]: "+W).strip()
                    if v: cfg[key]=v

def main():
    try:
        import urllib3
        urllib3.disable_warnings()
    except: pass

    cfg = load_cfg()

    while True:
        banner()
        print(Y+"  ┌────────────────────────────────────────────────┐"+W)
        print(Y+"  │               MAIN MENU                        │"+W)
        print(Y+"  ├────────────────────────────────────────────────┤"+W)
        print(Y+"  │  "+W+"[1]  Domain Scan  (Async + Full SNI)      "+Y+"  │"+W)
        print(Y+"  │  "+W+"[2]  Single Host  (Deep Check)             "+Y+"  │"+W)
        print(Y+"  │  "+W+"[3]  Batch Scan   (File Input)             "+Y+"  │"+W)
        print(Y+"  │  "+W+"[4]  Settings / Config                     "+Y+"  │"+W)
        print(Y+"  │  "+W+"[5]  Dependencies Status                   "+Y+"  │"+W)
        print(Y+"  │  "+W+"[6]  Exit                                  "+Y+"  │"+W)
        print(Y+"  └────────────────────────────────────────────────┘\n"+W)

        ch = input(C+"  Choice (1-6): "+W).strip()
        if   ch=='1': scan_domain_menu(cfg)
        elif ch=='2': single_host_menu(cfg)
        elif ch=='3': batch_scan_menu(cfg)
        elif ch=='4': config_menu(cfg)
        elif ch=='5': deps_menu()
        elif ch=='6':
            print(G+"\n  ජය වේවා! 👋\n"+W); sys.exit(0)
        else:
            print(R+"\n  [-] 1-6 ඇතුලත් කරන්න.\n"+W); time.sleep(1)

if __name__=="__main__":
    main()
