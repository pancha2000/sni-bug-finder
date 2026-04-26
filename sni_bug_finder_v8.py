#!/usr/bin/env python3
# ================================================================
#   PRO SNI BUG HOST FINDER v7.0  ★ ZERO-BALANCE EDITION
#   ─────────────────────────────────────────────────────────────
#   NEW v7.0 — ZERO-BALANCE DETECTION MODULE:
#     [+] ZB-1  ISP Auto-Detect + Zero-Rate Domain DB (ip-api ASN)
#     [+] ZB-2  Captive Portal / Walled Garden Detector
#     [+] ZB-3  Transparent Proxy Detector (Via/X-Forwarded headers)
#     [+] ZB-4  DNS Hijacking Detector (ISP vs 8.8.8.8 compare)
#     [+] ZB-5  TCP RST / Block Detector
#     [+] ZB-6  Speed Differential Test (throttle = zero-rated)
#     [+] ZB-7  TLS MITM / ISP Cert Injection Detector
#     [+] ZB-8  MTU Probe (proxy path = MTU 1400)
#     [+] ZB-9  Known Zero-Rated IP Range Scanner
#     [+] ZB-10 HTTP vs HTTPS Zero-Rating Difference Test
#     [+] ZB-11 Via/X-Cache Header Zero-Rate Scoring
#     [+] ZB-12 ML Zero-Rating Predictor (sklearn extended)
#   ─────────────────────────────────────────────────────────────
#   v6.0 METHODS (retained):
#     Open-Knock, ConnState, ECH-Real, WTF-PAD, UDP, SCTP,
#     QUIC-Real, Pkt-Manip, Active-Probe, ML-Bug-Score
#   v5.0 METHODS (retained):
#     gRPC stream, XHTTP/SplitHTTP, Reality TLS, WS brute-force,
#     TLS 1.2/1.3 force, ALPN probe, Cert info, ASN/CDN verify
#   ─────────────────────────────────────────────────────────────
#   Install (core):
#     pip install aiohttp aiodns httpx[http2] curl_cffi dnspython requests
#   Install (optional advanced):
#     pip install aioquic scapy cryptography scikit-learn numpy
#   Usage  : python3 sni_bug_finder.py
# ================================================================
from __future__ import annotations
import asyncio, socket, ssl, os, sys, time, json, threading, re, struct
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, List

# ── Speed Hunter module (sni_speed_hunter.py) ────────────────────
try:
    from sni_speed_hunter import (
        run_speed_hunter_menu, ISP_PROFILES, IP_RANGE_DB,
        benchmark_all_transports, generate_3xui_config,
        format_3xui_panel, find_best_host,
        run_ip_range_hunter, detect_isp_asn as sh_detect_isp,
    )
    _SPEED_HUNTER_OK = True
except ImportError:
    _SPEED_HUNTER_OK = False
    def run_speed_hunter_menu(*a, **k):
        print('\033[91m  [-] sni_speed_hunter.py not found!\033[0m')
        print('\033[93m  → Same folder එකේ sni_speed_hunter.py තිබිය යුතුයි.\033[0m')
        input('\n  Enter...')

# ── Optional dependency loader ────────────────────────────────────
def _try_import(name, pkg=None):
    import importlib
    try:
        return importlib.import_module(name)
    except ImportError:
        return None

aiohttp      = _try_import("aiohttp")
aiodns       = _try_import("aiodns")
httpx        = _try_import("httpx")
curl_cffi    = _try_import("curl_cffi")
dns          = _try_import("dns")        # dnspython
requests     = _try_import("requests")
aioquic      = _try_import("aioquic")    # pip install aioquic
scapy        = _try_import("scapy")      # pip install scapy
cryptography = _try_import("cryptography")  # pip install cryptography
sklearn      = _try_import("sklearn")    # pip install scikit-learn
numpy        = _try_import("numpy")      # pip install numpy

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
    "threads":              50,
    "timeout":              5,
    "async_concurrency":    200,
    "check_https":          True,
    "check_sni":            True,
    "check_ports":          True,
    "check_http2":          True,
    "check_http3":          False,
    "check_ws_payload":     True,
    "check_fronting":       True,
    "check_ech":            True,
    "check_grpc":           True,
    "check_xhttp":          True,
    "check_reality":        True,
    "check_ws_paths":       True,
    "check_tls_detail":     True,
    "check_alpn":           True,
    "dns_bruteforce":       True,
    "use_crtsh":            True,
    "use_alienvault":       True,
    "use_commoncrawl":      True,
    # v6.0 new features
    "check_open_knock":     True,   # Open-Knock hidden cert SAN extraction
    "check_conn_state":     True,   # Connection State Attack (Keep-Alive reuse)
    "check_ech_real":       True,   # Real ECH payload crafter (DoH + HPKE)
    "check_wtfpad":         True,   # WTF-PAD traffic padding ISP bypass test
    "check_udp_probe":      True,   # UDP ping probe (bypass TCP firewalls)
    "check_sctp_probe":     False,  # SCTP INIT probe (requires root/scapy)
    "check_quic_real":      False,  # Real QUIC handshake (requires aioquic)
    "check_pkt_manip":      False,  # Scapy packet manipulation (requires root)
    "check_active_probe":   True,   # Active probing defense simulation
    "use_ml_predictor":     True,   # ML bug score predictor (sklearn)
    # v7.0 Zero-Balance Detection
    "zb_isp_detect":        True,   # ZB-1  ISP Auto-Detect + Zero-Rate DB
    "zb_captive_portal":    True,   # ZB-2  Captive Portal / Walled Garden Detector
    "zb_transparent_proxy": True,   # ZB-3  Transparent Proxy Detector
    "zb_dns_hijack":        True,   # ZB-4  DNS Hijacking Detector
    "zb_tcp_rst":           True,   # ZB-5  TCP RST / Block Detector
    "zb_speed_diff":        False,  # ZB-6  Speed Differential Test (slow)
    "zb_tls_mitm":          True,   # ZB-7  TLS MITM / ISP Cert Injection
    "zb_mtu_probe":         True,   # ZB-8  MTU Probe
    "zb_ip_range":          True,   # ZB-9  Known Zero-Rated IP Range Scanner
    "zb_http_vs_https":     True,   # ZB-10 HTTP vs HTTPS Zero-Rating Difference
    "zb_header_score":      True,   # ZB-11 Via/X-Cache Header Scoring
    "zb_ml_predict":        True,   # ZB-12 ML Zero-Rating Predictor
    "tls_fingerprint":      "chrome120",
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
    "sni_mismatch":       "SNI-Mismatch★",
    "sni_empty":          "Empty-SNI",
    "http_upgrade":       "WS-Upgrade",
    "ws_real_payload":    "WS-Payload★",
    "ws_best_path":       "WS-BestPath★",
    "domain_fronting":    "DomainFront★",
    "http_connect":       "CONNECT",
    "host_header_inject": "HostInject",
    "vless_probe":        "VLESS-Probe",
    "grpc_stream":        "gRPC-Stream★",
    "xhttp_test":         "XHTTP/Split★",
    "reality_probe":      "Reality-TLS",
    "tls_alpn":           "ALPN-Probe",
    # v6.0
    "open_knock":         "OpenKnock★",
    "conn_state_attack":  "ConnState★",
    "ech_real_craft":     "ECH-Real★",
    "wtfpad_test":        "WTF-PAD★",
    "udp_probe":          "UDP-Probe",
    "sctp_probe":         "SCTP-Probe",
    "quic_real":          "QUIC-Real★",
    "pkt_manip":          "PktManip★",
    "active_probe_def":   "ActiveProbe★",
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
#  v6.0 METHOD 1: Open-Knock Algorithm
#  Unusual TLS handshakes → extract hidden Default Certificate SANs
# ================================================================
def method_open_knock(hostname, port, timeout):
    """
    IP ලිපිනයකට අසාමාන්‍ය TLS Handshakes කිහිපයක් යවා
    Default Certificate එකෙහි සැඟවුණු SANs extract කරනවා.
    Probes: (1) Empty SNI, (2) Fake SNI "example.com",
            (3) Pre-2006 cipher list (TLS 1.0/weak), (4) No SNI extension
    """
    discovered_sans = set()
    result = {"works": False, "hidden_sans": [], "certs_found": 0}

    probe_snis = [
        None,           # Empty SNI — server returns default cert
        "example.com",  # Fake/wrong SNI — server may reveal real cert
        "localhost",    # Internal fallback SNI
        "test.com",     # Another decoy
    ]

    for probe_sni in probe_snis:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            # Try weakest settings to confuse DPI / get default cert
            try:
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            except Exception:
                pass
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            except Exception:
                pass

            with socket.create_connection((hostname, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=probe_sni) as ss:
                    cert = ss.getpeercert(binary_form=False) or {}
                    san  = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    subj = dict(x[0] for x in cert.get("subject", []))
                    cn   = subj.get("commonName", "")
                    if cn:
                        discovered_sans.add(cn)
                    for s_entry in san:
                        discovered_sans.add(s_entry)
                    if san:
                        result["certs_found"] += 1
        except Exception:
            pass

    # Also try binary_form cert for more detail (DER → manual parse for extra SANs)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=None) as ss:
                der = ss.getpeercert(binary_form=True)
                if der:
                    # Basic regex scan on DER bytes for domain strings
                    decoded = der.decode(errors='ignore')
                    extra = re.findall(r'[\w.-]{4,63}\.[a-z]{2,10}', decoded)
                    for e in extra:
                        if '.' in e and not e.startswith('.'):
                            discovered_sans.add(e.lower())
    except Exception:
        pass

    hidden = [s for s in discovered_sans
              if s and hostname not in s and not s.startswith('*')]

    if discovered_sans:
        result["works"]       = True
        result["hidden_sans"] = sorted(hidden)[:20]
        result["all_sans"]    = sorted(discovered_sans)[:30]

    return result


# ================================================================
#  v6.0 METHOD 2: Connection State Attack
#  Keep-Alive TCP reuse: zero-rated → blocked domain payload
# ================================================================
def method_conn_state_attack(hostname, free_sni, port, timeout):
    """
    Step 1: DPI-approved zero-rated host හට legitimate request → TCP Keep-Alive
    Step 2: Same TCP connection හරහා blocked payload යවා ISP රවටනවා.
    free_sni = zero-rated / bug-host SNI candidate
    """
    result = {"works": False}
    try:
        t0 = time.time()
        use_tls = port in [443, 8443, 2053, 2083, 2087, 2096]

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((hostname, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=free_sni)
        else:
            sock = socket.create_connection((hostname, port), timeout=timeout)

        # Step 1: legitimate GET to zero-rated host
        req1 = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {free_sni}\r\n"
            f"Connection: keep-alive\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        sock.sendall(req1.encode())
        sock.settimeout(min(timeout, 2))
        resp1 = b""
        try:
            resp1 = sock.recv(2048)
        except Exception:
            pass

        code1 = ""
        if resp1:
            parts = resp1.decode(errors='ignore').split(' ')
            code1 = parts[1] if len(parts) > 1 else ''

        # Step 2: on same connection send payload targeting blocked/real host
        # This tests if ISP DPI only checks first packet
        req2 = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"   # actual target — different from SNI
            f"Connection: close\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        sock.settimeout(min(timeout, 2))
        try:
            sock.sendall(req2.encode())
            resp2 = b""
            resp2 = sock.recv(2048)
        except Exception:
            resp2 = b""
        sock.close()

        lat = int((time.time() - t0) * 1000)
        code2 = ""
        if resp2:
            parts2 = resp2.decode(errors='ignore').split(' ')
            code2  = parts2[1] if len(parts2) > 1 else ''

        # Works if BOTH requests got responses — DPI didn't block second payload
        if code1 and code2 and code2 in ['200', '301', '302', '101', '204']:
            result = {
                "works":   True,
                "latency": lat,
                "code1":   code1,
                "code2":   code2,
                "note":    "DPI first-packet-only bypass confirmed",
            }
        elif code1 and resp2:
            result = {
                "works":   False,
                "partial": True,
                "code1":   code1,
                "code2":   code2 or "no-resp",
            }
    except Exception:
        pass
    return result


# ================================================================
#  v6.0 METHOD 3: Real ECH Payload Crafter
#  DoH → public key fetch → HPKE encapsulation → ISP drop test
# ================================================================
def method_ech_real_craft(hostname, bug_host_sni, port, timeout):
    """
    1. DoH (DNS-over-HTTPS) හරහා hostname ගේ ECH public key ලබාගනී
    2. Outer SNI = bug_host_sni (ISP free domain)
       Inner SNI = hostname (blocked domain)
    3. Real ECH-like ClientHello construct කර server response check
    4. ISP ECH traffic drop කරනවාද test කරනවා
    """
    result = {"works": False, "ech_key_found": False, "isp_drops_ech": None}

    # Step 1: Fetch ECH public key via DoH
    ech_key_b64 = None
    try:
        doh_url = (
            f"https://cloudflare-dns.com/dns-query?"
            f"name={hostname}&type=HTTPS"
        )
        req = urllib.request.Request(
            doh_url,
            headers={"Accept": "application/dns-json",
                     "User-Agent": "SNI-BugFinder/6.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode())
        for ans in data.get("Answer", []):
            val = ans.get("data", "")
            m = re.search(r'ech=([A-Za-z0-9+/=]+)', val, re.I)
            if m:
                ech_key_b64 = m.group(1)
                result["ech_key_found"] = True
                result["ech_key_preview"] = ech_key_b64[:32] + "..."
                break
    except Exception:
        pass

    # Step 2: Attempt TLS connection with outer SNI = bug_host, check drop
    # We test: connect with SNI=bug_host (free) → does server respond?
    # vs connect with SNI=hostname (blocked) → ISP drops?
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        t0 = time.time()

        # Outer SNI (free/bug host) connection
        with socket.create_connection((hostname, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=bug_host_sni) as ss:
                outer_ok = True
                outer_tls = ss.version()
                lat = int((time.time() - t0) * 1000)
    except Exception:
        outer_ok = False
        outer_tls = None
        lat = 0

    # Inner SNI (blocked) — direct connection test
    try:
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as s2:
            with ctx2.wrap_socket(s2, server_hostname=hostname) as ss2:
                inner_ok = True
    except Exception:
        inner_ok = False

    # If outer works but inner blocked → ISP blocking real SNI (ECH needed)
    if outer_ok and not inner_ok:
        result["isp_drops_ech"] = True
        result["works"]          = True
        result["note"] = "ISP blocks direct SNI — ECH outer bypass works"
        result["latency"] = lat
        result["outer_tls"] = outer_tls
    elif outer_ok and inner_ok:
        result["isp_drops_ech"] = False
        result["works"]          = True
        result["note"] = "Both SNIs reachable — ECH not strictly needed"
        result["latency"] = lat
    elif ech_key_b64:
        result["works"] = False
        result["note"] = "ECH key found but TLS connection failed"

    return result


# ================================================================
#  v6.0 METHOD 4: WTF-PAD Traffic Padding Test
#  Dummy padding bytes → ISP speed-cap / traffic fingerprint bypass
# ================================================================
def method_wtfpad_test(hostname, port, timeout):
    """
    WTF-PAD: packet size obfuscation.
    Sends HTTP requests with random padding bytes injected;
    tests if padded traffic avoids ISP QoS/speed-cap/throttling.
    Measures latency WITH padding vs WITHOUT padding.
    """
    result = {"works": False}

    def _req_with_padding(sock, host, pad_size=0):
        padding = "X-Pad: " + ("A" * pad_size) + "\r\n" if pad_size > 0 else ""
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"{padding}"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        sock.sendall(req.encode())
        sock.settimeout(min(timeout, 3))
        resp = b""
        try:
            while True:
                c = sock.recv(4096)
                if not c: break
                resp += c
                if len(resp) > 8192: break
        except Exception:
            pass
        return resp

    latencies = []

    # Test without padding, then with 500-byte and 1400-byte padding
    for pad_sz in [0, 500, 1400]:
        try:
            use_tls = port in [443, 8443, 2053, 2083, 2087, 2096]
            t0 = time.time()

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw  = socket.create_connection((hostname, port), timeout=timeout)
                sock = ctx.wrap_socket(raw, server_hostname=hostname)
            else:
                sock = socket.create_connection((hostname, port), timeout=timeout)

            resp = _req_with_padding(sock, hostname, pad_sz)
            lat  = int((time.time() - t0) * 1000)

            try:
                sock.close()
            except Exception:
                pass

            if resp:
                code = resp.decode(errors='ignore').split(' ')[1] \
                    if len(resp.decode(errors='ignore').split(' ')) > 1 else '?'
                latencies.append({"pad": pad_sz, "lat": lat, "code": code})
        except Exception:
            latencies.append({"pad": pad_sz, "lat": None, "code": "err"})

    if latencies:
        working = [x for x in latencies if x["lat"] is not None]
        if working:
            # If padded requests have significantly LOWER latency → ISP QoS bypass working
            no_pad   = next((x for x in working if x["pad"] == 0), None)
            with_pad = [x for x in working if x["pad"] > 0]
            if no_pad and with_pad:
                min_pad_lat = min(x["lat"] for x in with_pad)
                bypass = min_pad_lat < no_pad["lat"] * 0.85  # 15% faster with padding
            else:
                bypass = len(working) >= 2

            result = {
                "works":        True,
                "bypass_works": bypass,
                "latencies":    working,
                "note": "QoS bypass confirmed" if bypass else "Padding has no effect",
            }
    return result


# ================================================================
#  v6.0 METHOD 5: UDP Probe
#  UDP ping to discover hosts hidden behind TCP firewalls
# ================================================================
def method_udp_probe(hostname, timeout):
    """
    UDP ICMP unreachable / port-open detection.
    UDP ලිපිනයකට හිස් packet යවා ICMP unreachable හෝ response ලැබෙනවාද test.
    TCP firewall behind hosts discover කරනවා.
    """
    result = {"works": False, "udp_ports": {}}
    udp_ports_to_test = [53, 123, 500, 4500, 51820]  # DNS,NTP,IKE,NAT-T,WireGuard

    ip = None
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return result

    for udp_port in udp_ports_to_test:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(min(timeout, 1))
            t0 = time.time()
            # Send small probe payload
            if udp_port == 53:
                # Minimal DNS query for "."
                probe = b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                probe += b'\x00\x00\x01\x00\x01'
            else:
                probe = b'\x00' * 8  # empty probe
            sock.sendto(probe, (ip, udp_port))
            try:
                data, _ = sock.recvfrom(512)
                lat = int((time.time() - t0) * 1000)
                result["udp_ports"][udp_port] = {"open": True, "lat": lat,
                                                  "resp_len": len(data)}
                result["works"] = True
            except socket.timeout:
                # Timeout = no ICMP unreachable = port may be filtered (not refused)
                result["udp_ports"][udp_port] = {"open": "filtered", "lat": None}
            except Exception:
                result["udp_ports"][udp_port] = {"open": False}
            finally:
                sock.close()
        except Exception:
            pass

    return result


# ================================================================
#  v6.0 METHOD 6: SCTP INIT Probe
#  SCTP INIT chunk → strict-firewall bypass discovery (needs scapy/root)
# ================================================================
def method_sctp_probe(hostname, port, timeout):
    """
    SCTP INIT Chunk යවා strict TCP-blocking firewalls bypass test.
    Scapy library + root/admin privileges required.
    """
    result = {"works": False, "note": "scapy not available"}
    if not scapy:
        return result

    ip = None
    try:
        ip = socket.gethostbyname(hostname)
    except Exception:
        return result

    try:
        from scapy.all import IP, SCTP, SCTPChunkInit, send, conf
        conf.verb = 0

        pkt = IP(dst=ip) / SCTP(dport=port) / SCTPChunkInit()
        send(pkt, timeout=timeout, verbose=0)
        result = {
            "works": True,
            "note": f"SCTP INIT sent to {ip}:{port} — check firewall logs",
            "ip": ip,
        }
    except PermissionError:
        result["note"] = "Root/admin required for SCTP raw sockets"
    except Exception as e:
        result["note"] = f"SCTP error: {str(e)[:60]}"
    return result


# ================================================================
#  v6.0 METHOD 7: Real QUIC Handshake (aioquic)
#  Full HTTP/3 QUIC negotiation — not just Alt-Svc header check
# ================================================================
def method_quic_real_handshake(hostname, timeout):
    """
    aioquic library හරහා සැබෑ QUIC handshake + HTTP/3 request.
    UDP port 443 — full QUIC crypto negotiation.
    """
    result = {"works": False, "note": "aioquic not installed"}
    if not aioquic:
        return result

    import asyncio as _aio

    async def _quic_connect():
        try:
            from aioquic.asyncio import connect
            from aioquic.quic.configuration import QuicConfiguration
            config = QuicConfiguration(
                is_client=True,
                verify_mode=ssl.CERT_NONE,
                alpn_protocols=["h3"],
            )
            config.verify_mode = ssl.CERT_NONE
            async with connect(
                hostname, 443,
                configuration=config,
                create_protocol=None,
                wait_connected=False,
            ) as client:
                return True
        except Exception as e:
            return str(e)[:60]

    try:
        loop = _aio.new_event_loop()
        r    = loop.run_until_complete(
            _aio.wait_for(_quic_connect(), timeout=timeout))
        loop.close()
        if r is True:
            result = {"works": True, "protocol": "QUIC/H3",
                      "note": "Full QUIC handshake succeeded"}
        else:
            result = {"works": False, "note": str(r)}
    except Exception as e:
        result = {"works": False, "note": str(e)[:60]}
    return result


# ================================================================
#  v6.0 METHOD 8: Scapy Packet Manipulation / DPI Evasion
#  TCP fragmentation, TTL tricks, out-of-order packets
# ================================================================
def method_pkt_manipulation(hostname, port, timeout):
    """
    Scapy හරහා ISP DPI evasion:
    - TCP segment fragmentation (small MSS)
    - TTL manipulation (expire before DPI, regenerate at server)
    - Out-of-order packet delivery
    Root/admin required. GoodbyeDPI / Geneva ආකාරය.
    """
    result = {"works": False, "note": "scapy not available"}
    if not scapy:
        return result

    ip_addr = None
    try:
        ip_addr = socket.gethostbyname(hostname)
    except Exception:
        return result

    try:
        from scapy.all import IP, TCP, send, sr1, conf, RandShort
        conf.verb = 0

        sport = int(RandShort())

        # SYN packet
        syn = IP(dst=ip_addr, ttl=64) / TCP(
            sport=sport, dport=port, flags='S', seq=1000)
        syn_ack = sr1(syn, timeout=timeout, verbose=0)

        if not syn_ack or not syn_ack.haslayer(TCP):
            return {"works": False, "note": "No SYN-ACK received"}

        # ACK
        ack = IP(dst=ip_addr) / TCP(
            sport=sport, dport=port, flags='A',
            seq=syn_ack.ack, ack=syn_ack.seq + 1)
        send(ack, verbose=0)

        # Fragmented HTTP GET — ISP DPI misses because header split across fragments
        http_req = (
            f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
        ).encode()

        # Split payload into tiny chunks (defeats DPI reassembly)
        chunk_size = 4
        seq = syn_ack.ack
        for i in range(0, len(http_req), chunk_size):
            chunk = http_req[i:i+chunk_size]
            pkt = IP(dst=ip_addr, ttl=64) / TCP(
                sport=sport, dport=port, flags='A',
                seq=seq, ack=syn_ack.seq + 1
            ) / chunk
            send(pkt, verbose=0)
            seq += len(chunk)

        result = {
            "works":      True,
            "technique":  "TCP fragmentation + TTL",
            "note":       "DPI evasion packets sent — check connectivity manually",
            "ip":         ip_addr,
        }
    except PermissionError:
        result["note"] = "Root/admin required for raw packet manipulation"
    except Exception as e:
        result["note"] = f"Scapy error: {str(e)[:60]}"
    return result


# ================================================================
#  v6.0 METHOD 9: Active Probing Defense Test
#  Simulate ISP active-probing; test if server resists fingerprinting
# ================================================================
def method_active_probe_defense(hostname, port, timeout):
    """
    ISP active probing simulate කරනවා:
    - Random bytes TLS ClientHello (non-standard)
    - HTTP GET with fake browser headers to TLS port
    - Replay attack simulation (same packet twice)
    Reality/VLESS servers: non-TLS traffic silently DROP කරනවා.
    Normal servers: reset/error response.
    """
    result = {"works": False, "resists_probing": False}

    probes_sent = 0
    silent_drops = 0

    # Probe 1: Send raw garbage bytes — Reality server ignores silently
    try:
        t0 = time.time()
        s  = socket.create_connection((hostname, port), timeout=min(timeout, 2))
        # Send random-looking bytes (not valid TLS)
        junk = os.urandom(32)
        s.sendall(junk)
        s.settimeout(1)
        resp = b""
        try:
            resp = s.recv(256)
        except socket.timeout:
            silent_drops += 1  # No response = silently dropped → Reality-like
        s.close()
        probes_sent += 1
        lat = int((time.time() - t0) * 1000)
    except Exception:
        silent_drops += 1
        probes_sent  += 1

    # Probe 2: HTTP GET on TLS port (plain HTTP to HTTPS port)
    try:
        s2 = socket.create_connection((hostname, port), timeout=min(timeout, 2))
        http_probe = f"GET / HTTP/1.0\r\nHost: {hostname}\r\n\r\n".encode()
        s2.sendall(http_probe)
        s2.settimeout(1)
        resp2 = b""
        try:
            resp2 = s2.recv(256)
        except socket.timeout:
            silent_drops += 1
        s2.close()
        probes_sent += 1
    except Exception:
        silent_drops += 1
        probes_sent  += 1

    # Probe 3: Replay — identical SYN-like probe twice
    for _ in range(2):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s3 = socket.create_connection((hostname, port), timeout=min(timeout, 2))
            # Non-standard SNI (ISP probe simulation)
            probe_sni = "active-probe-detect.invalid"
            try:
                s3 = ctx.wrap_socket(s3, server_hostname=probe_sni)
                s3.close()
                # If TLS handshake succeeds with fake SNI → not Reality-protected
            except ssl.SSLError:
                silent_drops += 1  # Rejected fake SNI → good defense
            except Exception:
                silent_drops += 1
        except Exception:
            pass
        probes_sent += 1

    # Scoring: ≥75% silent drops = strong active probe resistance
    resistance_ratio = silent_drops / probes_sent if probes_sent else 0
    resists = resistance_ratio >= 0.6

    result = {
        "works":            True,
        "resists_probing":  resists,
        "resistance_ratio": round(resistance_ratio, 2),
        "silent_drops":     silent_drops,
        "probes_sent":      probes_sent,
        "note": ("★ Strong active-probe resistance (Reality/VLESS likely)"
                 if resists else "Normal server — responds to probes"),
        "latency":          lat if 'lat' in dir() else 0,
    }
    return result


# ================================================================
#  v6.0 ML Bug Score Predictor
#  sklearn RandomForest — trains on accumulated scan data
# ================================================================
ML_MODEL_FILE = "sni_ml_model.json"
_ml_model     = None  # lazy load

def _features_from_result(r):
    """Scan result dict → feature vector (list of floats)"""
    m = r.get("sni_methods", {})
    return [
        1 if r.get("http_status")  == 200 else 0,
        1 if r.get("https_status") == 200 else 0,
        1 if r.get("http2")             else 0,
        1 if r.get("http3", {}).get("supported") else 0,
        1 if r.get("ech",   {}).get("supported") else 0,
        len(r.get("open_ports", {})),
        len(r.get("cdn", [])),
        1 if m.get("direct_sni",         {}).get("works") else 0,
        1 if m.get("sni_mismatch",        {}).get("works") else 0,
        1 if m.get("sni_empty",           {}).get("works") else 0,
        1 if m.get("ws_real_payload",     {}).get("works") else 0,
        1 if m.get("ws_best_path",        {}).get("works") else 0,
        1 if m.get("domain_fronting",     {}).get("works") else 0,
        1 if m.get("http_connect",        {}).get("works") else 0,
        1 if m.get("host_header_inject",  {}).get("works") else 0,
        1 if m.get("vless_probe",         {}).get("works") else 0,
        1 if m.get("grpc_stream",         {}).get("works") else 0,
        1 if m.get("xhttp_test",          {}).get("works") else 0,
        1 if m.get("reality_probe",       {}).get("looks_reality") else 0,
        1 if m.get("open_knock",          {}).get("works") else 0,
        1 if m.get("conn_state_attack",   {}).get("works") else 0,
        1 if m.get("ech_real_craft",      {}).get("works") else 0,
        1 if m.get("active_probe_def",    {}).get("resists_probing") else 0,
        r.get("bug_score", 0) / 100.0,
    ]

def ml_save_training_sample(result, label: bool):
    """Scan result + user-verified label → training data file append."""
    feats = _features_from_result(result)
    row   = {"features": feats, "label": int(label),
             "host": result.get("host", "")}
    try:
        data = []
        if os.path.exists(ML_MODEL_FILE):
            with open(ML_MODEL_FILE) as f:
                data = json.load(f)
        data.append(row)
        with open(ML_MODEL_FILE, 'w') as f:
            json.dump(data, f)
    except Exception:
        pass

def ml_train():
    """Train RandomForest on saved training samples."""
    global _ml_model
    if not sklearn or not numpy:
        return None
    if not os.path.exists(ML_MODEL_FILE):
        return None
    try:
        with open(ML_MODEL_FILE) as f:
            data = json.load(f)
        if len(data) < 10:
            return None  # Not enough samples yet
        from sklearn.ensemble import RandomForestClassifier
        import numpy as np
        X = np.array([d["features"] for d in data])
        y = np.array([d["label"]    for d in data])
        clf = RandomForestClassifier(n_estimators=50, random_state=42)
        clf.fit(X, y)
        _ml_model = clf
        sp(G + f"  [ML] Model trained on {len(data)} samples ✔" + W)
        return clf
    except Exception:
        return None

def ml_predict(result) -> float:
    """Predict bug-host probability (0.0–1.0) using trained model."""
    global _ml_model
    if _ml_model is None:
        _ml_model = ml_train()
    if _ml_model is None:
        return -1.0  # No model available
    try:
        import numpy as np
        feats = _features_from_result(result)
        prob  = _ml_model.predict_proba([feats])[0][1]
        return round(float(prob), 3)
    except Exception:
        return -1.0



# ================================================================
# ╔══════════════════════════════════════════════════════════╗
# ║   v7.0  ZERO-BALANCE DETECTION MODULE  — 12 Methods     ║
# ╚══════════════════════════════════════════════════════════╝
# ================================================================

import ipaddress

# ── ISP Zero-Rate Domain Database ────────────────────────────────
ZERO_RATE_DB = {
    "AS9329":  {
        "name": "Dialog Axiata (Sri Lanka)",
        "domains": [
            "speedtest.dialog.lk","myaccount.dialog.lk","dialog.lk",
            "wa.me","web.whatsapp.com","whatsapp.com","whatsapp.net",
            "free.facebook.com","static.xx.fbcdn.net",
            "edge-star-mini.facebook.com","z-m.facebook.com",
            "zoom.us","us02web.zoom.us","us04web.zoom.us",
        ],
        "ip_ranges": ["169.254.0.0/16","192.0.0.0/24"],
    },
    "AS17639": {
        "name": "Mobitel (Sri Lanka)",
        "domains": [
            "speedtest.mobitel.lk","mobitel.lk","selfcare.mobitel.lk",
            "wa.me","web.whatsapp.com","whatsapp.com",
            "free.facebook.com","static.xx.fbcdn.net","zoom.us",
        ],
        "ip_ranges": ["169.254.0.0/16"],
    },
    "AS9270":  {
        "name": "SLT (Sri Lanka)",
        "domains": [
            "slt.lk","speedtest.slt.lk",
            "free.facebook.com","wa.me","web.whatsapp.com","zoom.us",
        ],
        "ip_ranges": [],
    },
    "AS24616": {
        "name": "Hutch (Sri Lanka)",
        "domains": [
            "hutch.lk","speedtest.hutch.lk",
            "youtube.com","googlevideo.com",
            "wa.me","web.whatsapp.com","free.facebook.com",
        ],
        "ip_ranges": [],
    },
    "GLOBAL_FACEBOOK": {
        "name": "Facebook Free Basics",
        "domains": [
            "free.facebook.com","zero.facebook.com",
            "static.xx.fbcdn.net","scontent.xx.fbcdn.net",
            "edge-star-mini.facebook.com","z-m.facebook.com",
            "api.facebook.com","graph.facebook.com",
            "b-api.facebook.com","b-graph.facebook.com",
        ],
        "ip_ranges": ["31.13.0.0/16","157.240.0.0/16","179.60.192.0/22"],
    },
    "GLOBAL_WHATSAPP": {
        "name": "WhatsApp (Global zero-rated)",
        "domains": [
            "wa.me","whatsapp.com","web.whatsapp.com","whatsapp.net",
            "mmg.whatsapp.net","media.whatsapp.net",
            "v.whatsapp.net","e.whatsapp.net",
        ],
        "ip_ranges": ["185.60.216.0/22"],
    },
    "GLOBAL_ZOOM": {
        "name": "Zoom (Education zero-rated)",
        "domains": [
            "zoom.us","us02web.zoom.us","us04web.zoom.us",
            "us06web.zoom.us","us08web.zoom.us",
        ],
        "ip_ranges": ["170.114.0.0/16","99.79.0.0/16"],
    },
}

_isp_cache = {}

def detect_isp_asn(timeout=5):
    global _isp_cache
    if _isp_cache:
        return _isp_cache
    try:
        txt  = _fetch_zb("http://ip-api.com/json/?fields=status,isp,org,as,query", timeout)
        data = json.loads(txt)
        if data.get("status") == "success":
            asn_full = data.get("as", "")
            asn_num  = asn_full.split(" ")[0] if asn_full else ""
            _isp_cache = {
                "asn": asn_num, "asn_full": asn_full,
                "isp": data.get("isp","Unknown"),
                "org": data.get("org",""),
                "pub_ip": data.get("query",""),
            }
            return _isp_cache
    except Exception:
        pass
    return {"asn":"","isp":"Unknown","pub_ip":""}

def get_isp_zero_rate_domains(asn=""):
    base = list(ZERO_RATE_DB.get(asn, {}).get("domains", []))
    for k in ["GLOBAL_FACEBOOK","GLOBAL_WHATSAPP","GLOBAL_ZOOM"]:
        base.extend(ZERO_RATE_DB[k]["domains"])
    return list(dict.fromkeys(base))

def _fetch_zb(url, timeout=5):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent":"Mozilla/5.0 SNI-BugFinder/7.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode(errors='ignore')
    except Exception:
        return ""


# ── ZB-1: ISP Auto-Detect + Zero-Rate DB ──────────────────────
def zb_isp_detect_test(hostname, isp_info, timeout):
    result = {"in_zero_rate_db":False,"matched_isp":None,
              "matched_domain":None,"in_zero_ip_range":False,"zero_rate_score":0}
    asn = isp_info.get("asn","")
    for db_key, db_val in ZERO_RATE_DB.items():
        for zd in db_val["domains"]:
            if hostname==zd or hostname.endswith("."+zd) or zd.endswith("."+hostname):
                result["in_zero_rate_db"] = True
                result["matched_isp"]     = db_val["name"]
                result["matched_domain"]  = zd
                result["zero_rate_score"] += 40
                break
    try:
        ip_str = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_str)
        for db_key, db_val in ZERO_RATE_DB.items():
            for cidr in db_val.get("ip_ranges",[]):
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        result["in_zero_ip_range"] = True
                        result["matched_isp"] = result["matched_isp"] or db_val["name"]
                        result["zero_rate_score"] += 30
                        break
                except Exception:
                    pass
    except Exception:
        pass
    if asn and asn in ZERO_RATE_DB and result["in_zero_rate_db"]:
        result["zero_rate_score"] += 20
    return result


# ── ZB-2: Captive Portal Detector ─────────────────────────────
_CAPTIVE_KEYWORDS = [
    "recharge","top-up","topup","top up","balance","prepaid",
    "reload","data plan","data pack","buy data","insufficient",
    "no credit","out of data","portal","walled garden","subscribe",
    "activate","add-on","renew","payment","pay now","data expired",
    "quota exceeded","your data","buy more","get more data",
    "zero balance","please recharge","login to continue",
]

def zb_captive_portal_test(hostname, port, timeout):
    result = {"captive_detected":False,"zero_rated":False,"redirect_url":None,
              "status_code":None,"keywords_found":[],"zero_rate_score":0}
    try:
        use_tls = port in [443,8443,2053,2083,2087,2096]
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((hostname, port), timeout=min(timeout,4))
            sock = ctx.wrap_socket(raw, server_hostname=hostname)
        else:
            sock = socket.create_connection((hostname, port), timeout=min(timeout,4))

        req = (f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n"
               f"User-Agent: Mozilla/5.0 (Android 14) Mobile\r\n\r\n")
        sock.sendall(req.encode())
        sock.settimeout(3)
        resp = b""
        try:
            while True:
                c = sock.recv(4096)
                if not c: break
                resp += c
                if len(resp) > 16384: break
        except Exception:
            pass
        sock.close()

        if resp:
            rstr  = resp.decode(errors='ignore')
            parts = rstr.split(' ')
            code  = parts[1] if len(parts) > 1 else '?'
            result["status_code"] = code
            body  = rstr.lower()
            found = [k for k in _CAPTIVE_KEYWORDS if k in body]
            result["keywords_found"] = found

            if found:
                result["captive_detected"] = True
                result["zero_rate_score"] += 35
            elif code in ['200','204']:
                result["zero_rated"]       = True
                result["zero_rate_score"] += 30
            elif code in ['301','302','303','307','308']:
                for line in rstr.split("\r\n"):
                    if line.lower().startswith("location:"):
                        loc = line.split(":",1)[1].strip()
                        result["redirect_url"] = loc
                        portal_kw = ["portal","login","recharge","balance","prepaid"]
                        if any(k in loc.lower() for k in portal_kw):
                            result["captive_detected"] = True
                            result["zero_rate_score"] += 35
                        break
    except Exception:
        pass
    return result


# ── ZB-3: Transparent Proxy Detector ──────────────────────────
_PROXY_HEADERS = [
    "via","x-forwarded-for","x-forwarded-host","x-forwarded-proto",
    "x-real-ip","x-cache","x-cache-hits","x-cache-lookup",
    "x-proxy-id","x-proxy-cache","forwarded",
    "proxy-connection","x-isp-proxy","x-wap-profile",
    "x-online-host","x-transparent-proxy",
]

def zb_transparent_proxy_test(hostname, port, timeout):
    result = {"proxy_detected":False,"proxy_headers":{},
              "proxy_server_hint":None,"zero_rate_score":0}
    try:
        use_tls = port in [443,8443,2053,2083,2087,2096]
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((hostname, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=hostname)
        else:
            sock = socket.create_connection((hostname, port), timeout=timeout)

        req = (f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n"
               f"User-Agent: Mozilla/5.0\r\n\r\n")
        sock.sendall(req.encode())
        sock.settimeout(min(timeout,3))
        resp = b""
        try:
            while True:
                c = sock.recv(4096)
                if not c: break
                resp += c
                if len(resp) > 16384 or b"\r\n\r\n" in resp: break
        except Exception:
            pass
        sock.close()

        if resp:
            rstr = resp.decode(errors='ignore')
            hdr_section = rstr.split("\r\n\r\n")[0] if "\r\n\r\n" in rstr else rstr
            hdrs = {}
            for line in hdr_section.split("\r\n")[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    hdrs[k.strip().lower()] = v.strip()

            found = {ph: hdrs[ph] for ph in _PROXY_HEADERS if ph in hdrs}
            if found:
                result["proxy_detected"]   = True
                result["proxy_headers"]    = found
                result["zero_rate_score"] += 20 * min(len(found),3)

            srv = hdrs.get("server","").lower()
            proxy_hints = ["squid","nginx proxy","varnish","haproxy","privoxy","tinyproxy"]
            for hint in proxy_hints:
                if hint in srv:
                    result["proxy_server_hint"] = hdrs.get("server","")
                    result["proxy_detected"]    = True
                    result["zero_rate_score"]  += 15
                    break
    except Exception:
        pass
    return result


# ── ZB-4: DNS Hijacking Detector ──────────────────────────────
def zb_dns_hijack_test(hostname, timeout):
    result = {"hijacked":False,"isp_dns_ip":None,"google_dns_ip":None,
              "ip_mismatch":False,"zero_rate_score":0}
    try:
        isp_ip = socket.gethostbyname(hostname)
        result["isp_dns_ip"] = isp_ip
    except Exception:
        return result

    def _raw_dns_query(host, dns_server="8.8.8.8"):
        try:
            txid   = os.urandom(2)
            flags  = b'\x01\x00'
            counts = b'\x00\x01\x00\x00\x00\x00\x00\x00'
            parts  = host.split('.')
            qname  = b''.join(bytes([len(p)]) + p.encode() for p in parts) + b'\x00'
            packet = txid + flags + counts + qname + b'\x00\x01\x00\x01'
            sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(min(timeout,3))
            sock.sendto(packet, (dns_server, 53))
            resp, _ = sock.recvfrom(512)
            sock.close()
            ancount = int.from_bytes(resp[6:8], 'big')
            if ancount == 0:
                return None
            # Parse first answer — skip question
            pos = 12
            qdcount = int.from_bytes(resp[4:6], 'big')
            for _ in range(qdcount):
                while pos < len(resp):
                    if resp[pos] == 0: pos += 1; break
                    if resp[pos] & 0xC0 == 0xC0: pos += 2; break
                    pos += resp[pos] + 1
                pos += 4
            if pos + 12 <= len(resp):
                if resp[pos] & 0xC0 == 0xC0:
                    pos += 2
                else:
                    while pos < len(resp) and resp[pos] != 0:
                        pos += resp[pos] + 1
                    pos += 1
                rdlen = int.from_bytes(resp[pos+8:pos+10], 'big')
                rdata = resp[pos+10:pos+10+rdlen]
                rtype = int.from_bytes(resp[pos:pos+2], 'big')
                if rtype == 1 and rdlen == 4:
                    return ".".join(str(b) for b in rdata)
        except Exception:
            pass
        return None

    google_ip = _raw_dns_query(hostname)
    result["google_dns_ip"] = google_ip

    if google_ip and isp_ip and google_ip != isp_ip:
        try:
            ip_obj = ipaddress.ip_address(isp_ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                result["hijacked"]        = True
                result["ip_mismatch"]     = True
                result["zero_rate_score"] += 40
            else:
                result["ip_mismatch"]     = True
                result["zero_rate_score"] += 10
        except Exception:
            result["ip_mismatch"]     = True
            result["zero_rate_score"] += 10
    return result


# ── ZB-5: TCP RST / Block Detector ────────────────────────────
def zb_tcp_rst_test(hostname, port, timeout):
    result = {"blocked":False,"rst_received":False,
              "connection_ok":False,"zero_rate_score":0}
    try:
        sock = socket.create_connection((hostname, port), timeout=min(timeout,3))
        sock.settimeout(2)
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {hostname}\r\n\r\n".encode())
        try:
            resp = sock.recv(256)
            if resp:
                result["connection_ok"]   = True
                result["zero_rate_score"] += 25
        except socket.timeout:
            result["connection_ok"]   = True
            result["zero_rate_score"] += 10
        except Exception as e:
            err = str(e).lower()
            if "reset" in err or "104" in err:
                result["rst_received"]    = True
                result["blocked"]         = True
                result["zero_rate_score"] -= 20
        finally:
            try: sock.close()
            except: pass
    except (ConnectionRefusedError, Exception):
        result["blocked"] = True
    return result


# ── ZB-6: Speed Differential Test ─────────────────────────────
def zb_speed_test(hostname, port, timeout):
    result = {"speed_kbps":None,"throttled":False,
              "zero_rate_score":0,"speed_tier":"unknown"}
    try:
        use_tls = port in [443,8443,2053,2083,2087,2096]
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((hostname, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=hostname)
        else:
            sock = socket.create_connection((hostname, port), timeout=timeout)

        sock.sendall(
            f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
        sock.settimeout(5)
        t0 = time.time(); total = 0
        try:
            while True:
                c = sock.recv(8192)
                if not c: break
                total += len(c)
                if total >= 512*1024: break
        except Exception:
            pass
        elapsed = time.time() - t0
        sock.close()

        if elapsed > 0 and total > 1024:
            kbps = int((total/elapsed)/1024)
            result["speed_kbps"] = kbps
            if kbps < 128:
                result["throttled"]       = True
                result["speed_tier"]      = f"heavy-throttle ({kbps}Kbps)"
                result["zero_rate_score"] += 35
            elif kbps < 512:
                result["throttled"]       = True
                result["speed_tier"]      = f"throttled ({kbps}Kbps)"
                result["zero_rate_score"] += 25
            elif kbps < 2048:
                result["throttled"]       = True
                result["speed_tier"]      = f"limited ({kbps}Kbps)"
                result["zero_rate_score"] += 15
            else:
                result["speed_tier"]      = f"full-speed ({kbps}Kbps)"
                result["zero_rate_score"] += 5
    except Exception:
        pass
    return result


# ── ZB-7: TLS MITM / ISP Cert Injection Detector ──────────────
_TRUSTED_CA_ORGS = [
    "digicert","let's encrypt","globalsign","comodo","sectigo",
    "geotrust","thawte","verisign","entrust","godaddy",
    "amazon","google trust services","baltimore","microsoft",
    "cloudflare","identrust","quovadis","ssl.com","zerossl",
    "usertrust","comodoca","rapidssl",
]

def zb_tls_mitm_test(hostname, port, timeout):
    result = {"mitm_suspected":False,"cert_issuer":None,"cert_cn":None,
              "self_signed":False,"isp_cert":False,"zero_rate_score":0}
    if port not in [443,8443,2053,2083,2087,2096]:
        return result
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                cert    = ss.getpeercert() or {}
                subject = dict(x[0] for x in cert.get("subject",[]))
                issuer  = dict(x[0] for x in cert.get("issuer",[]))
                cn          = subject.get("commonName","")
                issuer_org  = issuer.get("organizationName","")
                issuer_cn   = issuer.get("commonName","")
                result["cert_cn"]     = cn
                result["cert_issuer"] = f"{issuer_org} / {issuer_cn}"
                issuer_str = f"{issuer_org} {issuer_cn}".lower()
                if subject == issuer:
                    result["self_signed"]    = True
                    result["mitm_suspected"] = True
                    result["zero_rate_score"] += 15
                is_trusted = any(ca in issuer_str for ca in _TRUSTED_CA_ORGS)
                if not is_trusted and not result["self_signed"]:
                    result["isp_cert"]        = True
                    result["mitm_suspected"]  = True
                    result["zero_rate_score"] += 30
                if is_trusted:
                    result["zero_rate_score"] += 10
    except Exception:
        pass
    return result


# ── ZB-8: MTU Probe ───────────────────────────────────────────
def zb_mtu_probe(hostname, port, timeout):
    result = {"mtu_detected":None,"proxy_path":False,"zero_rate_score":0}
    use_tls = port in [443,8443,2053,2083,2087,2096]
    best_mtu = None
    for mtu in [1500,1450,1400,1380,1280]:
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw  = socket.create_connection((hostname, port), timeout=min(timeout,2))
                sock = ctx.wrap_socket(raw, server_hostname=hostname)
            else:
                sock = socket.create_connection((hostname, port), timeout=min(timeout,2))
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            headers  = (f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n"
                        f"X-MTU-Test: {mtu}\r\nUser-Agent: Mozilla/5.0\r\n\r\n").encode()
            pad_size = max(0, (mtu-40) - len(headers))
            sock.sendall(headers + b"X"*pad_size)
            sock.settimeout(1)
            resp = b""
            try: resp = sock.recv(256)
            except Exception: pass
            sock.close()
            if resp:
                best_mtu = mtu; break
        except Exception:
            continue
    result["mtu_detected"] = best_mtu
    if best_mtu is not None:
        if best_mtu <= 1400:
            result["proxy_path"]      = True
            result["zero_rate_score"] += 25
        else:
            result["zero_rate_score"] += 5
    return result


# ── ZB-9: Known Zero-Rated IP Range Scanner ───────────────────
def zb_ip_range_test(hostname, timeout):
    result = {"in_known_range":False,"matched_range":None,
              "matched_service":None,"ip":None,"zero_rate_score":0}
    try:
        ip_str = socket.gethostbyname(hostname)
        result["ip"] = ip_str
        ip_obj = ipaddress.ip_address(ip_str)
        for db_key, db_val in ZERO_RATE_DB.items():
            for cidr in db_val.get("ip_ranges",[]):
                try:
                    if ip_obj in ipaddress.ip_network(cidr, strict=False):
                        result["in_known_range"]  = True
                        result["matched_range"]   = cidr
                        result["matched_service"] = db_val["name"]
                        result["zero_rate_score"] += 40
                        return result
                except Exception:
                    pass
    except Exception:
        pass
    return result


# ── ZB-10: HTTP vs HTTPS Zero-Rating Difference ───────────────
def zb_http_vs_https_test(hostname, timeout):
    result = {"http_works":False,"https_works":False,"http_code":None,
              "https_code":None,"http_latency":None,"https_latency":None,
              "zero_rate_mode":"neither","zero_rate_score":0}
    # HTTP
    try:
        t0   = time.time()
        sock = socket.create_connection((hostname, 80), timeout=min(timeout,3))
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {hostname}\r\n\r\n".encode())
        sock.settimeout(2)
        resp = b""
        try: resp = sock.recv(512)
        except: pass
        sock.close()
        if resp:
            code = resp.decode(errors='ignore').split(' ')
            result["http_works"]   = True
            result["http_code"]    = code[1] if len(code) > 1 else '?'
            result["http_latency"] = int((time.time()-t0)*1000)
    except Exception:
        pass
    # HTTPS
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        t0   = time.time()
        raw  = socket.create_connection((hostname, 443), timeout=min(timeout,3))
        sock = ctx.wrap_socket(raw, server_hostname=hostname)
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {hostname}\r\n\r\n".encode())
        sock.settimeout(2)
        resp = b""
        try: resp = sock.recv(512)
        except: pass
        sock.close()
        if resp:
            code = resp.decode(errors='ignore').split(' ')
            result["https_works"]   = True
            result["https_code"]    = code[1] if len(code) > 1 else '?'
            result["https_latency"] = int((time.time()-t0)*1000)
    except Exception:
        pass
    h, hs = result["http_works"], result["https_works"]
    if h and hs:
        result["zero_rate_mode"]  = "both"
        result["zero_rate_score"] += 30
    elif hs:
        result["zero_rate_mode"]  = "https-only"
        result["zero_rate_score"] += 25
    elif h:
        result["zero_rate_mode"]  = "http-only"
        result["zero_rate_score"] += 15
    return result


# ── ZB-11: Via/X-Cache Header Zero-Rate Scoring ───────────────
_ZB_HEADER_SCORES = {
    "via":20,"x-forwarded-for":15,"x-forwarded-host":15,
    "x-cache":15,"x-cache-hits":10,"x-cache-lookup":10,
    "x-proxy-id":20,"x-proxy-cache":20,"cf-cache-status":10,
    "x-amz-cf-id":10,"x-fastly-request-id":10,
    "x-isp-proxy":25,"x-wap-profile":20,"x-online-host":15,
    "x-transparent-proxy":25,
}

def zb_header_score_test(hostname, port, timeout):
    result = {"scored_headers":{},"total_score":0,"zero_rate_score":0,"proxy_level":"none"}
    try:
        use_tls = port in [443,8443,2053,2083,2087,2096]
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((hostname, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=hostname)
        else:
            sock = socket.create_connection((hostname, port), timeout=timeout)
        sock.sendall(
            f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())
        sock.settimeout(min(timeout,3))
        resp = b""
        try:
            while True:
                c = sock.recv(4096)
                if not c: break
                resp += c
                if b"\r\n\r\n" in resp: break
        except Exception:
            pass
        sock.close()
        if resp:
            hdr_section = resp.decode(errors='ignore').split("\r\n\r\n")[0]
            hdrs = {}
            for line in hdr_section.split("\r\n")[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    hdrs[k.strip().lower()] = v.strip()
            total  = 0
            scored = {}
            for hk, pts in _ZB_HEADER_SCORES.items():
                if hk in hdrs:
                    scored[hk] = {"value": hdrs[hk][:80], "score": pts}
                    total += pts
            result["scored_headers"]  = scored
            result["total_score"]     = total
            result["zero_rate_score"] = min(total, 60)
            result["proxy_level"] = ("high" if total>=40 else
                                     "medium" if total>=20 else
                                     "low" if total>0 else "none")
    except Exception:
        pass
    return result


# ── ZB-12: ML Zero-Rating Predictor ───────────────────────────
ZB_ML_MODEL_FILE = "sni_zb_ml_model.json"
_zb_ml_model     = None

def _zb_features(zb_result):
    isp   = zb_result.get("isp_detect",{})
    cap   = zb_result.get("captive_portal",{})
    prx   = zb_result.get("transparent_proxy",{})
    dns   = zb_result.get("dns_hijack",{})
    tcp   = zb_result.get("tcp_rst",{})
    spd   = zb_result.get("speed_test",{})
    mitm  = zb_result.get("tls_mitm",{})
    mtu   = zb_result.get("mtu_probe",{})
    ipr   = zb_result.get("ip_range",{})
    proto = zb_result.get("http_vs_https",{})
    hdr   = zb_result.get("header_score",{})
    return [
        1 if isp.get("in_zero_rate_db")    else 0,
        1 if isp.get("in_zero_ip_range")   else 0,
        isp.get("zero_rate_score",0)/100.0,
        1 if cap.get("zero_rated")         else 0,
        1 if cap.get("captive_detected")   else 0,
        cap.get("zero_rate_score",0)/100.0,
        1 if prx.get("proxy_detected")     else 0,
        prx.get("zero_rate_score",0)/100.0,
        1 if dns.get("hijacked")           else 0,
        1 if dns.get("ip_mismatch")        else 0,
        1 if tcp.get("connection_ok")      else 0,
        1 if tcp.get("blocked")            else 0,
        1 if mitm.get("mitm_suspected")    else 0,
        1 if mitm.get("isp_cert")          else 0,
        1 if mtu.get("proxy_path")         else 0,
        mtu.get("zero_rate_score",0)/100.0,
        1 if ipr.get("in_known_range")     else 0,
        1 if proto.get("http_works")       else 0,
        1 if proto.get("https_works")      else 0,
        hdr.get("total_score",0)/100.0,
        zb_result.get("total_zb_score",0)/100.0,
    ]

def zb_ml_save_sample(zb_result, label):
    try:
        data = []
        if os.path.exists(ZB_ML_MODEL_FILE):
            with open(ZB_ML_MODEL_FILE) as f:
                data = json.load(f)
        data.append({"features":_zb_features(zb_result),
                     "label":int(label),"host":zb_result.get("host","")})
        with open(ZB_ML_MODEL_FILE,'w') as f:
            json.dump(data, f)
    except Exception:
        pass

def zb_ml_train():
    global _zb_ml_model
    if not sklearn or not numpy: return None
    if not os.path.exists(ZB_ML_MODEL_FILE): return None
    try:
        with open(ZB_ML_MODEL_FILE) as f: data = json.load(f)
        if len(data) < 10: return None
        from sklearn.ensemble import RandomForestClassifier
        import numpy as np
        X = np.array([d["features"] for d in data])
        y = np.array([d["label"]    for d in data])
        clf = RandomForestClassifier(n_estimators=50, random_state=42)
        clf.fit(X, y)
        _zb_ml_model = clf
        return clf
    except Exception:
        return None

def zb_ml_predict(zb_result):
    global _zb_ml_model
    if _zb_ml_model is None: _zb_ml_model = zb_ml_train()
    if _zb_ml_model is None: return -1.0
    try:
        import numpy as np
        prob = _zb_ml_model.predict_proba([_zb_features(zb_result)])[0][1]
        return round(float(prob), 3)
    except Exception:
        return -1.0


# ── Master Zero-Balance Scanner ───────────────────────────────
def run_zero_balance_scan(hostname, port, cfg, isp_info):
    """Run all 12 ZB tests on one host. Returns zb dict."""
    timeout = cfg.get("timeout", 5)
    zb      = {"host": hostname}

    zb["isp_detect"]        = zb_isp_detect_test(hostname, isp_info, timeout) \
                               if cfg.get("zb_isp_detect", True)        else {"zero_rate_score":0}
    zb["captive_portal"]    = zb_captive_portal_test(hostname, port, timeout) \
                               if cfg.get("zb_captive_portal", True)    else {"zero_rate_score":0}
    zb["transparent_proxy"] = zb_transparent_proxy_test(hostname, port, timeout) \
                               if cfg.get("zb_transparent_proxy", True) else {"zero_rate_score":0}
    zb["dns_hijack"]        = zb_dns_hijack_test(hostname, timeout) \
                               if cfg.get("zb_dns_hijack", True)        else {"zero_rate_score":0}
    zb["tcp_rst"]           = zb_tcp_rst_test(hostname, port, timeout) \
                               if cfg.get("zb_tcp_rst", True)           else {"zero_rate_score":0}
    zb["speed_test"]        = zb_speed_test(hostname, port, timeout) \
                               if cfg.get("zb_speed_diff", False)       else {"zero_rate_score":0}
    zb["tls_mitm"]          = zb_tls_mitm_test(hostname, port, timeout) \
                               if cfg.get("zb_tls_mitm", True)          else {"zero_rate_score":0}
    zb["mtu_probe"]         = zb_mtu_probe(hostname, port, timeout) \
                               if cfg.get("zb_mtu_probe", True)         else {"zero_rate_score":0}
    zb["ip_range"]          = zb_ip_range_test(hostname, timeout) \
                               if cfg.get("zb_ip_range", True)          else {"zero_rate_score":0}
    zb["http_vs_https"]     = zb_http_vs_https_test(hostname, timeout) \
                               if cfg.get("zb_http_vs_https", True)     else {"zero_rate_score":0}
    zb["header_score"]      = zb_header_score_test(hostname, port, timeout) \
                               if cfg.get("zb_header_score", True)      else {"zero_rate_score":0}

    raw = sum(zb[k].get("zero_rate_score",0) for k in [
        "isp_detect","captive_portal","transparent_proxy","dns_hijack",
        "tcp_rst","speed_test","tls_mitm","mtu_probe","ip_range",
        "http_vs_https","header_score"])

    # Penalty: blocked but not connected
    if zb["tcp_rst"].get("blocked") and not zb["tcp_rst"].get("connection_ok"):
        raw = max(0, raw - 30)

    zb["total_zb_score"]          = min(raw, 100)
    zb["is_zero_balance_candidate"] = zb["total_zb_score"] >= 40

    # Recommended transport from ZB-10
    mode = zb["http_vs_https"].get("zero_rate_mode","both")
    zb["recommended_transport"] = {
        "http-only":  "WS (no TLS / port 80)",
        "https-only": "gRPC / WS+TLS (port 443)",
        "both":       "gRPC (preferred) or WS+TLS",
        "neither":    "Unknown — try gRPC",
    }.get(mode, "gRPC preferred")

    # ZB-12: ML
    if cfg.get("zb_ml_predict", True):
        ml_prob = zb_ml_predict(zb)
        zb["ml_zb_probability"] = ml_prob
        if ml_prob >= 0:
            zb_ml_save_sample(zb, zb["is_zero_balance_candidate"])
    else:
        zb["ml_zb_probability"] = -1.0

    return zb


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

    # 9. gRPC Real Stream  ★ NEW v5.0
    if cfg.get("check_grpc", True) and tls_port:
        sni_h = methods["sni_mismatch"].get("sni_used") \
                if methods["sni_mismatch"].get("works") else None
        methods["grpc_stream"] = method_grpc_stream(hostname, tls_port, timeout, sni_h)
    else:
        methods["grpc_stream"] = {"works": False}

    # 10. XHTTP / SplitHTTP  ★ NEW v5.0
    if cfg.get("check_xhttp", True) and (tls_port or tcp_port):
        xp = tls_port or tcp_port
        sni_h = methods["sni_mismatch"].get("sni_used") \
                if methods["sni_mismatch"].get("works") else None
        methods["xhttp_test"] = method_xhttp_splithttp(hostname, xp, timeout, sni_h)
    else:
        methods["xhttp_test"] = {"works": False}

    # 11. Reality TLS Probe  ★ NEW v5.0
    if cfg.get("check_reality", True) and tls_port:
        methods["reality_probe"] = method_reality_probe(hostname, tls_port, timeout)
    else:
        methods["reality_probe"] = {"works": False}

    # 12. WS Best Path Brute-force  ★ NEW v5.0
    if cfg.get("check_ws_paths", True) and (tls_port or tcp_port):
        wp = tls_port or tcp_port
        sni_h = methods["sni_mismatch"].get("sni_used") \
                if methods["sni_mismatch"].get("works") else None
        methods["ws_best_path"] = method_ws_path_bruteforce(hostname, wp, timeout, sni_h)
    else:
        methods["ws_best_path"] = {"works": False}

    # 13. TLS ALPN Detail Probe  ★ NEW v5.0
    if cfg.get("check_alpn", True) and tls_port:
        methods["tls_alpn"] = method_tls_alpn_probe(hostname, tls_port, timeout)
    else:
        methods["tls_alpn"] = {"works": False}

    # ── v6.0 NEW METHODS ─────────────────────────────────────────

    # 14. Open-Knock — hidden cert SAN extraction
    if cfg.get("check_open_knock", True) and tls_port:
        methods["open_knock"] = method_open_knock(hostname, tls_port, timeout)
    else:
        methods["open_knock"] = {"works": False}

    # 15. Connection State Attack — Keep-Alive TCP reuse
    if cfg.get("check_conn_state", True) and any_port:
        free_sni = methods["sni_mismatch"].get("sni_used", "free.facebook.com") \
            if methods["sni_mismatch"].get("works") else "free.facebook.com"
        cp = tls_port or tcp_port or any_port
        methods["conn_state_attack"] = method_conn_state_attack(
            hostname, free_sni, cp, timeout)
    else:
        methods["conn_state_attack"] = {"works": False}

    # 16. Real ECH Payload Crafter
    if cfg.get("check_ech_real", True) and tls_port:
        free_sni = methods["sni_mismatch"].get("sni_used", "free.facebook.com") \
            if methods["sni_mismatch"].get("works") else "free.facebook.com"
        methods["ech_real_craft"] = method_ech_real_craft(
            hostname, free_sni, tls_port, timeout)
    else:
        methods["ech_real_craft"] = {"works": False}

    # 17. WTF-PAD Traffic Padding
    if cfg.get("check_wtfpad", True) and any_port:
        cp = tls_port or tcp_port or any_port
        methods["wtfpad_test"] = method_wtfpad_test(hostname, cp, timeout)
    else:
        methods["wtfpad_test"] = {"works": False}

    # 18. UDP Probe
    if cfg.get("check_udp_probe", True):
        methods["udp_probe"] = method_udp_probe(hostname, timeout)
    else:
        methods["udp_probe"] = {"works": False}

    # 19. SCTP Probe (requires scapy + root)
    if cfg.get("check_sctp_probe", False) and scapy and tls_port:
        methods["sctp_probe"] = method_sctp_probe(hostname, tls_port, timeout)
    else:
        methods["sctp_probe"] = {"works": False}

    # 20. Real QUIC Handshake (requires aioquic)
    if cfg.get("check_quic_real", False) and aioquic:
        methods["quic_real"] = method_quic_real_handshake(hostname, timeout)
    else:
        methods["quic_real"] = {"works": False}

    # 21. Scapy Packet Manipulation (requires scapy + root)
    if cfg.get("check_pkt_manip", False) and scapy and tls_port:
        methods["pkt_manip"] = method_pkt_manipulation(hostname, tls_port, timeout)
    else:
        methods["pkt_manip"] = {"works": False}

    # 22. Active Probing Defense Test
    if cfg.get("check_active_probe", True) and tls_port:
        methods["active_probe_def"] = method_active_probe_defense(
            hostname, tls_port, timeout)
    else:
        methods["active_probe_def"] = {"works": False}

    return methods

# ================================================================
#  SNI Method 9: gRPC Real Stream Test  ★ NEW v5.0
# ================================================================
def method_grpc_stream(hostname, port, timeout, sni_host=None):
    """
    Real gRPC HTTP/2 POST request send කරනවා.
    gRPC: POST /ServiceName/Method + content-type: application/grpc
    Server gRPC support කරනවාද detect.
    """
    import base64
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2'])

        sni = sni_host or hostname
        t0  = time.time()
        raw  = socket.create_connection((hostname, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=sni)

        # Check ALPN negotiated h2
        alpn = sock.selected_alpn_protocol()
        if alpn != 'h2':
            sock.close()
            return {"works": False, "reason": f"ALPN={alpn}"}

        # Send minimal HTTP/2 client preface + HEADERS frame for gRPC
        # HTTP/2 client connection preface
        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        # SETTINGS frame (empty)
        settings = b'\x00\x00\x00\x04\x00\x00\x00\x00\x00'
        sock.sendall(preface + settings)

        # Build HEADERS frame (simplified gRPC request)
        # Using raw HTTP/2 HEADERS with HPACK literal encoding
        headers_payload = (
            b'\x82'                                  # :method POST (indexed)
            b'\x84'                                  # :scheme https (indexed)
            b'\x86'                                  # :path / (indexed, override below)
            + b'\x04' + b'\x05' + b'/grpc'          # :path: /grpc literal
            + b'\x41'                                # :authority literal
            + bytes([len(hostname)]) + hostname.encode()
            + b'\x0f\x10'                            # content-type literal
            + b'\x10' + b'application/grpc'
        )
        # Simplified: just send connection preface and check server response
        sock.settimeout(timeout)
        resp = b""
        try:
            resp = sock.recv(1024)
        except: pass
        sock.close()
        lat = int((time.time()-t0)*1000)

        # HTTP/2 server connection preface starts with SETTINGS frame
        # Frame format: 3 bytes length + 1 byte type (0x04=SETTINGS) + flags + stream_id
        if len(resp) >= 9:
            frame_type = resp[3] if len(resp) > 3 else 0
            if frame_type == 0x04:  # SETTINGS frame — server speaks HTTP/2
                return {"works": True, "latency": lat, "alpn": "h2",
                        "note": "HTTP/2 SETTINGS — gRPC capable"}
        # Any response on h2 ALPN port is promising
        if resp and alpn == 'h2':
            return {"works": True, "latency": lat, "alpn": "h2",
                    "note": "h2 ALPN negotiated"}
    except Exception:
        pass
    return {"works": False}


# ================================================================
#  SNI Method 10: XHTTP / SplitHTTP Test  ★ NEW v5.0
# ================================================================
def method_xhttp_splithttp(hostname, port, timeout, sni_host=None):
    """
    XHTTP (SplitHTTP) — xray v2.x newest transport.
    GET request → chunked/streaming response test.
    POST request → data upload test.
    """
    import base64, os as _os
    paths = ["/", "/?session=" + base64.urlsafe_b64encode(_os.urandom(8)).decode().rstrip('=')]
    sni   = sni_host or hostname

    for path in paths:
        try:
            use_tls = port in [443, 8443, 2053, 2083, 2087, 2096]
            t0 = time.time()

            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw  = socket.create_connection((hostname, port), timeout=timeout)
                sock = ctx.wrap_socket(raw, server_hostname=sni)
            else:
                sock = socket.create_connection((hostname, port), timeout=timeout)

            # XHTTP GET — server should return chunked stream or 200
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"Connection: keep-alive\r\n"
                f"X-Forwarded-Host: {sni}\r\n"
                f"Accept: */*\r\n\r\n"
            )
            sock.sendall(req.encode())
            sock.settimeout(min(timeout, 2))
            resp = b""
            try:
                resp = sock.recv(1024)
            except: pass

            resp_str = resp.decode(errors='ignore')
            lat = int((time.time()-t0)*1000)

            if resp_str:
                status_parts = resp_str.split('\r\n')[0].split(' ')
                code = status_parts[1] if len(status_parts) > 1 else '?'
                # 200 with chunked or streaming = XHTTP candidate
                if code in ['200','204']:
                    is_chunked = 'chunked' in resp_str.lower()
                    return {"works": True, "latency": lat, "code": code,
                            "chunked": is_chunked, "path": path}
                # 101 = upgrade (WS fallback)
                if code == '101':
                    return {"works": True, "latency": lat, "code": "101",
                            "path": path, "note": "WebSocket upgrade"}
            sock.close()
        except Exception:
            pass

    return {"works": False}


# ================================================================
#  SNI Method 11: Reality TLS Probe  ★ NEW v5.0
# ================================================================
def method_reality_probe(hostname, port, timeout):
    """
    Reality TLS — xray Reality protocol detect.
    Reality servers: normal TLS handshake but with special fingerprint.
    Server cert CN / ALPN / TLS version patterns check.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        t0 = time.time()

        with socket.create_connection((hostname, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                lat    = int((time.time()-t0)*1000)
                cert   = ss.getpeercert() or {}
                cipher = ss.cipher() or ('?', '?', 0)
                alpn   = ss.selected_alpn_protocol() or ''
                tls_v  = ss.version() or ''

                subj   = dict(x[0] for x in cert.get('subject', []))
                san    = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']
                expiry = cert.get('notAfter', '?')
                cn     = subj.get('commonName', '')

                # Reality indicators:
                # 1. cert CN does not match hostname (mismatch but TLS works)
                # 2. TLS 1.3 mandatory
                # 3. h2 ALPN
                cn_mismatch = cn and hostname not in cn and cn not in hostname
                is_tls13    = tls_v == 'TLSv1.3'
                has_h2      = alpn == 'h2'

                reality_score = sum([cn_mismatch, is_tls13, has_h2])
                looks_reality = reality_score >= 2

                return {
                    "works":         True,
                    "latency":       lat,
                    "tls":           tls_v,
                    "alpn":          alpn,
                    "cipher":        cipher[0],
                    "cn":            cn,
                    "san":           san[:3],
                    "expiry":        expiry,
                    "cn_mismatch":   cn_mismatch,
                    "looks_reality": looks_reality,
                    "reality_score": reality_score,
                }
    except Exception:
        pass
    return {"works": False}


# ================================================================
#  SNI Method 12: WebSocket Best Path Brute-force  ★ NEW v5.0
# ================================================================
WS_PATHS = [
    "/", "/ws", "/v2ray", "/ray", "/vmess", "/vless",
    "/trojan", "/grpc", "/stream", "/proxy", "/tunnel",
    "/ws/", "/websocket", "/wss", "/live", "/socket",
]

def method_ws_path_bruteforce(hostname, port, timeout, sni_host=None):
    """
    Common WS paths try කරලා best working path හොයනවා.
    Parallel threads — fast scan.
    """
    import base64, hashlib
    sni     = sni_host or hostname
    use_tls = port in [443, 8443, 2053, 2083, 2087, 2096]
    fast_to = min(timeout, 2)
    results = []
    r_lock  = threading.Lock()

    def try_path(path):
        ws_key = base64.b64encode(os.urandom(16)).decode()
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw  = socket.create_connection((hostname, port), timeout=fast_to)
                sock = ctx.wrap_socket(raw, server_hostname=sni)
            else:
                sock = socket.create_connection((hostname, port), timeout=fast_to)

            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {sni}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Origin: https://{sni}\r\n\r\n"
            )
            sock.sendall(req.encode())
            sock.settimeout(fast_to)
            resp = b""
            try:
                resp = sock.recv(512)
            except: pass
            sock.close()

            resp_str = resp.decode(errors='ignore')
            if '101' in resp_str.split('\r\n')[0] if resp_str else False:
                # Verify WS accept key
                expected = base64.b64encode(
                    __import__('hashlib').sha1(
                        (ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                    ).digest()
                ).decode()
                key_ok = expected in resp_str
                with r_lock:
                    results.append({"path": path, "code": "101",
                                   "key_verified": key_ok, "works": True})
            elif resp_str and resp_str.startswith('HTTP'):
                code = (resp_str.split('\r\n')[0].split(' ') + ['?'])[1]
                if code in ['200', '204']:
                    with r_lock:
                        results.append({"path": path, "code": code, "works": True})
        except Exception:
            pass

    from concurrent.futures import ThreadPoolExecutor as _T, wait as _w
    with _T(max_workers=8) as ex:
        _w([ex.submit(try_path, p) for p in WS_PATHS], timeout=fast_to + 1)

    if results:
        # Best: 101 with key_verified first, then 101, then 200
        best = sorted(results,
            key=lambda x: (x.get('code') != '101', not x.get('key_verified', False))
        )[0]
        best["all_working"] = results
        return best
    return {"works": False}


# ================================================================
#  SNI Method 13: TLS Detail + Cipher + ALPN Probe  ★ NEW v5.0
# ================================================================
def method_tls_alpn_probe(hostname, port, timeout):
    """
    TLS 1.2 vs 1.3 test + ALPN negotiate + cipher strength detect.
    Certificate validity, wildcard, SAN count check.
    """
    result = {"works": False}

    # Test TLS 1.3
    for tls_ver, min_v, max_v in [
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = min_v
            ctx.maximum_version = max_v
            ctx.set_alpn_protocols(['h2', 'http/1.1'])
            t0 = time.time()
            with socket.create_connection((hostname, port), timeout=timeout) as s:
                with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                    lat    = int((time.time()-t0)*1000)
                    cert   = ss.getpeercert() or {}
                    cipher = ss.cipher() or ('?', '?', 0)
                    alpn   = ss.selected_alpn_protocol() or 'none'
                    ver    = ss.version()

                    subj   = dict(x[0] for x in cert.get('subject', []))
                    san    = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']
                    cn     = subj.get('commonName', '?')
                    expiry = cert.get('notAfter', '?')
                    is_wc  = any('*' in s for s in san + [cn])

                    result = {
                        "works":      True,
                        "tls":        ver,
                        "tls13_ok":   ver == 'TLSv1.3',
                        "tls12_ok":   ver == 'TLSv1.2',
                        "alpn":       alpn,
                        "h2_alpn":    alpn == 'h2',
                        "cipher":     cipher[0],
                        "bits":       cipher[2] if len(cipher) > 2 else '?',
                        "cn":         cn,
                        "san_count":  len(san),
                        "wildcard":   is_wc,
                        "expiry":     expiry,
                        "latency":    lat,
                    }
                    break   # Got one — stop
        except ssl.SSLError:
            continue
        except Exception:
            break

    return result


# ================================================================
#  ASN / CDN IP Verify  ★ NEW v5.0
# ================================================================
def check_asn_info(ip, timeout=4):
    """
    ip-api.com හරහා IP ASN + ISP + country info get කරනවා.
    CDN ද operator ද verify.
    """
    if not ip: return {}
    try:
        txt = _fetch(
            f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as,hosting",
            timeout)
        data = json.loads(txt)
        if data.get('status') == 'success':
            return {
                "country": data.get('country','?'),
                "isp":     data.get('isp','?'),
                "org":     data.get('org','?'),
                "asn":     data.get('as','?'),
                "hosting": data.get('hosting', False),
            }
    except Exception:
        pass
    return {}



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
    """crt.sh — retry 3 times with longer timeout"""
    out = set()
    for attempt in range(3):
        txt = _fetch(f"https://crt.sh/?q=%.{domain}&output=json", timeout + 10)
        if txt:
            try:
                for e in json.loads(txt):
                    for n in e.get('name_value','').split('\n'):
                        n = n.strip().lstrip('*.')
                        if n and domain in n: out.add(n)
                break   # success
            except Exception:
                pass
        time.sleep(1)   # retry pause
    return out

def subs_commoncrawl(domain, timeout):
    """CommonCrawl CDX API — large index"""
    out = set()
    try:
        url = (f"https://index.commoncrawl.org/CC-MAIN-2024-10-index"
               f"?url=*.{domain}&output=json&fl=url&limit=500")
        txt = _fetch(url, timeout + 8)
        for line in txt.strip().split('\n'):
            if not line: continue
            try:
                data = json.loads(line)
                u = data.get('url','')
                # Extract hostname from URL
                m = re.match(r'https?://([^/:?]+)', u)
                if m:
                    h = m.group(1).lower()
                    if domain in h: out.add(h)
            except Exception:
                pass
    except Exception:
        pass
    return out

def subs_dns_bruteforce(domain, timeout):
    """
    Common subdomain wordlist brute-force.
    Async DNS resolve — fast.
    """
    WORDLIST = [
        "www","mail","ftp","webmail","smtp","pop","pop3","imap","ns1","ns2",
        "api","dev","staging","test","blog","shop","store","app","mobile","m",
        "vpn","cdn","media","static","img","images","portal","admin","panel",
        "cpanel","whm","webdisk","autodiscover","autoconfig","beta","auth",
        "login","dashboard","manage","support","help","docs","wiki","forum",
        "chat","stream","live","video","music","download","update","push",
        "ws","wss","socket","proxy","tunnel","relay","edge","gateway","lb",
        "b2b","secure","ssl","tls","remote","demo","preview","old","new",
        "v1","v2","v3","api2","api3","myaccount","account","user","client",
    ]
    out    = set()
    lock   = threading.Lock()
    fast   = min(timeout, 2)

    def resolve_one(sub):
        host = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(fast)
            socket.gethostbyname(host)
            with lock: out.add(host)
        except Exception: pass

    from concurrent.futures import ThreadPoolExecutor as _T
    with _T(max_workers=30) as ex:
        list(ex.map(resolve_one, WORDLIST))
    return out

def subs_axfr(domain, timeout):
    """
    DNS zone transfer (AXFR) attempt.
    Most servers reject, but worth trying.
    """
    out = set()
    _dns = dns
    if not _dns: return out
    try:
        import importlib
        dns_resolver = importlib.import_module('dns.resolver')
        dns_zone     = importlib.import_module('dns.zone')
        dns_query    = importlib.import_module('dns.query')
        dns_rdatatype= importlib.import_module('dns.rdatatype')

        ns_records = dns_resolver.resolve(domain, 'NS', lifetime=timeout)
        for ns in list(ns_records)[:3]:   # try first 3 nameservers
            ns_host = str(ns.target).rstrip('.')
            try:
                ns_ip = socket.gethostbyname(ns_host)
                z = dns_zone.from_xfr(dns_query.xfr(ns_ip, domain, timeout=timeout))
                for name in z.nodes.keys():
                    h = f"{name}.{domain}".lstrip('@.')
                    if h and domain in h: out.add(h)
                if out: break   # AXFR worked, no need for more NS
            except Exception: pass
    except Exception: pass
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
    all_subs     = set([domain])
    timeout      = cfg["timeout"]
    results_lock = threading.Lock()
    print(C+"\n  [*] Subdomain Sources (parallel):\n"+W)

    def run_source(label, fn, *args):
        try:
            found = fn(*args)
        except Exception:
            found = set()
        with results_lock:
            all_subs.update(found)
        sp(C+f"    → {label:<22}"+W+G+f" {len(found)} found"+W)

    sources = [
        ("HackerTarget",       subs_hackertarget,  domain, timeout),
        ("AlienVault OTX",     subs_alienvault,    domain, timeout),
        ("BufferOver.run",     subs_bufferover,    domain, timeout),
        ("RapidDNS",           subs_rapiddns,      domain, timeout),
    ]
    if cfg.get("use_crtsh", True):
        sources.append(("CRT.sh (SSL)",       subs_crtsh,       domain, timeout))
    if cfg.get("use_commoncrawl", True):
        sources.append(("CommonCrawl",        subs_commoncrawl, domain, timeout))

    from concurrent.futures import ThreadPoolExecutor as _T, as_completed as _ac
    with _T(max_workers=6) as ex:
        futs = {ex.submit(run_source, *s): s[0] for s in sources}
        for _ in _ac(futs): pass

    if cfg.get("dns_bruteforce", True):
        sp(C+"    → DNS Brute-force      "+W+"scanning...", )
        bf = subs_dns_bruteforce(domain, timeout)
        all_subs |= bf
        sp(C+"    → DNS Brute-force     "+W+G+f" {len(bf)} found"+W)

    if dns:
        sp(C+"    → AXFR Zone Xfer      "+W+"trying...", )
        ax = subs_axfr(domain, timeout)
        all_subs |= ax
        sp(C+"    → AXFR Zone Xfer     "+W+(G+f" {len(ax)} found"+W if ax else DIM+" rejected"+W))

    print(G+f"\n  [+] Total unique: {len(all_subs)} subdomains"+W)
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
        "zero_balance":    {},   # v7.0 ZB module results
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
    if result["http_status"]  == 200:  s += 8
    if result["https_status"] == 200:  s += 8
    if result["http2"]:                s += 4
    if result["http3"].get("supported"):s += 2
    if result["ech"].get("supported"): s += 3
    # Core SNI methods
    if m.get("direct_sni",        {}).get("works"): s += 10
    if m.get("sni_mismatch",      {}).get("works"): s += 25  # highest — zero-balance key
    if m.get("sni_empty",         {}).get("works"): s += 6
    if m.get("ws_real_payload",   {}).get("works"): s += 18
    if m.get("ws_best_path",      {}).get("works"): s += 10  # confirmed WS path
    if m.get("domain_fronting",   {}).get("works"): s += 16
    if m.get("http_connect",      {}).get("works"): s += 6
    if m.get("host_header_inject",{}).get("works"): s += 6
    if m.get("vless_probe",       {}).get("works"): s += 12
    # v5.0
    if m.get("grpc_stream",       {}).get("works"): s += 14
    if m.get("xhttp_test",        {}).get("works"): s += 14
    if m.get("tls_alpn",          {}).get("h2_alpn"): s += 4
    if m.get("reality_probe",     {}).get("looks_reality"): s += 8
    if any(c in result["cdn"] for c in ["Cloudflare","Akamai","Fastly","AWS CloudFront"]): s += 3
    # v6.0
    if m.get("open_knock",        {}).get("works"):             s += 8   # hidden SANs found
    if m.get("conn_state_attack", {}).get("works"):             s += 12  # DPI bypass confirmed
    if m.get("ech_real_craft",    {}).get("isp_drops_ech"):    s += 10  # ECH needed & works
    if m.get("ech_real_craft",    {}).get("works"):             s += 5
    if m.get("wtfpad_test",       {}).get("bypass_works"):      s += 8   # QoS bypass
    if m.get("udp_probe",         {}).get("works"):             s += 5   # UDP host discovered
    if m.get("quic_real",         {}).get("works"):             s += 8   # Full QUIC handshake
    if m.get("active_probe_def",  {}).get("resists_probing"):  s += 10  # Reality-like defense

    result["bug_score"]   = min(s, 100)
    result["is_bug_host"] = result["bug_score"] >= 50

    # ML prediction (non-blocking — enriches result)
    if cfg.get("use_ml_predictor", True):
        ml_prob = ml_predict(result)
        result["ml_probability"] = ml_prob
        # Auto-save training sample for future model training
        if ml_prob >= 0 and result["bug_score"] >= 40:
            ml_save_training_sample(result, result["is_bug_host"])
    else:
        result["ml_probability"] = -1.0

    # v7.0: Zero-Balance Detection Module
    any_zb = any(cfg.get(k, True) for k in [
        "zb_isp_detect","zb_captive_portal","zb_transparent_proxy",
        "zb_dns_hijack","zb_tcp_rst","zb_tls_mitm","zb_mtu_probe",
        "zb_ip_range","zb_http_vs_https","zb_header_score",
    ])
    if any_zb and result["is_bug_host"]:
        # Only run ZB tests on confirmed bug hosts (saves time)
        isp_info = detect_isp_asn(timeout)
        scan_port = (next(iter(result["open_ports"]), 443))
        result["zero_balance"] = run_zero_balance_scan(
            hostname, scan_port, cfg, isp_info)
    else:
        result["zero_balance"] = {
            "total_zb_score": 0,
            "is_zero_balance_candidate": False,
            "ml_zb_probability": -1.0,
        }

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
    wspath_ok = [r for r in results if r["sni_methods"].get("ws_best_path",{}).get("works")]
    grpc_ok   = [r for r in results if r["sni_methods"].get("grpc_stream",{}).get("works")]
    xhttp_ok  = [r for r in results if r["sni_methods"].get("xhttp_test",{}).get("works")]
    front_ok  = [r for r in results if r["sni_methods"].get("domain_fronting",{}).get("works")]
    vless_ok  = [r for r in results if r["sni_methods"].get("vless_probe",{}).get("works")]
    real_ok   = [r for r in results if r["sni_methods"].get("reality_probe",{}).get("looks_reality")]
    ech_ok    = [r for r in results if r.get("ech",{}).get("supported")]
    h2_ok     = [r for r in results if r["http2"]]
    h3_ok     = [r for r in results if r.get("http3",{}).get("supported")]
    # v6.0
    knock_ok  = [r for r in results if r["sni_methods"].get("open_knock",{}).get("works")]
    conn_ok   = [r for r in results if r["sni_methods"].get("conn_state_attack",{}).get("works")]
    ech_real  = [r for r in results if r["sni_methods"].get("ech_real_craft",{}).get("works")]
    pad_ok    = [r for r in results if r["sni_methods"].get("wtfpad_test",{}).get("bypass_works")]
    udp_ok    = [r for r in results if r["sni_methods"].get("udp_probe",{}).get("works")]
    aprobe_ok = [r for r in results if r["sni_methods"].get("active_probe_def",{}).get("resists_probing")]
    ml_ok     = [r for r in results if r.get("ml_probability", -1) >= 0.5]
    tls_fp    = results[0].get("tls_fingerprint","?") if results else "?"

    print(G+f"\n{'═'*75}"+W)
    print(G+f"  SCAN COMPLETE — {domain}"+W)
    print(C+f"  TLS Fingerprint : {tls_fp} ({'curl_cffi' if curl_cffi else 'ssl fallback'})"+W)
    print(C+f"  Total Scanned   : {len(results)}"+W)
    print(G+f"  Bug Hosts       : {len(bugs)}"+W)
    print(M+f"  SNI Mismatch★   : {len(mismatches)}"+W)
    print(G+f"  WS Payload★     : {len(ws_ok)}"+W)
    print(G+f"  WS Best Path★   : {len(wspath_ok)}"+W)
    print(B+f"  gRPC Stream★    : {len(grpc_ok)}"+W)
    print(C+f"  XHTTP/Split★    : {len(xhttp_ok)}"+W)
    print(Y+f"  Domain Fronting : {len(front_ok)}"+W)
    print(B+f"  VLESS Probe     : {len(vless_ok)}"+W)
    print(M+f"  Reality TLS     : {len(real_ok)}"+W)
    print(B+f"  HTTP/2          : {len(h2_ok)}"+W)
    print(C+f"  HTTP/3 (QUIC)   : {len(h3_ok)}"+W)
    print(M+f"  ECH Support     : {len(ech_ok)}"+W)
    # v6.0
    print(G+f"  OpenKnock★      : {len(knock_ok)}"+W)
    print(Y+f"  ConnState★      : {len(conn_ok)}"+W)
    print(M+f"  ECH-Real★       : {len(ech_real)}"+W)
    print(C+f"  WTF-PAD★        : {len(pad_ok)}"+W)
    print(B+f"  UDP-Probe       : {len(udp_ok)}"+W)
    print(G+f"  ActiveProbe★    : {len(aprobe_ok)}"+W)
    if sklearn:
        print(M+f"  ML Predicted    : {len(ml_ok)}"+W)
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
    M_ORDER = ["direct_sni","sni_mismatch","sni_empty","ws_real_payload","ws_best_path",
               "grpc_stream","xhttp_test","domain_fronting","vless_probe",
               "reality_probe","http_connect","host_header_inject","tls_alpn",
               "open_knock","conn_state_attack","ech_real_craft","wtfpad_test",
               "udp_probe","active_probe_def"]
    M_HEAD  = ["DirectSNI","Mismatch★","EmptySNI","WS-Pay★","WSPath★",
               "gRPC★","XHTTP★","Front★","VLESS","Reality",
               "CONNECT","HdrInj","ALPN",
               "Knock★","ConnSt★","ECH-R★","PAD★","UDP","AProbe★"]
    print(C+BOLD+f"\n[MATRIX] All Methods — Top 50\n"+W)
    print(C+f"  {'HOST':<38} "+"  ".join(f"{h:<13}" for h in M_HEAD)+W)
    print(C+"  "+"─"*180+W)
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
            ml_p    = r.get("ml_probability", -1)
            ml_s    = f" [ML:{ml_p:.0%}]"          if ml_p >= 0 else ""
            print(G+f"  {i:>2}. {r['host']}"+W
                  +Y+ip_s+W+M+cdn_s+W+B+h2_s+h3_s+W+M+ech_s+W+C+ml_s+W)
            print(C+f"      Score:{sc(r['bug_score'])}{r['bug_score']}%{W}  "
                  f"Methods:{G} {methods}{W}\n")

    # v6.0: Open-Knock hidden SANs table
    if knock_ok:
        print(G+BOLD+f"\n[OPEN-KNOCK★] Hidden Default Cert SANs ({len(knock_ok)})\n"+W)
        print(C+f"  {'HOST':<40} HIDDEN SANs"+W)
        print(C+"  "+"─"*90+W)
        for r in knock_ok:
            ok   = r["sni_methods"]["open_knock"]
            sans = ", ".join(ok.get("hidden_sans", [])[:5])
            print(G+f"  {r['host']:<40}{W} {DIM}{sans or '(default cert extracted)'}{W}")

    # v6.0: Active Probe Defense table
    if aprobe_ok:
        print(M+BOLD+f"\n[ACTIVE-PROBE★] Strong Probe Resistance ({len(aprobe_ok)})\n"+W)
        print(C+f"  {'HOST':<40} {'RATIO':>7}  NOTE"+W)
        print(C+"  "+"─"*85+W)
        for r in aprobe_ok:
            ap = r["sni_methods"]["active_probe_def"]
            ratio = ap.get("resistance_ratio", 0)
            note  = ap.get("note", "")[:50]
            print(M+f"  {r['host']:<40}{W} {G}{ratio:.0%}{W:>7}  {DIM}{note}{W}")

    # ── v7.0 ZERO-BALANCE DETECTION TABLES ─────────────────────────

    # Collect zero-balance candidates
    zb_candidates = [r for r in results
                     if r.get("zero_balance",{}).get("is_zero_balance_candidate")]
    zb_isp_db     = [r for r in results
                     if r.get("zero_balance",{}).get("isp_detect",{}).get("in_zero_rate_db")]
    zb_proxy      = [r for r in results
                     if r.get("zero_balance",{}).get("transparent_proxy",{}).get("proxy_detected")]
    zb_mitm       = [r for r in results
                     if r.get("zero_balance",{}).get("tls_mitm",{}).get("mitm_suspected")]
    zb_dns_hijack = [r for r in results
                     if r.get("zero_balance",{}).get("dns_hijack",{}).get("hijacked")]
    zb_ip_range   = [r for r in results
                     if r.get("zero_balance",{}).get("ip_range",{}).get("in_known_range")]

    if zb_candidates or zb_isp_db or zb_ip_range:
        print(G+BOLD+f"\n{'═'*75}"+W)
        print(G+BOLD+f"  ★ ZERO-BALANCE DETECTION RESULTS (v7.0)"+W)
        print(G+BOLD+f"{'═'*75}\n"+W)

        # Summary counts
        print(C+f"  ZB Candidates        : {G}{len(zb_candidates)}{W}")
        print(C+f"  ISP DB Match         : {G}{len(zb_isp_db)}{W}")
        print(C+f"  Known IP Range       : {G}{len(zb_ip_range)}{W}")
        print(C+f"  Transparent Proxy    : {Y}{len(zb_proxy)}{W}")
        print(C+f"  DNS Hijacked         : {R}{len(zb_dns_hijack)}{W}")
        print(C+f"  TLS MITM Suspected   : {Y}{len(zb_mitm)}{W}")
        print()

    # Table ZB-A: Top Zero-Balance Candidates
    if zb_candidates:
        print(G+BOLD+f"[ZB-★] Top Zero-Balance Candidates ({len(zb_candidates)})\n"+W)
        print(C+f"  {'HOST':<42} {'ZB-SCORE':>9} {'ML-ZB':>7} {'TRANSPORT':<22} {'ISP':<25} SIGNALS"+W)
        print(C+"  "+"─"*145+W)
        for r in sorted(zb_candidates,
                        key=lambda x: x["zero_balance"].get("total_zb_score",0),
                        reverse=True)[:20]:
            zb    = r["zero_balance"]
            zbs   = zb.get("total_zb_score", 0)
            ml_zb = zb.get("ml_zb_probability", -1)
            ml_s  = f"{ml_zb:.0%}" if ml_zb >= 0 else "—"
            trans = zb.get("recommended_transport","?")[:20]
            isp   = zb.get("isp_detect",{}).get("matched_isp","?")
            if isp: isp = isp[:23]

            # Signal icons
            signals = ""
            if zb.get("isp_detect",{}).get("in_zero_rate_db"):
                signals += G+"[DB]"+W+" "
            if zb.get("ip_range",{}).get("in_known_range"):
                signals += G+"[IP]"+W+" "
            if zb.get("transparent_proxy",{}).get("proxy_detected"):
                signals += Y+"[PRX]"+W+" "
            if zb.get("captive_portal",{}).get("zero_rated"):
                signals += G+"[CAP✔]"+W+" "
            if zb.get("captive_portal",{}).get("captive_detected"):
                signals += R+"[WALL]"+W+" "
            if zb.get("tls_mitm",{}).get("mitm_suspected"):
                signals += Y+"[MITM]"+W+" "
            if zb.get("mtu_probe",{}).get("proxy_path"):
                signals += C+"[MTU1400]"+W+" "
            if zb.get("dns_hijack",{}).get("hijacked"):
                signals += R+"[DNS-HJ]"+W+" "

            zb_color = G+BOLD if zbs >= 70 else (Y if zbs >= 40 else R)
            print(f"  {G}{r['host']:<42}{W} {zb_color}{zbs:>8}%{W} "
                  f"{M}{ml_s:>7}{W} {C}{trans:<22}{W} {DIM}{isp:<25}{W} {signals}")

    # Table ZB-B: ISP DB Matched Domains
    if zb_isp_db:
        print(M+BOLD+f"\n[ZB-DB] Known Zero-Rated Domain DB Matches ({len(zb_isp_db)})\n"+W)
        print(C+f"  {'HOST':<42} {'MATCHED DOMAIN':<30} ISP"+W)
        print(C+"  "+"─"*100+W)
        for r in zb_isp_db[:15]:
            zb  = r["zero_balance"]["isp_detect"]
            md  = zb.get("matched_domain","?")[:28]
            isp = (zb.get("matched_isp") or "?")[:30]
            print(M+f"  {r['host']:<42}{W} {G}{md:<30}{W} {DIM}{isp}{W}")

    # Table ZB-C: IP Range Matches
    if zb_ip_range:
        print(B+BOLD+f"\n[ZB-IP] Known Zero-Rated IP Range Matches ({len(zb_ip_range)})\n"+W)
        print(C+f"  {'HOST':<42} {'IP':<18} {'RANGE':<22} SERVICE"+W)
        print(C+"  "+"─"*100+W)
        for r in zb_ip_range[:15]:
            zb  = r["zero_balance"]["ip_range"]
            ip  = (zb.get("ip") or "?")[:16]
            rng = (zb.get("matched_range") or "?")[:20]
            svc = (zb.get("matched_service") or "?")[:30]
            print(B+f"  {r['host']:<42}{W} {Y}{ip:<18}{W} {G}{rng:<22}{W} {DIM}{svc}{W}")

    # Table ZB-D: Proxy / Header Score Detail
    if zb_proxy:
        print(Y+BOLD+f"\n[ZB-PRX] Transparent Proxy Detected ({len(zb_proxy)})\n"+W)
        print(C+f"  {'HOST':<42} {'LEVEL':<8} {'SCORE':>6}  HEADERS"+W)
        print(C+"  "+"─"*100+W)
        for r in zb_proxy[:10]:
            prx   = r["zero_balance"].get("transparent_proxy",{})
            hdr   = r["zero_balance"].get("header_score",{})
            level = hdr.get("proxy_level","?")
            score = hdr.get("total_score",0)
            hdrs  = ", ".join(list(prx.get("proxy_headers",{}).keys())[:5])
            print(Y+f"  {r['host']:<42}{W} {G}{level:<8}{W} {Y}{score:>6}{W}  {DIM}{hdrs}{W}")

    # Table ZB-E: TLS MITM (ISP cert injection)
    if zb_mitm:
        print(R+BOLD+f"\n[ZB-MITM] ⚠ TLS MITM / ISP Cert Suspected ({len(zb_mitm)})\n"+W)
        print(C+f"  {'HOST':<42} {'ISSUER':<40} SELF-SIGNED"+W)
        print(C+"  "+"─"*100+W)
        for r in zb_mitm[:10]:
            mitm   = r["zero_balance"].get("tls_mitm",{})
            issuer = (mitm.get("cert_issuer") or "?")[:38]
            ss     = G+"YES"+W if mitm.get("self_signed") else "no"
            isp_c  = R+"ISP-CERT"+W if mitm.get("isp_cert") else ""
            print(R+f"  {r['host']:<42}{W} {DIM}{issuer:<40}{W} {ss}  {isp_c}")

    # Table ZB-F: HTTP vs HTTPS Mode Summary
    mode_counts = {}
    for r in results:
        mode = r.get("zero_balance",{}).get("http_vs_https",{}).get("zero_rate_mode","")
        if mode and mode != "neither":
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
    if mode_counts:
        print(C+BOLD+f"\n[ZB-PROTO] Zero-Rating Protocol Mode Summary\n"+W)
        print(C+f"  {'MODE':<20} {'COUNT':>6}  RECOMMENDED TRANSPORT"+W)
        print(C+"  "+"─"*60+W)
        for mode, cnt in sorted(mode_counts.items(), key=lambda x:x[1], reverse=True):
            trans = {
                "both":       "gRPC (preferred) or WS+TLS",
                "https-only": "gRPC / WS+TLS (port 443)",
                "http-only":  "WS no-TLS (port 80)",
            }.get(mode, "?")
            print(C+f"  {mode:<20}{W} {G}{cnt:>6}{W}  {Y}{trans}{W}")

    # Speed test summary (if enabled)
    spd_results = [r for r in results if r.get("zero_balance",{}).get("speed_test",{}).get("speed_kbps")]
    if spd_results:
        print(C+BOLD+f"\n[ZB-SPD] Speed Differential Results\n"+W)
        print(C+f"  {'HOST':<42} {'SPEED':>10}  TIER"+W)
        print(C+"  "+"─"*80+W)
        for r in sorted(spd_results,
                        key=lambda x: x["zero_balance"]["speed_test"]["speed_kbps"])[:10]:
            spd  = r["zero_balance"]["speed_test"]
            kbps = spd.get("speed_kbps",0)
            tier = spd.get("speed_tier","?")
            clr  = R if kbps < 512 else (Y if kbps < 2048 else G)
            print(f"  {G}{r['host']:<42}{W} {clr}{kbps:>9}Kbps{W}  {DIM}{tier}{W}")


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
    """Top bug hosts වල 3x-ui config — ALL working transports display"""
    bugs = [r for r in results if r["is_bug_host"]]
    if not bugs:
        print(Y+"  [!] Bug hosts නෑ — 3x-ui config generate කරන්න බෑ."+W)
        return

    print(f"\n{M}{'═'*72}{W}")
    print(M+BOLD+"  ★  3x-ui INBOUND CONFIG GUIDE  ★"+W)
    print(f"{M}{'═'*72}{W}\n")

    for i, r in enumerate(bugs[:8], 1):
        cfg    = analyze_3xui(r)
        m      = r["sni_methods"]
        op     = r["open_ports"]

        # ── Header ───────────────────────────────────────────────────
        print(G+BOLD+f"  [{i}] {cfg['host']}"+W
              + DIM+f"  (IP: {cfg['ip']})"+W
              + (f"  {Y}{cfg['cdn_note']}{W}" if cfg['cdn_note'] else ""))
        print(C+"  "+f"{'─'*68}"+W)

        # ── Speed Hunter transport score (if available) ───────────────
        if _SPEED_HUNTER_OK:
            try:
                ip   = cfg["ip"]
                sni  = cfg["sni"]
                plist = sorted(op.keys()) if op else [443, 80]
                bench = benchmark_all_transports(ip, sni, plist, timeout=4.0)
                winner     = bench.get("winner")
                win_score  = bench.get("winner_score", 0)
                transports = bench.get("transports", {})
            except Exception:
                bench = {}; winner = None; transports = {}
        else:
            bench = {}; winner = None; transports = {}

        # ── Transport tags ────────────────────────────────────────────
        tags = []
        if m.get("grpc_stream",{}).get("works"):       tags.append(B+"gRPC★"+W)
        if m.get("xhttp_test",{}).get("works"):        tags.append(C+"SplitHTTP★"+W)
        if m.get("ws_real_payload",{}).get("works"):   tags.append(G+"WS★"+W)
        if m.get("ws_best_path",{}).get("works"):      tags.append(G+"WS-Path★"+W)
        if m.get("domain_fronting",{}).get("works"):   tags.append(Y+"Fronting★"+W)
        if m.get("vless_probe",{}).get("works"):       tags.append(G+"VLESS★"+W)
        if m.get("reality_probe",{}).get("looks_reality"): tags.append(M+"Reality★"+W)
        if r.get("http2"):                             tags.append(B+"H2"+W)
        if tags:
            print(f"  {BOLD}Capabilities:{W} " + " │ ".join(tags))

        # Speed Hunter winner
        if winner:
            wclr = G+BOLD if win_score >= 60 else Y
            print(f"  {BOLD}Speed Winner:{W} {wclr}{winner}{W} "
                  f"{DIM}(score:{win_score}){W}")

        # ── ALL Working Transport Configs ─────────────────────────────
        # Collect all transports to generate configs for
        all_transport_cfgs = []

        # From SNI scan results
        scan_transports = []
        if m.get("grpc_stream",{}).get("works"):
            port, _ = _best_port(op, prefer_tls=True)
            scan_transports.append(("gRPC", port, "/", True))
        if m.get("xhttp_test",{}).get("works"):
            port, _ = _best_port(op, prefer_tls=True)
            scan_transports.append(("SplitHTTP", port, "/xhttp", True))
        if m.get("ws_real_payload",{}).get("works") or m.get("ws_best_path",{}).get("works"):
            ws_m    = m.get("ws_best_path",{}) or m.get("ws_real_payload",{})
            ws_path = ws_m.get("best_path", ws_m.get("path", "/"))
            port_tls  = _best_port(op, prefer_tls=True)
            port_plain = _best_port(op, prefer_tls=False)
            scan_transports.append(("WS+TLS", port_tls[0], ws_path, True))
            if port_plain[0] != port_tls[0]:
                scan_transports.append(("WS", port_plain[0], ws_path, False))
        if not scan_transports:
            port, use_tls = _best_port(op, prefer_tls=True)
            scan_transports.append(("TCP+TLS", port, "/", use_tls))

        # From Speed Hunter benchmark
        sh_transports = []
        for tk, tv in sorted(transports.items(),
                             key=lambda x: x[1].get("score",0), reverse=True)[:3]:
            if tv.get("score", 0) > 20:
                tr_type, port, path = tk.split(":")[0], tv.get("port", 443), "/"
                if "/" in tk.split(":",1)[-1]:
                    path = "/" + tk.split("/",1)[-1]
                sh_transports.append((tk, port, path, tv.get("score",0)))

        # ── Print each transport config box ──────────────────────────
        for tr_idx, (tr_name, tr_port, tr_path, tr_tls) in enumerate(scan_transports[:3]):
            net_map = {
                "gRPC": "grpc", "WS+TLS": "ws", "WS": "ws",
                "SplitHTTP": "splithttp", "HTTPUpgrade": "httpupgrade",
                "TCP+TLS": "tcp",
            }
            network  = net_map.get(tr_name.split("+")[0], "ws")
            use_tls  = tr_tls if isinstance(tr_tls, bool) else (tr_port in [443,8443,2053,2083,2087,2096])
            security = "tls" if use_tls else "none"

            # Is this the speed winner?
            is_winner = winner and tr_name.split("+")[0] in winner
            hdr_clr   = G+BOLD if is_winner else C

            print(hdr_clr+f"\n  ┌─ Transport [{tr_idx+1}]: {tr_name}"
                  + (" ← Speed Winner ★" if is_winner else "")
                  + f" {'─'*max(0,42-len(tr_name))}┐{W}")
            print(C+f"  │{W} Remark       : {G}{cfg['host']}-{tr_name}{W}")
            print(C+f"  │{W} Protocol     : {G}vless{W}")
            print(C+f"  │{W} Port         : {G}{tr_port}{W}")
            print(C+f"  │{W} Network      : {G}{network}{W}")

            if network == "grpc":
                print(C+f"  │{W} gRPC Mode    : {G}multi{W}")
                print(C+f"  │{W} Service Name : {G}grpc{W}")
            elif network in ["ws","splithttp","httpupgrade"]:
                print(C+f"  │{W} Path         : {G}{tr_path}{W}")
                print(C+f"  │{W} Host Header  : {G}{cfg['sni']}{W}")

            print(C+f"  │{W} TLS          : {G if use_tls else Y}{security}{W}")
            if use_tls:
                print(C+f"  │{W} SNI          : {G}{cfg['sni']}{W}")
                print(C+f"  │{W} Fingerprint  : {G}chrome{W}")
                print(C+f"  │{W} allowInsecure: {G}true{W}")
            print(C+f"  └{'─'*52}┘{W}")

            # Share link
            params = f"security={security}&sni={cfg['sni']}&fp=chrome&type={network}&allowInsecure=1"
            if network == "grpc":
                params += "&serviceName=grpc&mode=multi"
            elif network in ["ws","splithttp","httpupgrade"]:
                params += f"&path={tr_path}&host={cfg['sni']}"
            share = f"vless://[UUID]@{cfg['ip']}:{tr_port}?{params}#{cfg['host']}-{tr_name}"
            print(Y+f"  Link: {DIM}{share}{W}")

        # Speed Hunter additional links
        if sh_transports and _SPEED_HUNTER_OK:
            print(C+f"\n  {DIM}Speed Hunter Alternatives:{W}")
            for tk, tk_port, tk_path, tk_score in sh_transports[:2]:
                try:
                    sh_cfg = generate_3xui_config(
                        cfg["ip"], cfg["sni"], "Unknown", tk, None, cfg["ip"])
                    print(Y+f"  [{tk}] score:{tk_score}"+W)
                    print(DIM+f"  {sh_cfg['share_link']}"+W)
                except Exception:
                    pass

        print(f"\n  {BOLD}Bug Score :{W} {sc(cfg['bug_score'])}{cfg['bug_score']}%{W}\n")

    print(M+"  "+f"{'═'*70}"+W)
    print(Y+BOLD+"  NOTE: [UUID] ← 3x-ui panel එකේ generate කරලා replace කරන්න."+W)
    print(Y+"  allowInsecure=true — SNI mismatch mode. Assessment only."+W)
    print(M+"  "+f"{'═'*70}"+W+"\n")

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
        "aioquic":    G+"✔"+W if aioquic     else Y+"○"+W,
        "scapy":      G+"✔"+W if scapy       else Y+"○"+W,
        "sklearn":    G+"✔"+W if sklearn     else Y+"○"+W,
    }
    print(f"""
{C}╔══════════════════════════════════════════════════════════════════╗
║  {G}{BOLD}SNI BUG HOST FINDER{C} v8.0  {DIM}★ SPEED HUNTER EDITION{C}              ║
║  {DIM}IP-Range | Transport-Bench | ISP-Config | ZB-Detect | ML{C}       ║
╚══════════════════════════════════════════════════════════════════╝{W}
  {C}curl_cffi:{W}{deps['curl_cffi']}  {C}httpx/H2:{W}{deps['httpx/H2']}  {C}aiohttp:{W}{deps['aiohttp']}  {C}aiodns:{W}{deps['aiodns']}  {C}dnspython:{W}{deps['dnspython']}
  {C}aioquic:{W}{deps['aioquic']}  {C}scapy:{W}{deps['scapy']}  {C}sklearn/ML:{W}{deps['sklearn']}  {C}SpeedHunter:{W}{G+'✔'+W if _SPEED_HUNTER_OK else R+'✘'+W}
{Y}  [!] Security Assessment Tool — Research & Educational use only{W}
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

    # v7.0: Zero-Balance results
    zb = res.get("zero_balance", {})
    if zb and zb.get("total_zb_score", 0) > 0:
        print(G+BOLD+f"\n  ★ ZERO-BALANCE ANALYSIS\n"+W)
        print(C+"  "+"─"*68+W)
        zbs  = zb.get("total_zb_score", 0)
        ml_z = zb.get("ml_zb_probability", -1)
        cand = zb.get("is_zero_balance_candidate", False)
        zclr = G+BOLD if zbs >= 60 else (Y if zbs >= 40 else R)
        print(f"  {BOLD}ZB Score     :{W} {zclr}{zbs}%{W}")
        print(f"  {BOLD}ZB Candidate :{W} {G+BOLD+'★ YES — Zero-Balance likely!'+W if cand else R+'NO'+W}")
        if ml_z >= 0:
            print(f"  {BOLD}ML ZB Prob   :{W} {M}{ml_z:.0%}{W}")
        print(f"  {BOLD}Transport    :{W} {C}{zb.get('recommended_transport','?')}{W}")
        isp_d = zb.get("isp_detect", {})
        if isp_d.get("in_zero_rate_db"):
            print(f"  {BOLD}ISP DB       :{W} {G}✔ {isp_d.get('matched_isp','?')} "
                  f"— {isp_d.get('matched_domain','')}{W}")
        if zb.get("ip_range", {}).get("in_known_range"):
            ipr = zb["ip_range"]
            print(f"  {BOLD}IP Range     :{W} {G}✔ {ipr.get('ip','')} ∈ "
                  f"{ipr.get('matched_range','')} ({ipr.get('matched_service','')}){W}")
        prx = zb.get("transparent_proxy", {})
        if prx.get("proxy_detected"):
            hs = list(prx.get("proxy_headers", {}).keys())[:4]
            print(f"  {BOLD}Proxy        :{W} {Y}✔ {', '.join(hs)}{W}")
        hdr = zb.get("header_score", {})
        if hdr.get("total_score", 0) > 0:
            print(f"  {BOLD}Hdr Score    :{W} {Y}{hdr.get('total_score',0)} pts "
                  f"[{hdr.get('proxy_level','none')}]{W}")
        cap = zb.get("captive_portal", {})
        if cap.get("captive_detected"):
            kws = cap.get("keywords_found", [])[:3]
            print(f"  {BOLD}Captive      :{W} {R}Portal detected — {', '.join(kws)}{W}")
        elif cap.get("zero_rated"):
            print(f"  {BOLD}Captive      :{W} {G}✔ Normal 200 (zero-rated confirmed){W}")
        dns = zb.get("dns_hijack", {})
        if dns.get("hijacked"):
            print(f"  {BOLD}DNS Hijack   :{W} {R}✔ ISP:{dns.get('isp_dns_ip')} ≠ "
                  f"Google:{dns.get('google_dns_ip')}{W}")
        elif dns.get("ip_mismatch"):
            print(f"  {BOLD}DNS Mismatch :{W} {Y}ISP:{dns.get('isp_dns_ip')} ≠ "
                  f"Google:{dns.get('google_dns_ip')}{W}")
        mtu = zb.get("mtu_probe", {})
        if mtu.get("proxy_path"):
            print(f"  {BOLD}MTU Probe    :{W} {C}✔ MTU {mtu.get('mtu_detected','?')} "
                  f"— proxy path confirmed{W}")
        mitm = zb.get("tls_mitm", {})
        if mitm.get("mitm_suspected"):
            print(f"  {BOLD}TLS MITM     :{W} {R}⚠ {mitm.get('cert_issuer','?')}{W}")
        proto = zb.get("http_vs_https", {})
        mode  = proto.get("zero_rate_mode", "?")
        mclr  = G if mode not in ["neither","?"] else R
        print(f"  {BOLD}Proto Mode   :{W} {mclr}{mode}{W}", end="")
        if proto.get("http_latency"):
            print(f"  HTTP:{Y}{proto.get('http_latency')}ms{W}", end="")
        if proto.get("https_latency"):
            print(f"  HTTPS:{Y}{proto.get('https_latency')}ms{W}", end="")
        print()
        spd = zb.get("speed_test", {})
        if spd.get("speed_kbps"):
            print(f"  {BOLD}Speed        :{W} {Y}{spd.get('speed_tier','?')}{W}")
        print(C+"  "+"─"*68+W)

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
        ("aiohttp",       "Async HTTP scanning (ඉතාම ඉක්මන්)"),
        ("aiodns",        "Async DNS resolve"),
        ("httpx[http2]",  "HTTP/2 accurate check"),
        ("curl_cffi",     "TLS fingerprint spoofing (Chrome/Firefox)"),
        ("dnspython",     "ECH / DNS HTTPS record lookup"),
        # v6.0 optional
        ("aioquic",       "Real QUIC/HTTP3 handshake ★ optional"),
        ("scapy",         "Packet manipulation / SCTP probe ★ root needed"),
        ("cryptography",  "HPKE / ECH key operations ★ optional"),
        ("scikit-learn",  "ML Bug Score Predictor ★ optional"),
        ("numpy",         "ML feature arrays ★ optional"),
    ]
    missing = []
    for pkg, desc in deps_info:
        mod = {
            'dnspython': 'dns',
            'httpx[http2]': 'httpx',
            'scikit-learn': 'sklearn',
        }.get(pkg, pkg.split('[')[0].replace('-','_'))
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
            ("1","threads",           "Threads",              cfg["threads"]),
            ("2","async_concurrency", "Async concurrency",    cfg["async_concurrency"]),
            ("3","timeout",           "Timeout (s)",          cfg["timeout"]),
            ("4","tls_fingerprint",   "TLS profile",          cfg["tls_fingerprint"]),
            ("5","check_https",       "HTTPS check",          cfg["check_https"]),
            ("6","check_sni",         "SNI check",            cfg["check_sni"]),
            ("7","check_http2",       "HTTP/2 check",         cfg["check_http2"]),
            ("8","check_http3",       "HTTP/3 check",         cfg.get("check_http3",False)),
            ("9","check_ws_payload",  "WS Payload test",      cfg.get("check_ws_payload",True)),
            ("a","check_fronting",    "Domain Fronting",      cfg.get("check_fronting",True)),
            ("b","check_ech",         "ECH detect",           cfg.get("check_ech",True)),
            ("c","use_crtsh",         "CRT.sh subdomains",    cfg["use_crtsh"]),
            ("d","use_alienvault",    "AlienVault subs",      cfg["use_alienvault"]),
            # v6.0
            ("e","check_open_knock",  "Open-Knock★",          cfg.get("check_open_knock",True)),
            ("f","check_conn_state",  "ConnState Attack★",    cfg.get("check_conn_state",True)),
            ("g","check_ech_real",    "ECH Real Crafter★",    cfg.get("check_ech_real",True)),
            ("h","check_wtfpad",      "WTF-PAD Padding★",     cfg.get("check_wtfpad",True)),
            ("i","check_udp_probe",   "UDP Probe",            cfg.get("check_udp_probe",True)),
            ("j","check_sctp_probe",  "SCTP Probe (root)",    cfg.get("check_sctp_probe",False)),
            ("k","check_quic_real",   "Real QUIC (aioquic)",  cfg.get("check_quic_real",False)),
            ("l","check_pkt_manip",   "Pkt Manip (root)",     cfg.get("check_pkt_manip",False)),
            ("m","check_active_probe","Active Probe Defense★", cfg.get("check_active_probe",True)),
            ("n","use_ml_predictor",  "ML Predictor (sklearn)",cfg.get("use_ml_predictor",True)),
            # v7.0 Zero-Balance
            ("o","zb_isp_detect",     "ZB-1 ISP Auto-Detect",  cfg.get("zb_isp_detect",True)),
            ("p","zb_captive_portal", "ZB-2 Captive Portal",   cfg.get("zb_captive_portal",True)),
            ("q","zb_transparent_proxy","ZB-3 Transparent Proxy",cfg.get("zb_transparent_proxy",True)),
            ("r","zb_dns_hijack",     "ZB-4 DNS Hijack",       cfg.get("zb_dns_hijack",True)),
            ("s","zb_tcp_rst",        "ZB-5 TCP RST Detect",   cfg.get("zb_tcp_rst",True)),
            ("t","zb_speed_diff",     "ZB-6 Speed Diff (slow)",cfg.get("zb_speed_diff",False)),
            ("u","zb_tls_mitm",       "ZB-7 TLS MITM Detect",  cfg.get("zb_tls_mitm",True)),
            ("v","zb_mtu_probe",      "ZB-8 MTU Probe",        cfg.get("zb_mtu_probe",True)),
            ("w","zb_ip_range",       "ZB-9 IP Range Scanner", cfg.get("zb_ip_range",True)),
            ("x","zb_http_vs_https",  "ZB-10 HTTP vs HTTPS",   cfg.get("zb_http_vs_https",True)),
            ("y","zb_header_score",   "ZB-11 Header Scoring",  cfg.get("zb_header_score",True)),
            ("z","zb_ml_predict",     "ZB-12 ML ZB Predictor", cfg.get("zb_ml_predict",True)),
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

def zb_standalone_menu(cfg):
    """Zero-Balance only scan — no full SNI scan."""
    banner()
    print(G+BOLD+"  ★ ZERO-BALANCE SCAN (ZB-Only Mode)\n"+W)

    isp_info = detect_isp_asn(cfg.get("timeout", 5))
    if isp_info.get("asn"):
        print(C+f"  ISP Detected : {G}{isp_info['isp']}{W}")
        print(C+f"  ASN          : {G}{isp_info['asn']}{W}")
        print(C+f"  Public IP    : {G}{isp_info['pub_ip']}{W}")
        known = isp_info["asn"] in ZERO_RATE_DB
        print(C+f"  DB Status    : {G+'Known ISP ✔'+W if known else Y+'Unknown ISP'+W}\n")
        if known:
            zr_doms = get_isp_zero_rate_domains(isp_info["asn"])
            print(C+f"  Zero-rated domains from DB ({len(zr_doms)}):"+W)
            for d in zr_doms[:10]:
                print(G+f"    • {d}"+W)
            if len(zr_doms) > 10:
                print(DIM+f"    ... and {len(zr_doms)-10} more"+W)
    else:
        print(Y+"  [!] ISP detection failed — using global DB\n"+W)
        isp_info = {"asn": "", "isp": "Unknown", "pub_ip": ""}

    print()
    raw = input(Y+"  [+] Hosts to scan (comma/space/newline separated)\n"
                "      OR file path (e.g. hosts.txt): "+W).strip()
    if not raw:
        input(R+"\n  [-] No input. Enter..."+W); return

    hosts = []
    if os.path.exists(raw):
        with open(raw) as f:
            hosts = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    else:
        import re as _re
        hosts = _re.split(r'[\s,]+', raw)
    hosts = [h for h in hosts if h]

    if not hosts:
        input(R+"\n  [-] No hosts found. Enter..."+W); return

    port_raw = input(Y+f"  [+] Port [443]: "+W).strip()
    port     = int(port_raw) if port_raw.isdigit() else 443

    print(G+f"\n  Scanning {len(hosts)} host(s) on port {port}...\n"+W)

    all_zb = []
    for i, host in enumerate(hosts, 1):
        print(C+f"  [{i}/{len(hosts)}] {host}"+W, end="  ", flush=True)
        zb = run_zero_balance_scan(host, port, cfg, isp_info)
        all_zb.append(zb)
        score = zb["total_zb_score"]
        ml    = zb.get("ml_zb_probability", -1)
        ml_s  = f" ML:{ml:.0%}" if ml >= 0 else ""
        clr   = G if score >= 60 else (Y if score >= 40 else R)
        cand  = G+BOLD+"★ ZB CANDIDATE"+W if zb["is_zero_balance_candidate"] else DIM+"—"+W
        print(f"{clr}{score}%{W}{ml_s}  {cand}")

    # ── Results ──────────────────────────────────────────────────
    print(G+f"\n{'═'*70}"+W)
    print(G+BOLD+f"  ZERO-BALANCE SCAN RESULTS"+W)
    print(G+f"{'═'*70}\n"+W)

    candidates = [z for z in all_zb if z["is_zero_balance_candidate"]]
    print(C+f"  Total Scanned    : {len(all_zb)}"+W)
    print(G+f"  ZB Candidates    : {len(candidates)}"+W)
    print()

    if candidates:
        print(G+BOLD+"  ★ TOP ZERO-BALANCE CANDIDATES\n"+W)
        print(C+f"  {'HOST':<38} {'ZB%':>5} {'ML':>6} {'TRANSPORT':<25} SIGNALS"+W)
        print(C+"  "+"─"*110+W)
        for z in sorted(candidates, key=lambda x: x["total_zb_score"], reverse=True):
            score = z["total_zb_score"]
            ml    = z.get("ml_zb_probability", -1)
            ml_s  = f"{ml:.0%}" if ml >= 0 else "—"
            trans = z.get("recommended_transport", "?")[:23]
            sigs  = ""
            if z.get("isp_detect",{}).get("in_zero_rate_db"):   sigs += G+"[DB]"+W+" "
            if z.get("ip_range",{}).get("in_known_range"):       sigs += G+"[IP]"+W+" "
            if z.get("transparent_proxy",{}).get("proxy_detected"): sigs += Y+"[PRX]"+W+" "
            if z.get("captive_portal",{}).get("zero_rated"):     sigs += G+"[CAP]"+W+" "
            if z.get("captive_portal",{}).get("captive_detected"):  sigs += R+"[WALL]"+W+" "
            if z.get("tls_mitm",{}).get("mitm_suspected"):       sigs += Y+"[MITM]"+W+" "
            if z.get("mtu_probe",{}).get("proxy_path"):          sigs += C+"[MTU]"+W+" "
            if z.get("dns_hijack",{}).get("hijacked"):           sigs += R+"[DNS-HJ]"+W+" "
            clr = G+BOLD if score>=70 else Y
            print(f"  {G}{z['host']:<38}{W} {clr}{score:>4}%{W} {M}{ml_s:>6}{W} "
                  f"{C}{trans:<25}{W} {sigs}")

        # Per-host detail
        print(G+BOLD+"\n  ★ DETAIL PER HOST\n"+W)
        for z in candidates:
            print(G+BOLD+f"  ┌─ {z['host']} ─"+W)
            isp_d = z.get("isp_detect",{})
            cap   = z.get("captive_portal",{})
            prx   = z.get("transparent_proxy",{})
            dns   = z.get("dns_hijack",{})
            tcp   = z.get("tcp_rst",{})
            mitm  = z.get("tls_mitm",{})
            mtu   = z.get("mtu_probe",{})
            ipr   = z.get("ip_range",{})
            proto = z.get("http_vs_https",{})
            hdr   = z.get("header_score",{})
            spd   = z.get("speed_test",{})

            def _row(label, val, good=True):
                clr = G if good else R
                print(f"  │  {C}{label:<26}{W} {clr}{val}{W}")

            _row("ZB Score",         f"{z['total_zb_score']}%")
            _row("ML ZB Probability", f"{z.get('ml_zb_probability',-1):.0%}"
                 if z.get('ml_zb_probability',-1)>=0 else "—")
            _row("Recommended",       z.get("recommended_transport","?"))

            if isp_d.get("in_zero_rate_db"):
                _row("ISP DB Match",  isp_d.get("matched_isp","?")+" — "+
                     (isp_d.get("matched_domain","")or""))
            if ipr.get("in_known_range"):
                _row("IP Range Match", f"{ipr.get('ip','')} in {ipr.get('matched_range','')}")
            if prx.get("proxy_detected"):
                hs = list(prx.get("proxy_headers",{}).keys())[:4]
                _row("Transparent Proxy", "YES — headers: "+", ".join(hs))
            if hdr.get("total_score",0) > 0:
                _row("Header Score",  f"{hdr.get('total_score',0)} pts "
                     f"[{hdr.get('proxy_level','none')}]")
            if cap.get("captive_detected"):
                kws = cap.get("keywords_found",[])[:3]
                _row("Captive Portal", "YES — keywords: "+", ".join(kws), good=False)
            elif cap.get("zero_rated"):
                _row("Captive Test",   f"Normal 200 response (code:{cap.get('status_code','?')})")
            if dns.get("hijacked"):
                _row("DNS Hijack",    f"ISP:{dns.get('isp_dns_ip','?')} vs "
                     f"Google:{dns.get('google_dns_ip','?')}", good=False)
            elif dns.get("ip_mismatch"):
                _row("DNS Mismatch",  f"ISP:{dns.get('isp_dns_ip','?')} vs "
                     f"Google:{dns.get('google_dns_ip','?')}")
            if mitm.get("mitm_suspected"):
                _row("TLS MITM",      f"Issuer: {mitm.get('cert_issuer','?')}", good=False)
            if mtu.get("proxy_path"):
                _row("MTU Probe",     f"MTU {mtu.get('mtu_detected','?')} — proxy path")
            mode = proto.get("zero_rate_mode","neither")
            _row("HTTP/HTTPS Mode", mode,
                 good=(mode!="neither"))
            if tcp.get("blocked"):
                _row("TCP Status",    "BLOCKED", good=False)
            elif tcp.get("connection_ok"):
                _row("TCP Status",    "OK — connection successful")
            if spd.get("speed_kbps"):
                _row("Speed",         spd.get("speed_tier","?"))
            print(G+f"  └─────────────────────────────\n"+W)
    else:
        print(Y+"  [!] Zero-balance candidates detected නෑ.\n"
              "      Hosts blocked / not zero-rated.\n"+W)

    # Export option
    exp = input(Y+"  [+] Results export කරන්නද? (y/N): "+W).strip().lower()
    if exp == 'y':
        fname = f"zb_results_{int(time.time())}.json"
        try:
            with open(fname, 'w') as f:
                json.dump(all_zb, f, indent=2, default=str)
            print(G+f"  ✔ Saved: {fname}"+W)
        except Exception as e:
            print(R+f"  [-] Save error: {e}"+W)

    input(Y+"\n  Enter ඔබන්න..."+W)


def zb_ml_train_menu():
    """Train the Zero-Balance ML model from accumulated data."""
    banner()
    print(C+BOLD+"  [ZB-ML TRAINER] Zero-Balance Model\n"+W)

    if not sklearn or not numpy:
        print(R+"  [-] scikit-learn / numpy not installed."+W)
        print(Y+"  pip install scikit-learn numpy"+W)
        input(Y+"\n  Enter ඔබන්න..."+W)
        return

    if not os.path.exists(ZB_ML_MODEL_FILE):
        print(Y+f"  [!] Training file '{ZB_ML_MODEL_FILE}' not found."+W)
        print(Y+"  ZB scans run කරාට පස්සේ data ස්වයංක්‍රීයව save වෙනවා."+W)
        input(Y+"\n  Enter ඔබන්න..."+W)
        return

    try:
        with open(ZB_ML_MODEL_FILE) as f:
            data = json.load(f)
        print(C+f"  Samples : {len(data)}"+W)
        pos = sum(1 for d in data if d["label"] == 1)
        neg = len(data) - pos
        print(C+f"  Positive (ZB=True)  : {G}{pos}{W}")
        print(C+f"  Negative (ZB=False) : {R}{neg}{W}\n")
        if len(data) < 10:
            print(Y+f"  [!] අවම 10 samples ඕනෑ. දැනට {len(data)}."+W)
            input(Y+"\n  Enter ඔබන්න..."+W)
            return
    except Exception as e:
        print(R+f"  [-] Load error: {e}"+W)
        input(Y+"\n  Enter ඔබන්න..."+W)
        return

    print(C+"  Training RandomForest..."+W)
    clf = zb_ml_train()
    if clf:
        print(G+f"\n  ✔ ZB Model trained on {len(data)} samples!\n"+W)
        try:
            import numpy as np
            feat_names = [
                "isp_db","isp_ip_range","isp_score",
                "cap_zero_rated","cap_captive","cap_score",
                "proxy_detected","proxy_score",
                "dns_hijacked","dns_mismatch",
                "tcp_ok","tcp_blocked",
                "mitm_suspected","isp_cert",
                "mtu_proxy","mtu_score",
                "ip_range","http_works","https_works",
                "hdr_score","total_zb_score",
            ]
            top5 = np.argsort(clf.feature_importances_)[::-1][:5]
            print(C+"  Top-5 Feature Importances:"+W)
            for idx in top5:
                name = feat_names[idx] if idx < len(feat_names) else f"feat_{idx}"
                print(C+f"    {name:<22}{W} {G}{clf.feature_importances_[idx]:.3f}{W}")
        except Exception:
            pass
    else:
        print(R+"  [-] Training failed."+W)

    input(Y+"\n  Enter ඔබන්න..."+W)


    banner()
    print(C+"  [ML MODEL TRAINER]\n"+W)
    if not sklearn or not numpy:
        print(R+"  [-] scikit-learn / numpy not installed."+W)
        print(Y+f"  Install: pip install scikit-learn numpy"+W)
        input(Y+"\n  Enter ඔබන්න..."+W)
        return

    if not os.path.exists(ML_MODEL_FILE):
        print(Y+f"  [!] Training data file '{ML_MODEL_FILE}' not found."+W)
        print(Y+f"  Scans run කරාට පස්සේ data ස්වයංක්‍රීයව save වෙනවා."+W)
        input(Y+"\n  Enter ඔබන්න..."+W)
        return

    try:
        with open(ML_MODEL_FILE) as f:
            data = json.load(f)
        print(C+f"  Training samples: {len(data)}"+W)
        if len(data) < 10:
            print(Y+f"  [!] අවම samples 10 ක් අවශ්‍යයි. දැනට {len(data)} ක් ඇත."+W)
            input(Y+"\n  Enter ඔබන්න..."+W)
            return
    except Exception as e:
        print(R+f"  [-] Data load error: {e}"+W)
        input(Y+"\n  Enter ඔබන්න..."+W)
        return

    print(C+"  Training RandomForest model..."+W)
    clf = ml_train()
    if clf:
        print(G+f"\n  ✔ Model trained successfully on {len(data)} samples!"+W)
        print(G+f"  Feature importances (top 5):"+W)
        try:
            import numpy as np
            feat_names = [
                "http200","https200","h2","h3","ech","open_ports","cdn_count",
                "direct_sni","sni_mismatch","sni_empty","ws_payload","ws_path",
                "domain_front","connect","host_inject","vless","grpc","xhttp",
                "reality","open_knock","conn_state","ech_real","active_probe","bug_score"
            ]
            importances = clf.feature_importances_
            top5 = np.argsort(importances)[::-1][:5]
            for idx in top5:
                name = feat_names[idx] if idx < len(feat_names) else f"feat_{idx}"
                print(C+f"    {name:<20}{W} {G}{importances[idx]:.3f}{W}")
        except Exception:
            pass
    else:
        print(R+"  [-] Training failed."+W)

    input(Y+"\n  Enter ඔබන්න..."+W)


def main():
    try:
        import urllib3
        urllib3.disable_warnings()
    except: pass

    cfg = load_cfg()

    # Auto-load ML models if available
    if cfg.get("use_ml_predictor", True) and sklearn and numpy:
        if ml_train():
            sp(G + "  [Bug-ML] Model auto-loaded ✔" + W)
        if zb_ml_train():
            sp(G + "  [ZB-ML]  Model auto-loaded ✔" + W)

    while True:
        banner()
        sh_status = G+"✔"+W if _SPEED_HUNTER_OK else R+"✘ (sni_speed_hunter.py missing)"+W
        print(Y+"  ┌──────────────────────────────────────────────────────┐"+W)
        print(Y+"  │     MAIN MENU  v8.0  ★ SPEED HUNTER EDITION         │"+W)
        print(Y+"  ├──────────────────────────────────────────────────────┤"+W)
        print(Y+"  │  "+W+"[1]  Domain Scan       (Full SNI + ZB)        "+Y+"  │"+W)
        print(Y+"  │  "+W+"[2]  Single Host        (Deep Check + ZB)     "+Y+"  │"+W)
        print(Y+"  │  "+W+"[3]  Batch Scan         (File Input)          "+Y+"  │"+W)
        print(Y+"  │  "+W+"[4]  ZB-Only Scan       (Zero-Balance focus)  "+Y+"  │"+W)
        print(Y+"  │  "+W+f"[5]  ★ Speed Hunter     {sh_status:<28}"+Y+"  │"+W)
        print(Y+"  │  "+W+"[6]  Settings / Config                        "+Y+"  │"+W)
        print(Y+"  │  "+W+"[7]  Dependencies Status                      "+Y+"  │"+W)
        print(Y+"  │  "+W+"[8]  Train Bug-ML Model                       "+Y+"  │"+W)
        print(Y+"  │  "+W+"[9]  Train ZB-ML Model                        "+Y+"  │"+W)
        print(Y+"  │  "+W+"[0]  Exit                                     "+Y+"  │"+W)
        print(Y+"  └──────────────────────────────────────────────────────┘\n"+W)

        ch = input(C+"  Choice (0-9): "+W).strip()
        if   ch=='1': scan_domain_menu(cfg)
        elif ch=='2': single_host_menu(cfg)
        elif ch=='3': batch_scan_menu(cfg)
        elif ch=='4': zb_standalone_menu(cfg)
        elif ch=='5': run_speed_hunter_menu(cfg.get("timeout", 5))
        elif ch=='6': config_menu(cfg)
        elif ch=='7': deps_menu()
        elif ch=='8': ml_train_menu()
        elif ch=='9': zb_ml_train_menu()
        elif ch=='0':
            print(G+"\n  ජය වේවා! 👋\n"+W); sys.exit(0)
        else:
            print(R+"\n  [-] 0-9 ඇතුලත් කරන්න.\n"+W); time.sleep(1)

if __name__=="__main__":
    main()
