#!/usr/bin/env python3
# ================================================================
#   PRO SNI BUG HOST FINDER v3.0
#   Features: Multi-thread | SNI Method Detection | Port Scan
#             CDN Detect | Cipher Suite | HTTP/2 | Batch Scan
#             Config File | 3 Subdomain Sources | Latency Measure
#   Usage: python3 sni_bug_finder.py
# ================================================================

import requests, socket, ssl, os, sys, time, json, threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Colors ───────────────────────────────────────────────────────
G    = '\033[92m'
R    = '\033[91m'
C    = '\033[96m'
Y    = '\033[93m'
B    = '\033[94m'
M    = '\033[95m'
W    = '\033[0m'
BOLD = '\033[1m'
DIM  = '\033[2m'

print_lock = threading.Lock()
def sp(text):
    with print_lock:
        print(text)

# ── Config ────────────────────────────────────────────────────────
CONFIG_FILE = "sni_config.json"
DEFAULT_CONFIG = {
    "threads":        20,
    "timeout":        4,
    "check_https":    True,
    "check_sni":      True,
    "check_ports":    True,
    "check_http2":    True,
    "use_crtsh":      True,
    "use_alienvault": True,
    "ports": [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096],
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36",
        "curl/7.88.1",
        "python-requests/2.28.0",
        "okhttp/4.9.3"
    ]
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return {**DEFAULT_CONFIG, **json.load(f)}
        except:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)
    print(G + f"[+] Config saved → {CONFIG_FILE}" + W)

# ── CDN Signatures ────────────────────────────────────────────────
CDN_SIGNATURES = {
    "Cloudflare":     ["cloudflare", "cf-ray", "cf-cache-status"],
    "Akamai":         ["akamai", "x-check-cacheable", "x-akamai"],
    "Fastly":         ["fastly", "x-fastly", "x-served-by"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "Google CDN":     ["gws", "x-google", "x-goog"],
    "Azure CDN":      ["x-azure", "x-msedge-ref"],
    "Sucuri":         ["sucuri", "x-sucuri-id"],
    "Varnish":        ["varnish", "x-varnish"],
    "Nginx":          ["nginx"],
    "Apache":         ["apache"],
    "LiteSpeed":      ["litespeed"],
}

METHOD_LABELS = {
    "direct_sni":         "Direct-SNI",
    "sni_mismatch":       "SNI-Mismatch",
    "sni_empty":          "Empty-SNI",
    "http_upgrade":       "WS-Upgrade",
    "http_connect":       "CONNECT",
    "host_header_inject": "HostInject",
}

# ================================================================
#  UI Helpers
# ================================================================
def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    clear()
    print(f"""
{C}╔══════════════════════════════════════════════════════════╗
║  {G}{BOLD}SNI BUG HOST FINDER{C} v3.0                               ║
║  {DIM}Multi-Thread | SNI Methods | Port Scan | CDN Detect{C}     ║
╚══════════════════════════════════════════════════════════╝{W}
{Y}  [!] Educational & Research use only{W}
""")

def progress_bar(done, total, label=""):
    if total == 0: return
    pct  = done / total
    fill = int(40 * pct)
    bar  = G + "█" * fill + DIM + "░" * (40 - fill) + W
    with print_lock:
        sys.stdout.write(f"\r  {C}{label}{W} [{bar}] {Y}{done}/{total}{W}  ")
        sys.stdout.flush()

def score_color(s):
    if s >= 70: return G + BOLD
    if s >= 40: return Y
    return R

def get_ua(cfg):
    import random
    return random.choice(cfg.get("user_agents", DEFAULT_CONFIG["user_agents"]))

# ================================================================
#  Subdomain Discovery  (3 sources)
# ================================================================
def subs_hackertarget(domain, timeout):
    out = set()
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}",
                         timeout=timeout)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split('\n'):
                if ',' in line:
                    s = line.split(',')[0].strip()
                    if s: out.add(s)
    except: pass
    return out

def subs_crtsh(domain, timeout):
    out = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         timeout=timeout + 5,
                         headers={"User-Agent": "SNI-BugFinder/3.0"})
        if r.status_code == 200:
            for entry in r.json():
                for name in entry.get('name_value', '').split('\n'):
                    name = name.strip().lstrip('*.')
                    if name and domain in name:
                        out.add(name)
    except: pass
    return out

def subs_alienvault(domain, timeout):
    out = set()
    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
            timeout=timeout,
            headers={"User-Agent": "SNI-BugFinder/3.0"})
        if r.status_code == 200:
            for rec in r.json().get('passive_dns', []):
                h = rec.get('hostname', '')
                if h and domain in h:
                    out.add(h)
    except: pass
    return out

def collect_subdomains(domain, cfg):
    all_subs = set()
    timeout  = cfg["timeout"]
    print(C + "\n  [*] Subdomain Sources:\n" + W)

    print(C + "    → HackerTarget     ..." + W, end='', flush=True)
    ht = subs_hackertarget(domain, timeout)
    all_subs |= ht
    print(G + f" {len(ht)} found" + W)

    if cfg["use_crtsh"]:
        print(C + "    → CRT.sh (SSL)     ..." + W, end='', flush=True)
        crt = subs_crtsh(domain, timeout)
        all_subs |= crt
        print(G + f" {len(crt)} found" + W)

    if cfg["use_alienvault"]:
        print(C + "    → AlienVault OTX   ..." + W, end='', flush=True)
        av = subs_alienvault(domain, timeout)
        all_subs |= av
        print(G + f" {len(av)} found" + W)

    return sorted(all_subs)

# ================================================================
#  Port Scanner
# ================================================================
def scan_ports(hostname, ports, timeout):
    open_ports = {}
    for port in ports:
        try:
            t0   = time.time()
            sock = socket.create_connection((hostname, port), timeout=timeout)
            latency_ms = int((time.time() - t0) * 1000)
            sock.close()
            open_ports[port] = latency_ms
        except: pass
    return open_ports

# ================================================================
#  SNI / SSL Method Checks
# ================================================================
def method_direct_sni(hostname, port, timeout):
    """Normal TLS — hostname ලෙසම SNI set"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_OPTIONAL
        t0 = time.time()
        with socket.create_connection((hostname, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                lat  = int((time.time() - t0) * 1000)
                cert = ss.getpeercert() or {}
                subj = dict(x[0] for x in cert.get('subject', []))
                san  = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']
                cip  = ss.cipher()
                return {
                    "works":   True,
                    "tls":     ss.version(),
                    "cn":      subj.get('commonName', '?'),
                    "san":     san[:4],
                    "expiry":  cert.get('notAfter', '?'),
                    "cipher":  cip[0] if cip else '?',
                    "bits":    cip[2] if cip and len(cip) > 2 else '?',
                    "latency": lat,
                }
    except: pass
    return {"works": False}

def method_sni_mismatch(real_host, sni_host, port, timeout):
    """
    SNI Mismatch — real_host ට TCP connect වෙලා
    TLS SNI field එකේ sni_host දානවා.
    Bug hosting core method — certificate mismatch ලෙස verify නොකර
    server respond කරනවා නම් bug host!
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE   # mismatch allow
        t0 = time.time()
        with socket.create_connection((real_host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=sni_host) as ss:
                lat  = int((time.time() - t0) * 1000)
                cert = ss.getpeercert(binary_form=False) or {}
                subj = dict(x[0] for x in cert.get('subject', [])) if cert else {}
                return {
                    "works":   True,
                    "tls":     ss.version(),
                    "cn":      subj.get('commonName', '?'),
                    "latency": lat,
                }
    except: pass
    return {"works": False}

def method_sni_empty(hostname, port, timeout):
    """Empty SNI — SNI field නැතිව TLS handshake"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        t0 = time.time()
        with socket.create_connection((hostname, port), timeout=timeout) as s:
            # server_hostname=None → SNI extension send නොකරයි
            with ctx.wrap_socket(s, server_hostname=None) as ss:
                lat = int((time.time() - t0) * 1000)
                return {"works": True, "tls": ss.version(), "latency": lat}
    except: pass
    return {"works": False}

def method_http_upgrade(hostname, port, timeout):
    """HTTP → WebSocket Upgrade — 101 response check"""
    try:
        t0 = time.time()
        s  = socket.create_connection((hostname, port), timeout=timeout)
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode())
        resp    = s.recv(512).decode(errors='ignore')
        latency = int((time.time() - t0) * 1000)
        s.close()
        code = resp.split(' ')[1] if len(resp.split(' ')) > 1 else ''
        if code in ['101', '200']:
            return {"works": True, "code": code, "latency": latency}
    except: pass
    return {"works": False}

def method_http_connect(hostname, port, timeout):
    """HTTP CONNECT tunnel probe — proxy capability check"""
    try:
        t0  = time.time()
        s   = socket.create_connection((hostname, port), timeout=timeout)
        req = f"CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}\r\n\r\n"
        s.sendall(req.encode())
        resp    = s.recv(256).decode(errors='ignore')
        latency = int((time.time() - t0) * 1000)
        s.close()
        if "200" in resp:
            return {"works": True, "latency": latency}
    except: pass
    return {"works": False}

def method_host_inject(real_host, port, fake_host, timeout):
    """Host Header Injection — actual server ට fake Host: header"""
    try:
        t0  = time.time()
        s   = socket.create_connection((real_host, port), timeout=timeout)
        req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {fake_host}\r\n"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req.encode())
        resp    = s.recv(512).decode(errors='ignore')
        latency = int((time.time() - t0) * 1000)
        s.close()
        parts = resp.split('\r\n')[0].split(' ') if resp else []
        code  = parts[1] if len(parts) > 1 else ''
        if code in ['200', '301', '302', '307', '308']:
            return {"works": True, "code": code, "latency": latency}
    except: pass
    return {"works": False}

def check_http2(hostname, timeout):
    """ALPN negotiation — HTTP/2 support check"""
    try:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2', 'http/1.1'])
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=hostname) as ss:
                return ss.selected_alpn_protocol() == 'h2'
    except: pass
    return False

# ================================================================
#  All SNI Methods in one call
# ================================================================
def detect_all_methods(hostname, open_ports, timeout, bug_sni):
    methods = {}
    has_443 = 443 in open_ports
    has_80  = 80  in open_ports

    # 1. Direct SNI
    methods["direct_sni"] = method_direct_sni(hostname, 443, timeout) \
        if has_443 else {"works": False}

    # 2. SNI Mismatch  ← Bug hosting core method
    methods["sni_mismatch"] = method_sni_mismatch(hostname, bug_sni, 443, timeout) \
        if has_443 else {"works": False}

    # 3. Empty SNI
    methods["sni_empty"] = method_sni_empty(hostname, 443, timeout) \
        if has_443 else {"works": False}

    # 4. WebSocket Upgrade
    ws_port = next((p for p in [80, 8080, 443, 8443] if p in open_ports), None)
    methods["http_upgrade"] = method_http_upgrade(hostname, ws_port, timeout) \
        if ws_port else {"works": False}

    # 5. HTTP CONNECT
    con_port = 80 if has_80 else (443 if has_443 else None)
    methods["http_connect"] = method_http_connect(hostname, con_port, timeout) \
        if con_port else {"works": False}

    # 6. Host Header Injection
    methods["host_header_inject"] = method_host_inject(hostname, 80, bug_sni, timeout) \
        if has_80 else {"works": False}

    return methods

# ================================================================
#  CDN Detector
# ================================================================
def detect_cdn(headers):
    s = json.dumps(dict(headers)).lower()
    return list({name for name, sigs in CDN_SIGNATURES.items()
                 if any(sig in s for sig in sigs)})

# ================================================================
#  Full Host Scanner
# ================================================================
def scan_host(hostname, cfg, bug_sni):
    result = {
        "host":             hostname,
        "ip":               None,
        "http_status":      None,
        "https_status":     None,
        "server":           None,
        "cdn":              [],
        "open_ports":       {},
        "http2":            False,
        "sni_methods":      {},
        "working_methods":  [],
        "bug_score":        0,
        "is_bug_host":      False,
        "redirect_to":      None,
        "latency_ms":       None,
    }
    timeout = cfg["timeout"]
    hdrs    = {"User-Agent": get_ua(cfg)}

    # IP resolve
    try:
        result["ip"] = socket.gethostbyname(hostname)
    except: pass

    # Port scan
    result["open_ports"] = scan_ports(hostname, cfg["ports"], timeout) \
        if cfg["check_ports"] else {80: 0, 443: 0}
    op = result["open_ports"]

    # HTTP
    if 80 in op or not cfg["check_ports"]:
        try:
            t0 = time.time()
            r  = requests.get(f"http://{hostname}", timeout=timeout,
                              allow_redirects=True, headers=hdrs, verify=False)
            result["http_status"] = r.status_code
            result["latency_ms"]  = int((time.time() - t0) * 1000)
            result["server"]      = r.headers.get('Server', '')
            result["cdn"]         = detect_cdn(r.headers)
            if r.history:
                result["redirect_to"] = r.url
        except: pass

    # HTTPS
    if cfg["check_https"] and (443 in op or not cfg["check_ports"]):
        try:
            r2 = requests.get(f"https://{hostname}", timeout=timeout,
                              allow_redirects=True, headers=hdrs, verify=False)
            result["https_status"] = r2.status_code
            if not result["server"]:
                result["server"] = r2.headers.get('Server', '')
            result["cdn"] = list(set(result["cdn"] + detect_cdn(r2.headers)))
        except: pass

    # HTTP/2
    if cfg.get("check_http2") and 443 in op:
        result["http2"] = check_http2(hostname, timeout)

    # SNI methods
    if cfg["check_sni"]:
        result["sni_methods"]     = detect_all_methods(hostname, op, timeout, bug_sni)
        result["working_methods"] = [m for m, v in result["sni_methods"].items()
                                     if v.get("works")]

    # Bug Score
    s  = 0
    m  = result["sni_methods"]
    if result["http_status"]  == 200: s += 15
    if result["https_status"] == 200: s += 15
    if m.get("direct_sni",         {}).get("works"): s += 15
    if m.get("sni_mismatch",       {}).get("works"): s += 30  # ← highest weight
    if m.get("sni_empty",          {}).get("works"): s += 10
    if m.get("http_upgrade",       {}).get("works"): s += 15
    if m.get("http_connect",       {}).get("works"): s += 10
    if m.get("host_header_inject", {}).get("works"): s += 10
    if result["http2"]:                              s += 5
    if any(c in result["cdn"] for c in ["Cloudflare","Akamai","Fastly"]): s += 5

    result["bug_score"]   = min(s, 100)
    result["is_bug_host"] = result["bug_score"] >= 50
    return result

# ================================================================
#  Multi-threaded Runner
# ================================================================
def run_scan(subdomains, cfg, bug_sni):
    results = []
    counter = {"n": 0}
    total   = len(subdomains)

    print(C + f"\n  Threads:{cfg['threads']} | Timeout:{cfg['timeout']}s "
              f"| Bug-SNI:{bug_sni}\n" + W)
    print(C + "  " + "─" * 88 + W)

    def worker(h):
        res = scan_host(h, cfg, bug_sni)
        counter["n"] += 1
        progress_bar(counter["n"], total, "Scanning")
        return res

    with ThreadPoolExecutor(max_workers=cfg["threads"]) as ex:
        for fut in as_completed({ex.submit(worker, s): s for s in subdomains}):
            try:
                results.append(fut.result())
            except: pass

    print()
    results.sort(key=lambda x: x["bug_score"], reverse=True)
    return results

# ================================================================
#  Results Display
# ================================================================
def display_results(results, domain):
    bug_hosts    = [r for r in results if r["is_bug_host"]]
    mismatches   = [r for r in results if r["sni_methods"].get("sni_mismatch",{}).get("works")]

    print(G + f"\n{'═'*70}" + W)
    print(G + f"  SCAN COMPLETE — {domain}" + W)
    print(C + f"  Total Scanned   : {len(results)}" + W)
    print(G + f"  Bug Hosts       : {len(bug_hosts)}" + W)
    print(M + f"  SNI Mismatch    : {len(mismatches)}" + W)
    print(B + f"  HTTP/2 Hosts    : {len([r for r in results if r['http2']])}" + W)
    print(G + f"{'═'*70}\n" + W)

    # ── Table 1: Bug Hosts ───────────────────────────────────────
    if bug_hosts:
        print(G + BOLD + f"[★] BUG HOSTS  ({len(bug_hosts)} found)\n" + W)
        print(C + f"  {'HOST':<40} {'IP':<16} {'HTTP':>4} {'HTTPS':>5} "
                  f"{'H2':>3} {'CDN':<14} {'SCORE':>6}  WORKING METHODS" + W)
        print(C + "  " + "─" * 110 + W)
        for r in bug_hosts:
            ip      = r["ip"] or "?"
            http_s  = str(r["http_status"])  if r["http_status"]  else "---"
            https_s = str(r["https_status"]) if r["https_status"] else "---"
            cdn     = ', '.join(r["cdn"][:2]) if r["cdn"] else "—"
            h2      = G+"✔"+W if r["http2"] else DIM+"—"+W
            sc      = score_color(r["bug_score"])
            methods = " ".join(G + METHOD_LABELS.get(m, m) + W for m in r["working_methods"])
            print(f"  {G}{r['host']:<40}{W} {DIM}{ip:<16}{W} "
                  f"{http_s:>4} {https_s:>5} {h2:>3} "
                  f"{M}{cdn:<14}{W} {sc}{r['bug_score']:>5}%{W}  {methods}")
    else:
        print(Y + "  [!] Bug Hosts හොයාගන්න බැරි වුනා." + W)

    # ── Table 2: SNI Mismatch Detail ─────────────────────────────
    if mismatches:
        print(M + BOLD + f"\n[SNI-MISMATCH] Bug Contact Method Detail  ({len(mismatches)} hosts)\n" + W)
        print(C + f"  {'HOST':<40} {'TLS':>8} {'CERT CN (Served)':<32} {'LATENCY':>9}" + W)
        print(C + "  " + "─" * 95 + W)
        for r in mismatches:
            mm  = r["sni_methods"]["sni_mismatch"]
            tls = mm.get("tls", "?")
            cn  = mm.get("cn",  "?") or "?"
            lat = f"{mm['latency']}ms" if mm.get('latency') else "?"
            print(M + f"  {r['host']:<40}{W} {B}{tls:>8}{W} {cn:<32} {Y}{lat:>9}{W}")
        print(M + "\n  ↑ SNI Mismatch method work වෙනවා — bug host candidate!" + W)

    # ── Table 3: All Methods Matrix ──────────────────────────────
    METHODS_ORDER = ["direct_sni","sni_mismatch","sni_empty",
                     "http_upgrade","http_connect","host_header_inject"]
    MLABELS       = ["DirectSNI","Mismatch★","EmptySNI","WS-Up","CONNECT","HostInject"]

    print(C + BOLD + f"\n[METHODS] Working Methods Matrix\n" + W)
    print(C + f"  {'HOST':<40} " + "  ".join(f"{h:<11}" for h in MLABELS) + W)
    print(C + "  " + "─" * 112 + W)
    for r in results[:60]:
        row = f"  {r['host']:<40} "
        for mid in METHODS_ORDER:
            v = r["sni_methods"].get(mid, {})
            if v.get("works"):
                lat = f"({v.get('latency','?')}ms)"
                row += G + f"  ✔{lat:<9}" + W
            else:
                row += R + f"  ✘{'':9}" + W
        print(row)

    # ── Table 4: Direct SNI Detail (TLS Info) ────────────────────
    direct_ok = [r for r in results if r["sni_methods"].get("direct_sni",{}).get("works")]
    if direct_ok:
        print(B + BOLD + f"\n[TLS] Direct-SNI Valid Hosts  ({len(direct_ok)} found)\n" + W)
        print(C + f"  {'HOST':<40} {'TLS':>8} {'CIPHER':<28} {'BITS':>5} {'EXPIRY':<26} {'CN'}" + W)
        print(C + "  " + "─" * 115 + W)
        for r in direct_ok:
            d = r["sni_methods"]["direct_sni"]
            print(B + f"  {r['host']:<40}{W} {d.get('tls','?'):>8} "
                  f"{d.get('cipher','?'):<28} {str(d.get('bits','?')):>5} "
                  f"{d.get('expiry','?'):<26} {d.get('cn','?')}")

    # ── Table 5: Port + HTTP/2 ───────────────────────────────────
    with_ports = [r for r in results if r["open_ports"]]
    if with_ports:
        print(B + BOLD + f"\n[PORTS] Open Ports & HTTP/2\n" + W)
        print(C + f"  {'HOST':<40} {'OPEN PORTS (latency)':<50} {'H2'}" + W)
        print(C + "  " + "─" * 100 + W)
        for r in with_ports[:50]:
            ports = "  ".join(f"{G}{p}{W}({l}ms)" for p, l in sorted(r["open_ports"].items()))
            h2    = G + "HTTP/2✔" + W if r["http2"] else ""
            print(f"  {r['host']:<40} {ports:<50} {h2}")

    # ── Final Summary ────────────────────────────────────────────
    if bug_hosts:
        print(G + BOLD + f"\n[BEST] Top Bug Hosts Summary\n" + W)
        for i, r in enumerate(bug_hosts[:10], 1):
            methods = ", ".join(METHOD_LABELS.get(m,m) for m in r["working_methods"])
            cdn_s   = f" [{', '.join(r['cdn'])}]" if r["cdn"] else ""
            h2_s    = " [HTTP/2]"            if r["http2"] else ""
            ip_s    = f" [{r['ip']}]"         if r["ip"]   else ""
            print(G + f"  {i:>2}. {r['host']}" + W
                  + Y + ip_s + W + M + cdn_s + W + B + h2_s + W)
            print(C + f"      Score:{score_color(r['bug_score'])}{r['bug_score']}%{W}  "
                  f"Methods:{G} {methods}{W}\n")

# ================================================================
#  Domain Scan Menu
# ================================================================
def scan_domain_menu(cfg):
    banner()
    domain = input(Y + "  [+] Target Domain (e.g. dialog.lk) : " + W).strip()
    if not domain: return

    bug_sni = input(Y + "  [+] SNI Mismatch test host (default: free.facebook.com) : " + W).strip()
    if not bug_sni: bug_sni = "free.facebook.com"

    print(C + "\n  [*] Override settings (Enter = use defaults):" + W)
    t  = input(Y + f"      Threads [{cfg['threads']}]: " + W).strip()
    if t.isdigit():  cfg["threads"] = int(t)
    to = input(Y + f"      Timeout [{cfg['timeout']}s]: " + W).strip()
    if to.isdigit(): cfg["timeout"] = int(to)

    subdomains = collect_subdomains(domain, cfg)
    if not subdomains:
        print(R + "\n  [-] Subdomains හොයාගන්න බැරි වුනා!" + W)
        input(Y + "\n  Enter ඔබන්න..." + W); return

    print(G + f"\n  [+] Subdomains: {len(subdomains)}  Bug-SNI: {bug_sni}\n" + W)
    t0      = time.time()
    results = run_scan(subdomains, cfg, bug_sni)
    print(C + f"\n  Scan time: {time.time()-t0:.1f}s\n" + W)
    display_results(results, domain)
    input(Y + "\n  [!] Enter ඔබන්න..." + W)

# ================================================================
#  Single Host Deep Check
# ================================================================
def single_host_menu(cfg):
    banner()
    host = input(Y + "  [+] Host/Domain: " + W).strip()
    if not host: return

    bug_sni = input(Y + "  [+] SNI Mismatch test host (default: free.facebook.com): " + W).strip()
    if not bug_sni: bug_sni = "free.facebook.com"

    print(C + f"\n  Scanning '{host}'...\n" + W)
    res = scan_host(host, cfg, bug_sni)

    print(C + "  " + "═" * 65 + W)
    print(f"  {BOLD}Host      :{W} {G}{res['host']}{W}")
    print(f"  {BOLD}IP        :{W} {res['ip'] or '?'}")
    print(f"  {BOLD}HTTP      :{W} {G if res['http_status']==200 else Y}{res['http_status'] or '---'}{W}")
    print(f"  {BOLD}HTTPS     :{W} {G if res['https_status']==200 else Y}{res['https_status'] or '---'}{W}")
    print(f"  {BOLD}Server    :{W} {res['server'] or 'Unknown'}")
    print(f"  {BOLD}HTTP/2    :{W} {G+'✔ YES'+W if res['http2'] else R+'✘ NO'+W}")
    print(f"  {BOLD}CDN       :{W} {M+', '.join(res['cdn'])+W if res['cdn'] else 'None'}")

    if res["open_ports"]:
        ports = "  ".join(f"{G}{p}{W}({l}ms)" for p, l in sorted(res["open_ports"].items()))
        print(f"  {BOLD}Open Ports:{W} {ports}")

    print(C + "\n  [SNI Method Results]\n" + W)
    print(C + f"  {'METHOD':<24} {'STATUS':<10} {'TLS':<10} {'LATENCY':<12} DETAIL" + W)
    print(C + "  " + "─" * 72 + W)

    for mid, label in METHOD_LABELS.items():
        v = res["sni_methods"].get(mid, {})
        if v.get("works"):
            tls = v.get("tls", "")
            lat = f"{v.get('latency','?')}ms"
            cn  = v.get("cn","") or ""
            extra = f"cn:{cn}" if cn and cn != '?' else ""
            extra += f"  code:{v.get('code','')}" if v.get('code') else ""
            print(f"  {label:<24} {G}WORKS{W}      {tls:<10} {lat:<12} {DIM}{extra}{W}")
        else:
            print(f"  {label:<24} {R}no resp{W}")

    sc      = score_color(res['bug_score'])
    verdict = f"{G}{BOLD}★ BUG HOST{W}" if res["is_bug_host"] else f"{R}NOT a Bug Host{W}"
    print(C + "\n  " + "─" * 65 + W)
    print(f"  {BOLD}Bug Score :{W} {sc}{res['bug_score']}%{W}")
    print(f"  {BOLD}Verdict   :{W} {verdict}")

    if res["working_methods"]:
        methods = ", ".join(METHOD_LABELS.get(m,m) for m in res["working_methods"])
        print(Y + f"\n  Working Methods: {G}{methods}{W}")

    print(C + "  " + "═" * 65 + W)
    input(Y + "\n  Enter ඔබන්න..." + W)

# ================================================================
#  Batch Scan (File)
# ================================================================
def batch_scan_menu(cfg):
    banner()
    fpath = input(Y + "  [+] Domain list file (one domain per line): " + W).strip()
    if not os.path.exists(fpath):
        print(R + f"  [-] File not found: {fpath}" + W)
        input(Y + "  Enter ඔබන්න..." + W); return

    with open(fpath) as f:
        domains = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    bug_sni = input(Y + "  [+] Bug SNI host (default: free.facebook.com): " + W).strip()
    if not bug_sni: bug_sni = "free.facebook.com"

    print(G + f"  [+] Domains: {len(domains)}\n" + W)

    for domain in domains:
        print(C + f"\n{'═'*50}\n  Scanning: {domain}\n{'═'*50}" + W)
        subs = collect_subdomains(domain, cfg)
        if not subs:
            print(R + f"  [-] No subdomains for {domain}" + W); continue
        results = run_scan(subs, cfg, bug_sni)
        display_results(results, domain)

    input(Y + "\n  Enter ඔබන්න..." + W)

# ================================================================
#  Config Editor
# ================================================================
def config_menu(cfg):
    while True:
        banner()
        print(Y + "  [CONFIG EDITOR]\n" + W)
        print(C + f"  1. Threads       : {cfg['threads']}" + W)
        print(C + f"  2. Timeout       : {cfg['timeout']}s" + W)
        print(C + f"  3. HTTPS Check   : {cfg['check_https']}" + W)
        print(C + f"  4. SNI Check     : {cfg['check_sni']}" + W)
        print(C + f"  5. HTTP/2 Check  : {cfg.get('check_http2', True)}" + W)
        print(C + f"  6. CRT.sh        : {cfg['use_crtsh']}" + W)
        print(C + f"  7. AlienVault    : {cfg['use_alienvault']}" + W)
        print(C + f"  8. Save & Back" + W)
        print(C + f"  9. Back (no save)" + W)

        ch = input(C + "\n  Choice: " + W).strip()
        if ch == '1':
            v = input(Y + f"  Threads [{cfg['threads']}]: " + W).strip()
            if v.isdigit(): cfg["threads"] = int(v)
        elif ch == '2':
            v = input(Y + f"  Timeout [{cfg['timeout']}]: " + W).strip()
            if v.isdigit(): cfg["timeout"] = int(v)
        elif ch == '3': cfg["check_https"]  = not cfg["check_https"]
        elif ch == '4': cfg["check_sni"]    = not cfg["check_sni"]
        elif ch == '5': cfg["check_http2"]  = not cfg.get("check_http2", True)
        elif ch == '6': cfg["use_crtsh"]    = not cfg["use_crtsh"]
        elif ch == '7': cfg["use_alienvault"]= not cfg["use_alienvault"]
        elif ch == '8': save_config(cfg); break
        elif ch == '9': break

# ================================================================
#  Main Menu
# ================================================================
def main():
    import urllib3
    urllib3.disable_warnings()
    cfg = load_config()

    while True:
        banner()
        print(Y + "  ┌──────────────────────────────────────────────┐" + W)
        print(Y + "  │              MAIN MENU                       │" + W)
        print(Y + "  ├──────────────────────────────────────────────┤" + W)
        print(Y + "  │  " + W + "[1]  Domain Scan     (Subdomains + SNI)  " + Y + "│" + W)
        print(Y + "  │  " + W + "[2]  Single Host     (Deep Check)        " + Y + "│" + W)
        print(Y + "  │  " + W + "[3]  Batch Scan      (File Input)        " + Y + "│" + W)
        print(Y + "  │  " + W + "[4]  Settings / Config                   " + Y + "│" + W)
        print(Y + "  │  " + W + "[5]  Exit                                " + Y + "│" + W)
        print(Y + "  └──────────────────────────────────────────────┘\n" + W)

        ch = input(C + "  Choice (1-5): " + W).strip()
        if   ch == '1': scan_domain_menu(cfg)
        elif ch == '2': single_host_menu(cfg)
        elif ch == '3': batch_scan_menu(cfg)
        elif ch == '4': config_menu(cfg)
        elif ch == '5':
            print(G + "\n  ජය වේවා! 👋\n" + W); sys.exit(0)
        else:
            print(R + "\n  [-] 1-5 ඇතුලත් කරන්න.\n" + W)
            time.sleep(1)

if __name__ == "__main__":
    main()
