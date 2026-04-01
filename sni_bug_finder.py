#!/usr/bin/env python3
# ============================================================
#         PRO SNI BUG HOST FINDER TOOL v2.0
#         GitHub: github.com/yourname/sni-bug-finder
# ============================================================

import requests
import socket
import ssl
import os
import sys
import time
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ══════════════════════════════════════
#  Terminal Colors
# ══════════════════════════════════════
G  = '\033[92m'   # Green   - සාර්ථකයි
R  = '\033[91m'   # Red     - අසාර්ථකයි
C  = '\033[96m'   # Cyan    - සාමාන්‍ය info
Y  = '\033[93m'   # Yellow  - menu / warning
B  = '\033[94m'   # Blue    - headers
M  = '\033[95m'   # Magenta - CDN / special
W  = '\033[0m'    # Reset
BOLD = '\033[1m'

# ══════════════════════════════════════
#  Thread-safe print lock
# ══════════════════════════════════════
print_lock = threading.Lock()

def safe_print(text):
    with print_lock:
        print(text)

# ══════════════════════════════════════
#  CDN / Bug Host Signatures
# ══════════════════════════════════════
CDN_SIGNATURES = {
    "Cloudflare":   ["cloudflare", "cf-ray", "cf-cache-status"],
    "Akamai":       ["akamai", "x-check-cacheable", "x-akamai"],
    "Fastly":       ["fastly", "x-fastly", "x-served-by"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "Google CDN":   ["gws", "x-google", "x-goog"],
    "Azure CDN":    ["x-azure", "x-msedge-ref"],
    "Nginx":        ["nginx"],
    "Apache":       ["apache"],
    "LiteSpeed":    ["litespeed"],
}

SNI_BUG_PORTS = [80, 443, 8080, 8443]

# ══════════════════════════════════════
#  UI Functions
# ══════════════════════════════════════
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    clear_screen()
    banner = f"""
{C}╔══════════════════════════════════════════════════════╗
║                                                      ║
║  {G}{BOLD}  ██████  ███    ██ ██     {C}  SNI BUG FINDER v2.0   {C}║
║  {G}██       ████   ██ ██     {C}                           ║
║  {G}███████  ██ ██  ██ ██     {C}  Multi-Thread Scanner     ║
║  {G}     ██  ██  ██ ██ ██     {C}  CDN Detector             ║
║  {G}██████   ██   ████ ██     {C}  SSL/SNI Checker          ║
║                                                      ║
╚══════════════════════════════════════════════════════╝{W}
{Y}  [!] අනවසර ප්‍රහාරයන් සඳහා භාවිතා නොකරන්න!{W}
{Y}  [!] Educational & Research use only!{W}
"""
    print(banner)

def show_progress(current, total, prefix=''):
    bar_len = 40
    filled = int(bar_len * current / total) if total > 0 else 0
    bar = '█' * filled + '░' * (bar_len - filled)
    pct = current / total * 100 if total > 0 else 0
    with print_lock:
        sys.stdout.write(f"\r{C}{prefix} [{G}{bar}{C}] {pct:.1f}% ({current}/{total}){W}")
        sys.stdout.flush()

# ══════════════════════════════════════
#  Subdomain Discovery
# ══════════════════════════════════════
def get_subdomains_hackertarget(domain):
    """HackerTarget API එකෙන් subdomains ගැනීම"""
    subdomains = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip()
                    if sub:
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains

def get_subdomains_crtsh(domain):
    """Certificate Transparency (crt.sh) API එකෙන් subdomains ගැනීම"""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        headers = {'User-Agent': 'Mozilla/5.0 SNI-BugFinder/2.0'}
        resp = requests.get(url, timeout=15, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lstrip('*.')
                    if sub and domain in sub:
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains

def get_subdomains_alienvault(domain):
    """AlienVault OTX API එකෙන් subdomains ගැනීම"""
    subdomains = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        headers = {'User-Agent': 'Mozilla/5.0 SNI-BugFinder/2.0'}
        resp = requests.get(url, timeout=10, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            for record in data.get('passive_dns', []):
                hostname = record.get('hostname', '')
                if hostname and domain in hostname:
                    subdomains.add(hostname)
    except Exception:
        pass
    return subdomains

def collect_all_subdomains(domain, use_crtsh=True, use_alienvault=True):
    """Sources කිහිපයකින් subdomains එකතු කිරීම"""
    all_subs = set()
    sources_used = []

    print(C + "\n[*] Subdomain Sources:" + W)

    # Source 1: HackerTarget
    print(C + "  → HackerTarget API ස්කෑන් කරමින්..." + W, end='', flush=True)
    ht = get_subdomains_hackertarget(domain)
    all_subs |= ht
    sources_used.append(f"HackerTarget ({len(ht)})")
    print(G + f" {len(ht)} ක් ✔" + W)

    # Source 2: crt.sh
    if use_crtsh:
        print(C + "  → CRT.sh (SSL Certs) ස්කෑන් කරමින්..." + W, end='', flush=True)
        crt = get_subdomains_crtsh(domain)
        all_subs |= crt
        sources_used.append(f"CRT.sh ({len(crt)})")
        print(G + f" {len(crt)} ක් ✔" + W)

    # Source 3: AlienVault
    if use_alienvault:
        print(C + "  → AlienVault OTX ස්කෑන් කරමින්..." + W, end='', flush=True)
        av = get_subdomains_alienvault(domain)
        all_subs |= av
        sources_used.append(f"AlienVault ({len(av)})")
        print(G + f" {len(av)} ක් ✔" + W)

    return list(all_subs), sources_used

# ══════════════════════════════════════
#  SNI / SSL Checker
# ══════════════════════════════════════
def check_sni(hostname, port=443, timeout=4):
    """
    SSL/TLS SNI handshake check කිරීම.
    SNI Bug Hosting සඳහා SSL certificate valid ද බලනවා.
    """
    result = {
        "sni_works": False,
        "cert_subject": None,
        "cert_issuer": None,
        "tls_version": None,
        "sni_mismatch": False,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["sni_works"] = True
                result["tls_version"] = ssock.version()
                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer  = dict(x[0] for x in cert.get('issuerAltName', cert.get('issuer', [])))
                    result["cert_subject"] = subject.get('commonName', 'Unknown')
                    result["cert_issuer"]  = subject.get('organizationName', 'Unknown')
                    # SNI Mismatch check (Bug Host indicator)
                    cn = subject.get('commonName', '')
                    if cn and hostname not in cn and cn not in hostname:
                        result["sni_mismatch"] = True
    except ssl.SSLError:
        result["sni_works"] = False
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return result

# ══════════════════════════════════════
#  CDN Detector
# ══════════════════════════════════════
def detect_cdn(headers: dict, server_ip: str = "") -> list:
    """Response headers බලලා CDN සොයාගැනීම"""
    found = []
    header_str = json.dumps(headers).lower()

    for cdn_name, signatures in CDN_SIGNATURES.items():
        for sig in signatures:
            if sig in header_str:
                found.append(cdn_name)
                break
    return list(set(found))

# ══════════════════════════════════════
#  Main Host Scanner
# ══════════════════════════════════════
def scan_host(hostname, check_https=True, check_sni_flag=True, timeout=4):
    """
    එක host එකක් සම්පූර්ණයෙන් scan කිරීම:
    - HTTP/HTTPS status
    - SNI/SSL check
    - CDN detection
    - Server headers
    """
    result = {
        "host":         hostname,
        "http_status":  None,
        "https_status": None,
        "server":       None,
        "cdn":          [],
        "sni":          {},
        "is_bug_host":  False,
        "bug_score":    0,   # 0-100 Bug Host probability
        "redirect_to":  None,
    }

    req_headers = {'User-Agent': 'Mozilla/5.0 SNI-BugFinder/2.0'}

    # ── HTTP Check ──────────────────────────
    try:
        r = requests.get(f"http://{hostname}", timeout=timeout,
                         allow_redirects=True, headers=req_headers)
        result["http_status"] = r.status_code
        result["server"] = r.headers.get('Server', r.headers.get('server', ''))
        cdns = detect_cdn(dict(r.headers))
        result["cdn"].extend(cdns)

        if r.history:
            result["redirect_to"] = r.url
    except requests.exceptions.RequestException:
        pass

    # ── HTTPS Check ─────────────────────────
    if check_https:
        try:
            r2 = requests.get(f"https://{hostname}", timeout=timeout,
                              allow_redirects=True, headers=req_headers,
                              verify=False)
            result["https_status"] = r2.status_code
            if not result["server"]:
                result["server"] = r2.headers.get('Server', '')
            cdns2 = detect_cdn(dict(r2.headers))
            result["cdn"].extend(cdns2)
        except requests.exceptions.RequestException:
            pass

    result["cdn"] = list(set(result["cdn"]))

    # ── SNI Check ───────────────────────────
    if check_sni_flag:
        result["sni"] = check_sni(hostname, timeout=timeout)

    # ── Bug Score Calculation ────────────────
    score = 0
    if result["http_status"] == 200:
        score += 30
    elif result["http_status"] in [301, 302, 307, 308]:
        score += 15

    if result["https_status"] == 200:
        score += 20
    elif result["https_status"] in [301, 302]:
        score += 10

    if result["sni"].get("sni_works"):
        score += 25

    if result["sni"].get("sni_mismatch"):
        score += 15   # SNI mismatch = likely bug host!

    if any(c in result["cdn"] for c in ["Cloudflare", "Akamai", "Fastly"]):
        score += 10

    result["bug_score"] = min(score, 100)
    result["is_bug_host"] = score >= 50

    return result

# ══════════════════════════════════════
#  Results Printer
# ══════════════════════════════════════
def print_result(res):
    host        = res["host"]
    http_s      = res["http_status"]
    https_s     = res["https_status"]
    sni         = res["sni"]
    cdn_list    = res["cdn"]
    score       = res["bug_score"]
    is_bug      = res["is_bug_host"]
    server      = res["server"] or "Unknown"
    redirect    = res["redirect_to"]

    # Score color
    if score >= 70:
        score_col = G + BOLD
    elif score >= 40:
        score_col = Y
    else:
        score_col = R

    # HTTP status color
    def status_color(s):
        if s == 200: return G + str(s) + W
        if s in [301,302,307,308]: return Y + str(s) + W
        if s: return R + str(s) + W
        return R + "---" + W

    bug_tag = f"{G}{BOLD}[★ BUG HOST]{W}" if is_bug else f"{R}[✘ NOT BUG]{W}"

    line = (
        f"{bug_tag} "
        f"{C}{host:<40}{W} "
        f"HTTP:{status_color(http_s)} "
        f"HTTPS:{status_color(https_s)} "
        f"SNI:{G+'✔'+W if sni.get('sni_works') else R+'✘'+W} "
        f"Score:{score_col}{score:>3}%{W}"
    )

    if cdn_list:
        line += f" {M}[{', '.join(cdn_list)}]{W}"

    if sni.get("sni_mismatch"):
        line += f" {Y}[SNI-MISMATCH!]{W}"

    if server and server != "Unknown":
        line += f" {B}[{server}]{W}"

    safe_print(line)

# ══════════════════════════════════════
#  Multi-threaded Scanner
# ══════════════════════════════════════
def run_scan(subdomains, threads=20, check_https=True, check_sni_flag=True, timeout=4):
    """Thread pool භාවිතා කරලා ඉක්මනින් scan කිරීම"""

    results      = []
    bug_hosts    = []
    counter      = {"done": 0}
    total        = len(subdomains)

    print(C + f"\n[*] Threads: {threads} | HTTPS: {'✔' if check_https else '✘'} "
              f"| SNI Check: {'✔' if check_sni_flag else '✘'} "
              f"| Timeout: {timeout}s\n" + W)
    print(C + "─" * 90 + W)

    def scan_wrapper(host):
        res = scan_host(host, check_https, check_sni_flag, timeout)
        counter["done"] += 1
        show_progress(counter["done"], total, "Scanning")
        return res

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_wrapper, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            try:
                res = future.result()
                results.append(res)
                if res["is_bug_host"] or res["bug_score"] >= 40:
                    print_result(res)
            except Exception:
                pass

    print()  # newline after progress bar
    print(C + "─" * 90 + W)

    # Sort by bug_score
    results.sort(key=lambda x: x["bug_score"], reverse=True)
    bug_hosts = [r for r in results if r["is_bug_host"]]

    return results, bug_hosts


# ══════════════════════════════════════
#  Scan Domain Menu
# ══════════════════════════════════════
def scan_domain_menu():
    show_banner()

    domain = input(Y + "\n[+] Target Domain (උදා: dialog.lk) : " + W).strip()
    if not domain:
        return

    # Settings
    print(C + "\n[*] Scan Settings:" + W)

    t_input = input(Y + f"  Threads (default 20): " + W).strip()
    threads = int(t_input) if t_input.isdigit() else 20

    to_input = input(Y + f"  Timeout seconds (default 4): " + W).strip()
    timeout = int(to_input) if to_input.isdigit() else 4

    https_input = input(Y + f"  HTTPS Check? (y/n, default y): " + W).strip().lower()
    check_https = https_input != 'n'

    sni_input = input(Y + f"  SNI/SSL Check? (y/n, default y): " + W).strip().lower()
    check_sni_flag = sni_input != 'n'

    crtsh_input = input(Y + f"  CRT.sh Subdomains? (y/n, default y): " + W).strip().lower()
    use_crtsh = crtsh_input != 'n'

    av_input = input(Y + f"  AlienVault Subdomains? (y/n, default y): " + W).strip().lower()
    use_av = av_input != 'n'

    print(C + f"\n{'─'*60}" + W)
    print(G + f"[*] '{domain}' ස්කෑන් කිරීම ආරම්භ වේ..." + W)

    # Subdomain collection
    subdomains, sources = collect_all_subdomains(domain, use_crtsh, use_av)

    if not subdomains:
        print(R + "\n[-] Subdomains හොයාගන්න බැරි වුනා!" + W)
        input(Y + "\n[!] Enter ඔබන්න..." + W)
        return

    print(G + f"\n[+] මුළු Subdomains: {len(subdomains)} (" + ", ".join(sources) + ")" + W)
    print(C + f"[*] Bug Host Score ≥ 50% ෙලස් ප‍්‍රකාශ වෙනවා\n" + W)

    # Run scan
    start_time = time.time()
    results, bug_hosts = run_scan(subdomains, threads, check_https, check_sni_flag, timeout)
    elapsed = time.time() - start_time

    # Summary
    print(G + f"\n{'═'*60}" + W)
    print(G + f"  ✔  Scan ඉවර! ({elapsed:.1f}s)" + W)
    print(C + f"  →  Scanned:   {len(results)}" + W)
    print(G + f"  →  Bug Hosts: {len(bug_hosts)}" + W)
    print(M + f"  →  CDN Found: {len([r for r in results if r['cdn']])}" + W)
    print(B + f"  →  SNI Valid: {len([r for r in results if r['sni'].get('sni_works')])}" + W)
    print(G + f"{'═'*60}\n" + W)

    # ── Bug Hosts Table ──────────────────────
    if bug_hosts:
        print(G + BOLD + f"\n[★] Bug Hosts ({len(bug_hosts)} found):\n" + W)
        print(C + f"  {'HOST':<42} {'HTTP':>5} {'HTTPS':>6} {'SNI':>4} {'CDN':<18} {'SCORE':>6}" + W)
        print(C + "  " + "─" * 85 + W)
        for r in bug_hosts:
            cdn_str = ', '.join(r['cdn']) if r['cdn'] else "—"
            http_s  = str(r['http_status'])  if r['http_status']  else "---"
            https_s = str(r['https_status']) if r['https_status'] else "---"
            sni_str = "✔" if r["sni"].get("sni_works") else "✘"
            mm_str  = f" {Y}[MISMATCH]{W}" if r["sni"].get("sni_mismatch") else ""
            sni_col = G if r["sni"].get("sni_works") else R
            score_col = G if r['bug_score'] >= 70 else Y
            print(
                G + f"  {r['host']:<42}{W} "
                f"{http_s:>5} "
                f"{https_s:>6} "
                + sni_col + f"{sni_str:>4}{W} "
                + M + f"{cdn_str:<18}{W} "
                + score_col + f"{r['bug_score']:>5}%{W}"
                + mm_str
            )
    else:
        print(Y + "\n[!] Bug Hosts හොයාගන්න බැරි වුනා." + W)

    # ── SNI Valid Hosts Table ─────────────────
    sni_valid = [r for r in results if r["sni"].get("sni_works")]
    if sni_valid:
        print(B + BOLD + f"\n[TLS] SNI Valid Hosts ({len(sni_valid)} found):\n" + W)
        print(C + f"  {'HOST':<42} {'TLS':<10} {'CERT CN':<35} {'MISMATCH'}" + W)
        print(C + "  " + "─" * 100 + W)
        for r in sni_valid:
            tls = r["sni"].get("tls_version", "?")
            cn  = r["sni"].get("cert_subject", "?") or "?"
            mm  = f"{Y}⚠ YES{W}" if r["sni"].get("sni_mismatch") else "No"
            print(B + f"  {r['host']:<42}{W} {tls:<10} {cn:<35} {mm}")

    # ── All Results (sorted by score) ────────
    print(C + BOLD + f"\n[ALL] Full Results (score order):\n" + W)
    print(C + f"  {'HOST':<42} {'HTTP':>5} {'HTTPS':>6} {'SNI':>4} {'SCORE':>6}" + W)
    print(C + "  " + "─" * 65 + W)
    for r in results:
        http_s  = str(r['http_status'])  if r['http_status']  else "---"
        https_s = str(r['https_status']) if r['https_status'] else "---"
        sni_str = G+"✔"+W if r["sni"].get("sni_works") else R+"✘"+W
        score_col = G if r['bug_score'] >= 70 else (Y if r['bug_score'] >= 40 else R)
        tag = G+"[★]"+W if r["is_bug_host"] else "   "
        print(f"  {tag} {r['host']:<42} {http_s:>5} {https_s:>6} {sni_str:>4} "
              + score_col + f"{r['bug_score']:>5}%{W}")

    input(Y + "\n[!] Enter ඔබන්න..." + W)

# ══════════════════════════════════════
#  Single Host Check
# ══════════════════════════════════════
def single_host_check():
    show_banner()
    host = input(Y + "\n[+] Check කරන්න Host/Domain: " + W).strip()
    if not host:
        return

    print(C + f"\n[*] '{host}' check කරමින්...\n" + W)
    import urllib3
    urllib3.disable_warnings()

    res = scan_host(host, check_https=True, check_sni_flag=True, timeout=6)

    print(C + "─" * 60 + W)
    print(f"  {BOLD}Host:{W}         {G}{res['host']}{W}")
    print(f"  {BOLD}HTTP Status:{W}  {G if res['http_status']==200 else Y}{res['http_status'] or '---'}{W}")
    print(f"  {BOLD}HTTPS Status:{W} {G if res['https_status']==200 else Y}{res['https_status'] or '---'}{W}")
    print(f"  {BOLD}Server:{W}       {res['server'] or 'Unknown'}")
    print(f"  {BOLD}CDN:{W}          {M + ', '.join(res['cdn']) + W if res['cdn'] else 'None detected'}")

    sni = res["sni"]
    print(f"  {BOLD}SNI Works:{W}    {G+'✔ YES'+W if sni.get('sni_works') else R+'✘ NO'+W}")
    if sni.get("sni_works"):
        print(f"  {BOLD}TLS Version:{W}  {sni.get('tls_version', '?')}")
        print(f"  {BOLD}Cert CN:{W}      {sni.get('cert_subject', '?')}")
        mm = sni.get("sni_mismatch")
        print(f"  {BOLD}SNI Mismatch:{W} {Y+'⚠ YES (Bug Host Indicator!)'+W if mm else 'No'}")

    score = res["bug_score"]
    score_col = G if score >= 70 else (Y if score >= 40 else R)
    print(f"  {BOLD}Bug Score:{W}    {score_col}{score}%{W}")
    verdict = f"{G}{BOLD}★ BUG HOST{W}" if res["is_bug_host"] else f"{R}NOT a Bug Host{W}"
    print(f"  {BOLD}Verdict:{W}      {verdict}")
    print(C + "─" * 60 + W)

    if res["redirect_to"]:
        print(Y + f"  Redirects to: {res['redirect_to']}" + W)

    input(Y + "\n[!] Enter ඔබන්න..." + W)

# ══════════════════════════════════════
#  Main Menu
# ══════════════════════════════════════
def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    while True:
        show_banner()
        print(Y + "  ┌─────────────────────────────────────┐" + W)
        print(Y + "  │          MAIN MENU                  │" + W)
        print(Y + "  ├─────────────────────────────────────┤" + W)
        print(Y + "  │  " + W + "[1]  Domain Scan (Subdomain + SNI) " + Y + "│" + W)
        print(Y + "  │  " + W + "[2]  Single Host Check            " + Y + "  │" + W)
        print(Y + "  │  " + W + "[3]  Exit                         " + Y + "  │" + W)
        print(Y + "  └─────────────────────────────────────┘\n" + W)

        choice = input(C + "  ඔයාගේ තේරීම (1/2/3): " + W).strip()

        if choice == '1':
            scan_domain_menu()
        elif choice == '2':
            single_host_check()
        elif choice == '3':
            print(G + "\n  [+] ජය වේවා! 👋\n" + W)
            sys.exit(0)
        else:
            print(R + "\n  [-] වැරදි input! 1, 2, හෝ 3 ඔබන්න.\n" + W)
            time.sleep(1.5)

if __name__ == "__main__":
    main()
