#!/usr/bin/env python3
# ================================================================
#   SNI SPEED HUNTER  v1.0  — IP Range Scanner + ISP Config
#   ─────────────────────────────────────────────────────────────
#   Features:
#     [SH-1]  IP Range Speed Scanner
#             — Zoom/Facebook/WhatsApp/ISP ranges
#             — Latency + TLS handshake + transport benchmark
#             — Top-10 fastest IPs auto-rank
#
#     [SH-2]  Transport Speed Benchmark (per IP)
#             — WS / gRPC / SplitHTTP / HTTPUpgrade / TCP-TLS
#             — Real throughput measure (KB/s)
#             — Auto-select winner transport
#
#     [SH-3]  ISP Profile Manager
#             — Dialog  : ports 80,443,8080,8443
#             — Mobitel : ports 80,443,2060,2086,8080,8443
#             — Hutch   : ports 80,443,8080
#             — SLT     : ports 80,443,8080,8443
#             — Per-ISP zero-rated SNI list
#
#     [SH-4]  Best Host Finder
#             — SNI candidate × ISP × port × transport matrix
#             — Composite speed score
#             — Winner config auto-generate
#
#     [SH-5]  3x-ui / Xray Config Generator
#             — ALL working transports (not just gRPC)
#             — ISP-specific port + SNI combos
#             — VLESS / VMess / Trojan links
#             — v2rayNG share links
#   ─────────────────────────────────────────────────────────────
#   Usage (standalone):
#       python3 sni_speed_hunter.py
#   Usage (imported):
#       from sni_speed_hunter import run_speed_hunter_menu
# ================================================================

from __future__ import annotations
import socket, ssl, os, sys, time, json, threading, ipaddress
import struct, random, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# ── Colors ────────────────────────────────────────────────────────
G='\033[92m'; R='\033[91m'; C='\033[96m'; Y='\033[93m'
B='\033[94m'; M='\033[95m'; W='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

plock = threading.Lock()
def sp(t):
    with plock: print(t)

# ================================================================
#  SH-3: ISP Profile Database
#  Dialog / Mobitel / Hutch / SLT — zero-rated ports + SNIs
# ================================================================
ISP_PROFILES = {
    "Dialog": {
        "asns":  ["AS9329"],
        "name":  "Dialog Axiata (Sri Lanka)",
        "ports": [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096],
        "tls_ports": [443, 8443, 2053, 2083, 2087, 2096],
        "plain_ports": [80, 8080, 2052, 2082, 2086, 2095],
        "zero_rated_snis": [
            "wa.me",
            "web.whatsapp.com",
            "whatsapp.com",
            "free.facebook.com",
            "static.xx.fbcdn.net",
            "edge-star-mini.facebook.com",
            "zoom.us",
            "us02web.zoom.us",
            "us04web.zoom.us",
            "speedtest.dialog.lk",
            "myaccount.dialog.lk",
        ],
        "notes": "Zoom education zero-rated. WhatsApp/Facebook free data.",
        "best_transport": ["gRPC", "WS+TLS", "SplitHTTP"],
    },
    "Mobitel": {
        "asns":  ["AS17639"],
        "name":  "Mobitel (Sri Lanka)",
        "ports": [80, 443, 2060, 2086, 8080, 8443, 2052, 2053, 2095, 2096],
        "tls_ports": [443, 8443, 2053, 2096],
        "plain_ports": [80, 8080, 2060, 2086, 2052, 2095],
        "zero_rated_snis": [
            "wa.me",
            "web.whatsapp.com",
            "whatsapp.com",
            "free.facebook.com",
            "static.xx.fbcdn.net",
            "zoom.us",
            "us02web.zoom.us",
            "speedtest.mobitel.lk",
            "selfcare.mobitel.lk",
        ],
        "notes": "Port 2060/2086 special for Mobitel zero-rating. "
                 "Zoom connect works differently — test 2060 first.",
        "best_transport": ["WS (port 2060)", "gRPC (port 443)", "SplitHTTP"],
        "special_ports": {
            2060: "Mobitel zero-rate special port (HTTP)",
            2086: "Mobitel alternative (HTTP)",
        },
    },
    "Hutch": {
        "asns":  ["AS24616"],
        "name":  "Hutchison Telecommunications (Sri Lanka)",
        "ports": [80, 443, 8080, 8443, 2052, 2053],
        "tls_ports": [443, 8443, 2053],
        "plain_ports": [80, 8080, 2052],
        "zero_rated_snis": [
            "wa.me",
            "web.whatsapp.com",
            "free.facebook.com",
            "youtube.com",
            "googlevideo.com",
            "speedtest.hutch.lk",
        ],
        "notes": "YouTube zero-rated on Hutch. WS transport works best.",
        "best_transport": ["WS+TLS", "gRPC", "HTTPUpgrade"],
    },
    "SLT": {
        "asns":  ["AS9270"],
        "name":  "Sri Lanka Telecom (SLT)",
        "ports": [80, 443, 8080, 8443, 2052, 2053, 2082, 2083],
        "tls_ports": [443, 8443, 2053, 2083],
        "plain_ports": [80, 8080, 2052, 2082],
        "zero_rated_snis": [
            "wa.me",
            "web.whatsapp.com",
            "free.facebook.com",
            "zoom.us",
            "slt.lk",
            "speedtest.slt.lk",
        ],
        "notes": "Standard Cloudflare ports. gRPC recommended.",
        "best_transport": ["gRPC", "WS+TLS", "SplitHTTP"],
    },
    "Unknown": {
        "asns":  [],
        "name":  "Unknown ISP",
        "ports": [80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096],
        "tls_ports": [443, 8443, 2053, 2083, 2087, 2096],
        "plain_ports": [80, 8080, 2052, 2082, 2086, 2095],
        "zero_rated_snis": [
            "wa.me", "web.whatsapp.com", "free.facebook.com",
            "zoom.us", "youtube.com",
        ],
        "notes": "Generic config — test all ports.",
        "best_transport": ["gRPC", "WS+TLS", "SplitHTTP"],
    },
}

# ================================================================
#  SH-1: IP Range Database
#  Known zero-rated / CDN IP ranges to scan
# ================================================================
IP_RANGE_DB = {
    "Zoom-CDN": {
        "ranges": [
            "170.114.52.0/23",   # Zoom Cloudflare CDN (closest to Asia)
            "170.114.62.0/24",   # Zoom Asia Pacific edge
            "170.114.0.0/20",    # Zoom broader range
        ],
        "sni":       "zoom.us",
        "ports":     [443, 8443, 2053, 80, 8080],
        "service":   "Zoom (Education zero-rated)",
    },
    "Zoom-AWS": {
        "ranges": [
            "99.79.0.0/24",
            "3.7.0.0/24",
        ],
        "sni":       "zoom.us",
        "ports":     [443, 8443],
        "service":   "Zoom (AWS backend)",
    },
    "Facebook-Free": {
        "ranges": [
            "31.13.64.0/20",     # Facebook Corp (EU)
            "157.240.0.0/20",    # Facebook Corp (global)
            "179.60.192.0/22",   # Facebook Corp
        ],
        "sni":       "free.facebook.com",
        "ports":     [443, 80],
        "service":   "Facebook Free Basics",
    },
    "WhatsApp": {
        "ranges": [
            "185.60.216.0/22",   # WhatsApp
        ],
        "sni":       "wa.me",
        "ports":     [443, 5222, 80],
        "service":   "WhatsApp (zero-rated)",
    },
    "Cloudflare-Global": {
        "ranges": [
            "104.16.0.0/13",     # Cloudflare
            "172.64.0.0/13",     # Cloudflare
            "141.101.64.0/18",   # Cloudflare
        ],
        "sni":       "cloudflare.com",
        "ports":     [443, 80, 2053, 2083, 2087, 2096],
        "service":   "Cloudflare CDN",
    },
    "Cloudflare-Asia": {
        "ranges": [
            "103.21.244.0/22",   # Cloudflare APAC
            "103.22.200.0/22",   # Cloudflare APAC
            "103.31.4.0/22",     # Cloudflare APAC
            "108.162.192.0/18",  # Cloudflare APAC
        ],
        "sni":       "cloudflare.com",
        "ports":     [443, 80, 2053, 2087],
        "service":   "Cloudflare CDN (Asia)",
    },
}

# ================================================================
#  Transport Test Functions
# ================================================================

def test_latency(ip: str, port: int, timeout: float = 3.0) -> Optional[int]:
    """Raw TCP connect latency (ms). Returns None if unreachable."""
    try:
        t0   = time.time()
        sock = socket.create_connection((ip, port), timeout=timeout)
        lat  = int((time.time() - t0) * 1000)
        sock.close()
        return lat
    except Exception:
        return None


def test_tls_handshake(ip: str, port: int, sni: str,
                       timeout: float = 4.0) -> Dict:
    """TLS handshake speed + cert info."""
    result = {"ok": False, "lat_ms": None, "tls_ver": None, "cn": None}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        t0   = time.time()
        raw  = socket.create_connection((ip, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=sni)
        lat  = int((time.time() - t0) * 1000)
        cert = sock.getpeercert() or {}
        subj = dict(x[0] for x in cert.get("subject", []))
        sock.close()
        result = {
            "ok":     True,
            "lat_ms": lat,
            "tls_ver": sock.version() if hasattr(sock,"version") else "TLS",
            "cn":     subj.get("commonName",""),
        }
    except Exception:
        pass
    return result


def test_ws_transport(ip: str, port: int, sni: str,
                      path: str = "/", timeout: float = 5.0) -> Dict:
    """
    WebSocket upgrade test.
    Measures: connect latency, WS handshake, payload round-trip.
    """
    result = {"works": False, "lat_ms": None, "speed_kbps": None,
              "ws_key_ok": False, "path": path}
    try:
        use_tls = port in [443, 8443, 2053, 2083, 2087, 2096]
        t0 = time.time()

        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw  = socket.create_connection((ip, port), timeout=timeout)
            sock = ctx.wrap_socket(raw, server_hostname=sni)
        else:
            sock = socket.create_connection((ip, port), timeout=timeout)

        # WS upgrade request
        ws_key = "dGhlIHNhbXBsZSBub25jZQ=="
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        sock.sendall(req.encode())
        sock.settimeout(min(timeout, 3))
        resp = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                resp += chunk
                if b"\r\n\r\n" in resp: break
        except Exception:
            pass

        lat = int((time.time() - t0) * 1000)
        resp_str = resp.decode(errors='ignore')

        if "101" in resp_str and "websocket" in resp_str.lower():
            # WS handshake accepted — measure throughput with ping frame
            t_dl = time.time()
            total_bytes = 0
            # Send WS ping frame
            ping = b'\x89\x00'  # FIN+PING, 0 payload
            try:
                sock.sendall(ping)
                pong = sock.recv(256)
                total_bytes = len(pong)
            except Exception:
                pass
            dl_time = time.time() - t_dl
            kbps = int((total_bytes / max(dl_time, 0.001)) / 1024) if total_bytes else 0

            result = {
                "works":      True,
                "lat_ms":     lat,
                "speed_kbps": kbps,
                "ws_key_ok":  "Sec-WebSocket-Accept" in resp_str,
                "path":       path,
            }
        elif any(c in resp_str for c in ["200","301","302"]):
            # HTTP response (no WS) — port is open but WS not accepted
            result["lat_ms"] = lat
        sock.close()
    except Exception:
        pass
    return result


def test_grpc_transport(ip: str, port: int, sni: str,
                        timeout: float = 5.0) -> Dict:
    """
    gRPC over HTTP/2 test.
    Sends minimal HTTP/2 preface + HEADERS frame.
    Checks for gRPC response (grpc-status header).
    """
    result = {"works": False, "lat_ms": None, "h2_ok": False,
              "grpc_status": None, "speed_kbps": None}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        # Request HTTP/2 via ALPN
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception:
            pass

        t0   = time.time()
        raw  = socket.create_connection((ip, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=sni)
        lat_tls = int((time.time() - t0) * 1000)

        alpn = sock.selected_alpn_protocol() if hasattr(sock, "selected_alpn_protocol") else ""
        h2_ok = (alpn == "h2")

        # HTTP/2 client preface
        h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        # SETTINGS frame (empty)
        settings_frame = struct.pack(">I", 0)[1:] + b'\x04\x00\x00\x00\x00\x00'

        sock.sendall(h2_preface + settings_frame)
        sock.settimeout(min(timeout, 3))

        resp = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
                resp += chunk
                if len(resp) >= 24: break  # Got server preface
        except Exception:
            pass

        lat = int((time.time() - t0) * 1000)

        # HTTP/2 server preface starts with SETTINGS frame
        # Frame type 0x04 = SETTINGS
        grpc_works = False
        if len(resp) >= 9:
            frame_type = resp[3] if len(resp) > 3 else 0
            if frame_type == 0x04:  # SETTINGS frame
                grpc_works = True

        # Now send actual gRPC test request
        if grpc_works:
            headers_payload = (
                b'\x82'                                    # :method: POST
                + b'\x86'                                  # :scheme: https
                + b'\x44\x0f/grpc.health.v1.Health/Check' # :path
                + b'\x41\x0a' + sni.encode()[:10]         # :authority
                + b'\x5f\x06application/grpc'             # content-type
            )
            # HEADERS frame: length(3) type(1) flags(1) stream_id(4) payload
            hlen = len(headers_payload)
            h_frame = (
                struct.pack(">I", hlen)[1:]  # 3-byte length
                + b'\x01'                     # type=HEADERS
                + b'\x04'                     # END_HEADERS flag
                + b'\x00\x00\x00\x01'         # stream_id=1
                + headers_payload
            )
            try:
                sock.sendall(h_frame)
                sock.settimeout(min(timeout, 2))
                resp2 = b""
                t_dl  = time.time()
                while True:
                    c = sock.recv(4096)
                    if not c: break
                    resp2 += c
                    if len(resp2) >= 512: break
                dl_lat = int((time.time() - t_dl) * 1000)
                kbps = int((len(resp2) / max((time.time()-t_dl), 0.001)) / 1024)

                result = {
                    "works":      True,
                    "lat_ms":     lat,
                    "h2_ok":      h2_ok,
                    "grpc_status": "responded",
                    "speed_kbps": kbps,
                    "alpn":       alpn or "none",
                }
            except Exception:
                result = {
                    "works":  True,
                    "lat_ms": lat,
                    "h2_ok":  h2_ok,
                    "grpc_status": "preface-ok",
                    "speed_kbps": 0,
                }
        sock.close()
    except Exception:
        pass
    return result


def test_splithttp_transport(ip: str, port: int, sni: str,
                             timeout: float = 5.0) -> Dict:
    """
    SplitHTTP / XHTTP transport test.
    Sends chunked HTTP/1.1 GET then POST.
    Checks for streaming response.
    """
    result = {"works": False, "lat_ms": None, "speed_kbps": None,
              "chunked": False}

    paths = ["/xhttp", "/splithttp", "/stream", "/h", "/xh"]

    for path in paths:
        try:
            use_tls = port in [443, 8443, 2053, 2083, 2087, 2096]
            t0 = time.time()

            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw  = socket.create_connection((ip, port), timeout=timeout)
                sock = ctx.wrap_socket(raw, server_hostname=sni)
            else:
                sock = socket.create_connection((ip, port), timeout=timeout)

            # Chunked GET (download leg of SplitHTTP)
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {sni}\r\n"
                f"Connection: keep-alive\r\n"
                f"Accept: */*\r\n"
                f"User-Agent: Mozilla/5.0\r\n\r\n"
            )
            sock.sendall(req.encode())
            sock.settimeout(min(timeout, 3))

            resp = b""
            t_dl = time.time()
            try:
                while True:
                    c = sock.recv(4096)
                    if not c: break
                    resp += c
                    if len(resp) >= 8192: break
            except Exception:
                pass

            lat      = int((time.time() - t0) * 1000)
            dl_time  = time.time() - t_dl
            kbps     = int((len(resp) / max(dl_time, 0.001)) / 1024)
            resp_str = resp.decode(errors='ignore')

            # SplitHTTP typically returns 200 with Transfer-Encoding: chunked
            # or a streaming response
            if "200" in resp_str[:20]:
                chunked = "chunked" in resp_str.lower()
                result = {
                    "works":      True,
                    "lat_ms":     lat,
                    "speed_kbps": kbps,
                    "chunked":    chunked,
                    "path":       path,
                }
                sock.close()
                return result

            sock.close()
        except Exception:
            pass

    return result


def test_httpupgrade_transport(ip: str, port: int, sni: str,
                               timeout: float = 5.0) -> Dict:
    """
    HTTPUpgrade transport test.
    Uses HTTP/1.1 Upgrade header to switch to custom protocol.
    """
    result = {"works": False, "lat_ms": None, "speed_kbps": None}

    paths = ["/", "/up", "/http", "/upgrade"]

    for path in paths:
        try:
            use_tls = port in [443, 8443, 2053, 2083, 2087, 2096]
            t0 = time.time()

            if use_tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw  = socket.create_connection((ip, port), timeout=timeout)
                sock = ctx.wrap_socket(raw, server_hostname=sni)
            else:
                sock = socket.create_connection((ip, port), timeout=timeout)

            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {sni}\r\n"
                f"Connection: Upgrade\r\n"
                f"Upgrade: websocket\r\n"
                f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"User-Agent: Mozilla/5.0\r\n\r\n"
            )
            sock.sendall(req.encode())
            sock.settimeout(min(timeout, 3))

            resp = b""
            t_dl = time.time()
            try:
                while True:
                    c = sock.recv(4096)
                    if not c: break
                    resp += c
                    if b"\r\n\r\n" in resp: break
            except Exception:
                pass

            lat      = int((time.time() - t0) * 1000)
            resp_str = resp.decode(errors='ignore')
            kbps     = int((len(resp) / max(time.time()-t_dl, 0.001)) / 1024)

            if "101" in resp_str or "200" in resp_str[:15]:
                result = {
                    "works":      True,
                    "lat_ms":     lat,
                    "speed_kbps": kbps,
                    "path":       path,
                }
                sock.close()
                return result

            sock.close()
        except Exception:
            pass

    return result


def test_tcp_tls_transport(ip: str, port: int, sni: str,
                           timeout: float = 5.0) -> Dict:
    """
    Plain TCP + TLS transport test (raw data tunnel).
    Measures pure TLS throughput.
    """
    result = {"works": False, "lat_ms": None, "speed_kbps": None}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        t0   = time.time()
        raw  = socket.create_connection((ip, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=sni)
        lat_connect = int((time.time() - t0) * 1000)

        # Send HTTP/1.0 GET to measure raw throughput
        req = f"GET / HTTP/1.0\r\nHost: {sni}\r\nConnection: close\r\n\r\n".encode()
        sock.sendall(req)
        sock.settimeout(min(timeout, 4))

        t_dl   = time.time()
        total  = 0
        LIMIT  = 256 * 1024  # 256KB
        try:
            while True:
                c = sock.recv(8192)
                if not c: break
                total += len(c)
                if total >= LIMIT: break
        except Exception:
            pass

        elapsed = time.time() - t_dl
        lat     = int((time.time() - t0) * 1000)
        kbps    = int((total / max(elapsed, 0.001)) / 1024)
        sock.close()

        if total > 0:
            result = {
                "works":      True,
                "lat_ms":     lat,
                "speed_kbps": kbps,
                "bytes_recv": total,
            }
    except Exception:
        pass
    return result


# ================================================================
#  SH-2: Transport Speed Benchmark (per IP)
# ================================================================
def benchmark_all_transports(ip: str, sni: str, ports: List[int],
                              timeout: float = 5.0,
                              isp_profile: dict = None) -> Dict:
    """
    Given an IP + SNI, test ALL transports across relevant ports.
    Returns ranked results with winner.
    """
    results = {
        "ip":          ip,
        "sni":         sni,
        "transports":  {},
        "winner":      None,
        "winner_score": 0,
    }

    # Use ISP-specific ports if available
    tls_ports   = (isp_profile or {}).get("tls_ports",   [443, 8443, 2053])
    plain_ports  = (isp_profile or {}).get("plain_ports", [80, 8080])
    test_ports   = [p for p in ports if p in tls_ports + plain_ports]
    if not test_ports:
        test_ports = ports[:4]

    # ── gRPC (TLS ports only) ─────────────────────────────────────
    for port in tls_ports:
        if port not in test_ports: continue
        r = test_grpc_transport(ip, port, sni, timeout)
        if r["works"]:
            key = f"gRPC:{port}"
            score = _transport_score(r)
            results["transports"][key] = {**r, "score": score, "port": port}
            if score > results["winner_score"]:
                results["winner"]       = key
                results["winner_score"] = score
            break  # Found working gRPC — stop

    # ── WS+TLS (TLS ports) ────────────────────────────────────────
    ws_paths = ["/", "/ws", "/ray", "/v2ray", "/xray", "/vmess"]
    for port in tls_ports:
        if port not in test_ports: continue
        for path in ws_paths:
            r = test_ws_transport(ip, port, sni, path, timeout)
            if r["works"]:
                key = f"WS+TLS:{port}{path}"
                score = _transport_score(r)
                results["transports"][key] = {**r, "score": score, "port": port}
                if score > results["winner_score"]:
                    results["winner"]       = key
                    results["winner_score"] = score
                break
        else:
            continue
        break

    # ── WS plain (plain ports including Mobitel special ports) ────
    for port in plain_ports:
        if port not in test_ports: continue
        for path in ["/", "/ws", "/ray"]:
            r = test_ws_transport(ip, port, sni, path, timeout)
            if r["works"]:
                key = f"WS:{port}{path}"
                score = _transport_score(r) - 5  # slight penalty for plain
                results["transports"][key] = {**r, "score": score, "port": port}
                if score > results["winner_score"]:
                    results["winner"]       = key
                    results["winner_score"] = score
                break

    # ── SplitHTTP ─────────────────────────────────────────────────
    for port in tls_ports[:2]:
        if port not in test_ports: continue
        r = test_splithttp_transport(ip, port, sni, timeout)
        if r["works"]:
            key = f"SplitHTTP:{port}"
            score = _transport_score(r)
            results["transports"][key] = {**r, "score": score, "port": port}
            if score > results["winner_score"]:
                results["winner"]       = key
                results["winner_score"] = score
            break

    # ── HTTPUpgrade ───────────────────────────────────────────────
    for port in tls_ports[:2]:
        if port not in test_ports: continue
        r = test_httpupgrade_transport(ip, port, sni, timeout)
        if r["works"]:
            key = f"HTTPUpgrade:{port}"
            score = _transport_score(r)
            results["transports"][key] = {**r, "score": score, "port": port}
            if score > results["winner_score"]:
                results["winner"]       = key
                results["winner_score"] = score
            break

    # ── TCP+TLS (fallback) ────────────────────────────────────────
    for port in [443, 8443]:
        if port not in test_ports: continue
        r = test_tcp_tls_transport(ip, port, sni, timeout)
        if r["works"]:
            key = f"TCP+TLS:{port}"
            score = _transport_score(r) - 10  # lower priority
            results["transports"][key] = {**r, "score": score, "port": port}
            if score > results["winner_score"]:
                results["winner"]       = key
                results["winner_score"] = score
            break

    return results


def _transport_score(r: dict) -> int:
    """Composite score: lower latency + higher speed = better."""
    score = 0
    lat   = r.get("lat_ms", 9999) or 9999
    kbps  = r.get("speed_kbps", 0) or 0

    # Latency score (0–50)
    if lat < 50:   score += 50
    elif lat < 100: score += 40
    elif lat < 200: score += 30
    elif lat < 400: score += 20
    elif lat < 800: score += 10

    # Speed score (0–50)
    if kbps > 5000:  score += 50
    elif kbps > 2000: score += 40
    elif kbps > 1000: score += 30
    elif kbps > 500:  score += 20
    elif kbps > 100:  score += 10
    elif kbps > 0:    score += 5

    return score


# ================================================================
#  SH-1: IP Range Speed Scanner
# ================================================================
def scan_ip_range(cidr: str, sni: str, ports: List[int],
                  timeout: float = 3.0,
                  max_ips: int = 50,
                  threads: int = 30) -> List[Dict]:
    """
    Scan all IPs in CIDR range.
    Returns latency-sorted list of responsive IPs.
    max_ips: sample size (skip IPs after this many found responsive)
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    all_ips = [str(ip) for ip in network.hosts()]
    # Sample evenly if range is large
    if len(all_ips) > max_ips * 4:
        step   = len(all_ips) // (max_ips * 4)
        all_ips = all_ips[::step][:max_ips * 4]

    results     = []
    found_count = [0]
    lock        = threading.Lock()
    primary_port = ports[0] if ports else 443

    def _probe(ip):
        lat = test_latency(ip, primary_port, timeout)
        if lat is not None:
            tls_r = {}
            if primary_port in [443, 8443, 2053, 2083, 2087, 2096]:
                tls_r = test_tls_handshake(ip, primary_port, sni, timeout)
            with lock:
                results.append({
                    "ip":        ip,
                    "lat_ms":    lat,
                    "tls_ok":    tls_r.get("ok", False),
                    "tls_lat":   tls_r.get("lat_ms"),
                    "tls_ver":   tls_r.get("tls_ver"),
                    "cn":        tls_r.get("cn",""),
                    "port":      primary_port,
                })
                found_count[0] += 1

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_probe, ip): ip for ip in all_ips}
        done = 0
        total = len(all_ips)
        for fut in as_completed(futs):
            done += 1
            if done % 20 == 0:
                with plock:
                    f   = int(40 * done / total)
                    bar = G + "█"*f + DIM + "░"*(40-f) + W
                    sys.stdout.write(
                        f"\r  [{bar}] {Y}{done}/{total}{W} "
                        f"found:{G}{found_count[0]}{W}  ")
                    sys.stdout.flush()
            # Stop early if we have enough
            if found_count[0] >= max_ips:
                for f2 in futs:
                    f2.cancel()
                break

    print()
    return sorted(results, key=lambda x: (x["lat_ms"] or 9999))


def run_ip_range_hunter(range_name: str,
                        sni: str = None,
                        isp_key: str = "Unknown",
                        timeout: float = 3.0,
                        max_ips: int = 30,
                        threads: int = 40,
                        do_transport_test: bool = True) -> List[Dict]:
    """
    Full IP range hunt:
    1. Scan range for responsive IPs
    2. Latency rank
    3. Transport benchmark on top IPs
    """
    if range_name not in IP_RANGE_DB:
        print(R + f"  [-] Unknown range: {range_name}" + W)
        return []

    db      = IP_RANGE_DB[range_name]
    sni     = sni or db["sni"]
    ports   = db["ports"]
    ranges  = db["ranges"]
    isp_prf = ISP_PROFILES.get(isp_key, ISP_PROFILES["Unknown"])

    all_responsive = []
    for cidr in ranges:
        print(C + f"\n  Scanning {cidr} (sni:{sni})..." + W)
        responsive = scan_ip_range(
            cidr, sni, ports, timeout, max_ips // len(ranges) + 5, threads)
        all_responsive.extend(responsive)
        print(G + f"  ✔ {len(responsive)} responsive IPs in {cidr}" + W)

    if not all_responsive:
        print(R + "  [-] No responsive IPs found." + W)
        return []

    # Sort by latency, take top IPs
    all_responsive.sort(key=lambda x: x["lat_ms"] or 9999)
    top_ips = all_responsive[:10]

    if do_transport_test:
        print(C + f"\n  Transport benchmark on top {len(top_ips)} IPs...\n" + W)
        for i, ip_res in enumerate(top_ips):
            ip = ip_res["ip"]
            print(C + f"  [{i+1}/{len(top_ips)}] {ip} ({ip_res['lat_ms']}ms)..." + W,
                  end=" ", flush=True)
            bench = benchmark_all_transports(ip, sni, ports, timeout, isp_prf)
            ip_res["transport_bench"] = bench
            winner = bench.get("winner", "none")
            wscore = bench.get("winner_score", 0)
            wcolor = G if wscore >= 50 else (Y if wscore >= 30 else R)
            print(f"winner={wcolor}{winner}{W} score={wscore}")

    return top_ips


# ================================================================
#  SH-4: Best Host Finder
#  SNI candidates × ISP × port × transport matrix
# ================================================================
def find_best_host(sni_list: List[str],
                   isp_key: str = "Unknown",
                   timeout: float = 5.0,
                   threads: int = 20) -> List[Dict]:
    """
    Test each SNI candidate across ISP ports + all transports.
    Returns ranked list of (sni, ip, port, transport, score).
    """
    isp_prf  = ISP_PROFILES.get(isp_key, ISP_PROFILES["Unknown"])
    all_ports = isp_prf["ports"][:8]  # limit for speed
    results   = []
    lock      = threading.Lock()

    def _test_one(sni, port):
        try:
            ip = socket.gethostbyname(sni)
        except Exception:
            return

        # Quick latency check first
        lat = test_latency(ip, port, timeout=min(timeout, 2))
        if lat is None:
            return

        # Transport tests
        bench = benchmark_all_transports(ip, sni, [port], timeout, isp_prf)
        if bench["winner"]:
            with lock:
                results.append({
                    "sni":       sni,
                    "ip":        ip,
                    "port":      port,
                    "lat_ms":    lat,
                    "winner":    bench["winner"],
                    "score":     bench["winner_score"],
                    "transports": bench["transports"],
                })

    tasks = [(sni, port) for sni in sni_list for port in all_ports]
    total = len(tasks)
    done  = [0]

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_test_one, sni, port): (sni, port)
                for sni, port in tasks}
        for fut in as_completed(futs):
            done[0] += 1
            f   = int(40 * done[0] / total)
            bar = G + "█"*f + DIM + "░"*(40-f) + W
            with plock:
                sys.stdout.write(
                    f"\r  [{bar}] {Y}{done[0]}/{total}{W}  "
                    f"found:{G}{len(results)}{W}   ")
                sys.stdout.flush()
    print()

    return sorted(results, key=lambda x: x["score"], reverse=True)


# ================================================================
#  SH-5: Config Generator
#  Generates 3x-ui / Xray / v2rayNG configs
# ================================================================
def _parse_transport_key(winner: str) -> Tuple[str, int, str]:
    """Parse 'gRPC:443' → ('gRPC', 443, '/')"""
    parts = winner.split(":")
    if len(parts) >= 2:
        transport = parts[0]
        rest      = parts[1]
        port_path = rest.split("/", 1)
        port = int(port_path[0]) if port_path[0].isdigit() else 443
        path = "/" + port_path[1] if len(port_path) > 1 else "/"
        return transport, port, path
    return winner, 443, "/"


def generate_3xui_config(ip: str, sni: str, isp_key: str,
                         transport_key: str,
                         uuid: str = None,
                         server_addr: str = None) -> dict:
    """
    Generate complete 3x-ui inbound config.
    Returns dict with panel_settings + share_link.
    """
    import uuid as _uuid
    uid        = uuid or str(_uuid.uuid4())
    srv        = server_addr or ip
    transport, port, path = _parse_transport_key(transport_key)
    isp_prf    = ISP_PROFILES.get(isp_key, ISP_PROFILES["Unknown"])
    use_tls    = port in isp_prf.get("tls_ports", [443, 8443])

    # Transport mapping
    transport_clean = transport.split("+")[0]  # "WS+TLS" → "WS"
    net_map = {
        "gRPC":        "grpc",
        "WS":          "ws",
        "WS+TLS":      "ws",
        "SplitHTTP":   "splithttp",
        "HTTPUpgrade": "httpupgrade",
        "TCP+TLS":     "tcp",
    }
    network = net_map.get(transport, "ws")

    config = {
        "remark":         f"{sni}-{transport_clean}-{port}",
        "protocol":       "vless",
        "port":           port,
        "network":        network,
        "security":       "tls" if use_tls else "none",
        "sni":            sni,
        "fingerprint":    "chrome",
        "allow_insecure": True,
        "address":        srv,
        "uuid":           uid,
    }

    # Transport-specific settings
    if network == "grpc":
        config["grpc_service_name"] = "grpc"
        config["grpc_mode"]         = "multi"
    elif network in ["ws", "httpupgrade", "splithttp"]:
        config["path"]      = path
        config["ws_host"]   = sni
    elif network == "tcp":
        config["tcp_type"]  = "http"

    # Generate v2rayNG / NekoBox share link
    import base64
    params = {
        "security":    "tls" if use_tls else "none",
        "sni":         sni,
        "fp":          "chrome",
        "type":        network,
        "allowInsecure": "1",
    }
    if network == "grpc":
        params["serviceName"] = "grpc"
        params["mode"]        = "multi"
    elif network in ["ws", "httpupgrade", "splithttp"]:
        params["path"] = path
        params["host"] = sni

    param_str  = "&".join(f"{k}={v}" for k, v in params.items())
    share_link = (
        f"vless://{uid}@{srv}:{port}"
        f"?{param_str}"
        f"#{sni}-{transport_clean}"
    )

    config["share_link"]    = share_link
    config["isp"]           = isp_key
    config["isp_notes"]     = isp_prf.get("notes", "")
    config["transport_key"] = transport_key

    return config


def format_3xui_panel(config: dict) -> str:
    """Format config as 3x-ui panel display."""
    net  = config["network"]
    use_tls = config["security"] == "tls"
    lines = [
        f"\n  {'─'*60}",
        f"  {G}{BOLD}★ {config['remark']}{W}",
        f"  {'─'*60}",
        f"  {C}Protocol   :{W} VLESS",
        f"  {C}Address    :{W} {G}{config['address']}{W}",
        f"  {C}Port       :{W} {Y}{config['port']}{W}",
        f"  {C}UUID       :{W} {DIM}{config['uuid']}{W}",
        f"  {C}Network    :{W} {config['network'].upper()}",
        f"  {C}Security   :{W} {'TLS' if use_tls else 'none'}",
        f"  {C}SNI        :{W} {config['sni']}",
        f"  {C}Fingerprint:{W} chrome",
        f"  {C}ISP Target :{W} {config['isp']}",
    ]
    if net == "grpc":
        lines += [
            f"  {C}gRPC Mode  :{W} multi",
            f"  {C}ServiceName:{W} grpc",
        ]
    elif net in ["ws","httpupgrade","splithttp"]:
        lines += [
            f"  {C}Path       :{W} {config.get('path','/')}",
            f"  {C}Host Header:{W} {config.get('ws_host','')}",
        ]

    lines += [
        f"  {'─'*60}",
        f"  {C}Share Link :{W}",
        f"  {Y}{config['share_link']}{W}",
        f"  {'─'*60}",
        f"  {DIM}{config.get('isp_notes','')}{W}",
    ]

    if config.get("allow_insecure"):
        lines.append(f"  {Y}[!] allowInsecure=true (assessment only){W}")

    return "\n".join(lines)


# ================================================================
#  Menu Functions — Speed Hunter UI
# ================================================================
def _banner_sh():
    print(f"""
{C}╔══════════════════════════════════════════════════════════╗
║  {G}{BOLD}SNI SPEED HUNTER{C}  v1.0  {DIM}★ IP Range + ISP Config{C}         ║
║  {DIM}IP-Scan | Transport-Bench | ISP-Profile | Config-Gen{C}    ║
╚══════════════════════════════════════════════════════════╝{W}
{Y}  [!] Security Assessment Tool — Research use only{W}
""")


def menu_ip_range_scan(timeout=4.0):
    """Interactive IP Range Scanner menu."""
    _banner_sh()
    print(G+BOLD+"  SH-1: IP Range Speed Scanner\n"+W)

    print(C+"  Available ranges:\n"+W)
    for i, (key, val) in enumerate(IP_RANGE_DB.items(), 1):
        ranges_str = ", ".join(val["ranges"][:2])
        print(f"  {Y}[{i}]{W} {G}{key:<22}{W} {DIM}{val['service']:<30}{W} {ranges_str}")

    print(f"\n  {Y}[A]{W} Custom CIDR range")
    print(f"  {Y}[B]{W} All ranges (comprehensive scan)\n")

    ch = input(C+"  Choice: "+W).strip().lower()

    # ISP selection
    print(C+"\n  Target ISP:\n"+W)
    for i, (key, val) in enumerate(ISP_PROFILES.items(), 1):
        if key == "Unknown": continue
        print(f"  {Y}[{i}]{W} {G}{key:<12}{W} {DIM}{val['notes'][:50]}{W}")
    isp_ch = input(C+"\n  ISP (1-4, Enter=Unknown): "+W).strip()
    isp_keys = [k for k in ISP_PROFILES if k != "Unknown"]
    try:
        isp_key = isp_keys[int(isp_ch)-1]
    except Exception:
        isp_key = "Unknown"

    max_ip_s = input(Y+f"  Max IPs per range [30]: "+W).strip()
    max_ips  = int(max_ip_s) if max_ip_s.isdigit() else 30
    do_bench = input(Y+"  Transport benchmark on top IPs? (Y/n): "+W).strip().lower() != 'n'

    range_keys = []
    if ch == 'a':
        cidr = input(Y+"  CIDR (e.g. 170.114.52.0/24): "+W).strip()
        sni  = input(Y+"  SNI host (e.g. zoom.us): "+W).strip()
        # Temp add to DB
        IP_RANGE_DB["_custom"] = {
            "ranges": [cidr], "sni": sni, "ports": [443,80,8080], "service": "Custom"
        }
        range_keys = ["_custom"]
    elif ch == 'b':
        range_keys = list(IP_RANGE_DB.keys())
    else:
        try:
            range_keys = [list(IP_RANGE_DB.keys())[int(ch)-1]]
        except Exception:
            print(R+"  [-] Invalid choice"+W)
            return

    all_results = []
    for rk in range_keys:
        print(G+f"\n  ── Scanning: {rk} ──\n"+W)
        r = run_ip_range_hunter(
            rk, isp_key=isp_key, timeout=timeout,
            max_ips=max_ips, do_transport_test=do_bench)
        all_results.extend(r)

    # Display results
    _display_ip_results(all_results, isp_key)

    # Config generation
    if all_results:
        server = input(Y+"\n  VPS Server IP/domain (for config): "+W).strip()
        if server:
            uid = input(Y+"  UUID (Enter=auto-generate): "+W).strip() or None
            _generate_configs_from_results(all_results[:3], isp_key, server, uid)

    input(Y+"\n  Enter ඔබන්න..."+W)


def menu_best_host_finder(timeout=5.0):
    """Interactive Best Host Finder menu."""
    _banner_sh()
    print(G+BOLD+"  SH-4: Best Host Finder\n"+W)

    # ISP selection
    print(C+"  Target ISP:\n"+W)
    isp_list = [k for k in ISP_PROFILES if k != "Unknown"]
    for i, k in enumerate(isp_list, 1):
        print(f"  {Y}[{i}]{W} {G}{k:<12}{W} ports: "
              f"{', '.join(str(p) for p in ISP_PROFILES[k]['ports'][:5])}")
    print(f"  {Y}[5]{W} {G}All ISPs{W}")

    isp_ch = input(C+"\n  ISP choice: "+W).strip()
    try:
        isp_key = isp_list[int(isp_ch)-1] if int(isp_ch) <= 4 else "Unknown"
    except Exception:
        isp_key = "Unknown"

    isp_prf = ISP_PROFILES.get(isp_key, ISP_PROFILES["Unknown"])
    print(C+f"\n  Zero-rated SNI candidates for {isp_key}:\n"+W)
    for i, sni in enumerate(isp_prf["zero_rated_snis"], 1):
        print(f"  {i}. {sni}")

    print(f"\n  {Y}[A]{W} Use above list")
    print(f"  {Y}[B]{W} Custom SNI list")

    snich = input(C+"\n  Choice (A/B): "+W).strip().lower()
    if snich == 'b':
        raw  = input(Y+"  Enter SNIs (comma separated): "+W).strip()
        snis = [s.strip() for s in raw.split(",") if s.strip()]
    else:
        snis = isp_prf["zero_rated_snis"]

    if not snis:
        print(R+"  [-] No SNIs given."+W)
        input(Y+"\n  Enter..."+W); return

    print(G+f"\n  Testing {len(snis)} SNIs × {len(isp_prf['ports'][:8])} ports...\n"+W)
    results = find_best_host(snis, isp_key, timeout)

    if not results:
        print(R+"  [-] No working hosts found."+W)
        input(Y+"\n  Enter..."+W); return

    # Display
    print(G+BOLD+f"\n  ★ BEST HOSTS FOUND ({len(results)})\n"+W)
    print(C+f"  {'SNI':<35} {'IP':<18} {'PORT':>5} {'TRANSPORT':<20} {'SCORE':>6}"+W)
    print(C+"  "+"─"*90+W)
    for r in results[:15]:
        sc_clr = G+BOLD if r['score']>=60 else (Y if r['score']>=30 else R)
        print(f"  {G}{r['sni']:<35}{W} {Y}{r['ip']:<18}{W} "
              f"{C}{r['port']:>5}{W} {B}{r['winner']:<20}{W} "
              f"{sc_clr}{r['score']:>5}{W}")

    # Config gen
    if results:
        server = input(Y+"\n  VPS Server IP/domain: "+W).strip()
        uid    = input(Y+"  UUID (Enter=auto): "+W).strip() or None
        if server:
            best = results[0]
            cfg  = generate_3xui_config(
                best["ip"], best["sni"], isp_key,
                best["winner"], uid, server)
            print(format_3xui_panel(cfg))

            # All working transports
            print(G+BOLD+"\n  All Working Transports:\n"+W)
            for tk, tv in best.get("transports", {}).items():
                alt_cfg = generate_3xui_config(
                    best["ip"], best["sni"], isp_key, tk, uid, server)
                print(Y+f"  ── {tk} (score:{tv.get('score',0)}) ──"+W)
                print(C+f"  {alt_cfg['share_link']}{W}\n")

    input(Y+"\n  Enter ඔබන්න..."+W)


def menu_isp_config_generator():
    """Generate ISP-specific configs without scanning."""
    _banner_sh()
    print(G+BOLD+"  SH-5: ISP Config Generator\n"+W)

    print(C+"  ISP Selection:\n"+W)
    isp_list = [k for k in ISP_PROFILES if k != "Unknown"]
    for i, k in enumerate(isp_list, 1):
        prf = ISP_PROFILES[k]
        print(f"  {Y}[{i}]{W} {G}{k:<12}{W} {DIM}{prf['notes'][:55]}{W}")
    print(f"  {Y}[5]{W} All ISPs")

    isp_ch = input(C+"\n  ISP: "+W).strip()
    try:
        isp_keys = isp_list if isp_ch == '5' else [isp_list[int(isp_ch)-1]]
    except Exception:
        isp_keys = ["Unknown"]

    sni    = input(Y+"  Bug host / SNI (e.g. zoom.us): "+W).strip()
    ip     = input(Y+"  Bug host IP (Enter=auto resolve): "+W).strip()
    server = input(Y+"  VPS Server IP/domain: "+W).strip()
    uid    = input(Y+"  UUID (Enter=auto): "+W).strip() or None

    if not sni or not server:
        print(R+"  [-] SNI and Server required."+W)
        input(Y+"\n  Enter..."+W); return

    if not ip:
        try:
            ip = socket.gethostbyname(sni)
            print(G+f"  Resolved: {sni} → {ip}"+W)
        except Exception:
            ip = sni

    for isp_key in isp_keys:
        prf = ISP_PROFILES.get(isp_key, ISP_PROFILES["Unknown"])
        print(G+BOLD+f"\n  ═══ {isp_key} Configs ═══"+W)
        print(DIM+f"  {prf['notes']}"+W)
        print(Y+f"  Zero-rated SNIs: {', '.join(prf['zero_rated_snis'][:4])}"+W)

        # Generate config for each best transport × port combo
        transports_to_try = prf.get("best_transport", ["gRPC", "WS+TLS"])

        port_map = {
            "gRPC":        prf["tls_ports"][:2],
            "WS+TLS":      prf["tls_ports"][:2],
            "WS":          prf["plain_ports"][:2],
            "SplitHTTP":   prf["tls_ports"][:1],
            "HTTPUpgrade": prf["tls_ports"][:1],
            "TCP+TLS":     [443],
        }

        # Special Mobitel ports
        if isp_key == "Mobitel":
            port_map["WS"] = [2060, 2086, 80]

        for tr in transports_to_try:
            tr_base = tr.split(" ")[0]  # "WS (port 2060)" → "WS"
            ports   = port_map.get(tr_base, prf["tls_ports"][:1])
            for port in ports[:2]:
                tk  = f"{tr_base}:{port}"
                cfg = generate_3xui_config(ip, sni, isp_key, tk, uid, server)
                print(format_3xui_panel(cfg))

    input(Y+"\n  Enter ඔබන්න..."+W)


def menu_transport_benchmark():
    """Benchmark all transports for a specific IP."""
    _banner_sh()
    print(G+BOLD+"  SH-2: Transport Speed Benchmark\n"+W)

    host    = input(Y+"  Host/IP to benchmark: "+W).strip()
    sni_raw = input(Y+"  SNI (Enter=same as host): "+W).strip()
    sni     = sni_raw or host

    isp_list = [k for k in ISP_PROFILES if k != "Unknown"]
    for i, k in enumerate(isp_list, 1):
        print(f"  {Y}[{i}]{W} {k}")
    isp_ch = input(Y+"  ISP (1-4, Enter=Unknown): "+W).strip()
    try:
        isp_key = isp_list[int(isp_ch)-1]
    except Exception:
        isp_key = "Unknown"

    isp_prf = ISP_PROFILES.get(isp_key, ISP_PROFILES["Unknown"])

    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = host

    print(G+f"\n  Benchmarking {ip} (sni:{sni}) for {isp_key}...\n"+W)
    ports = isp_prf["ports"][:6]
    bench = benchmark_all_transports(ip, sni, ports, timeout=5.0, isp_profile=isp_prf)

    print(G+BOLD+f"\n  TRANSPORT BENCHMARK RESULTS — {ip}\n"+W)
    print(C+f"  {'TRANSPORT':<25} {'LAT':>6} {'SPEED':>10} {'SCORE':>7}"+W)
    print(C+"  "+"─"*55+W)

    for tk, tv in sorted(bench["transports"].items(),
                          key=lambda x: x[1].get("score",0), reverse=True):
        lat   = tv.get("lat_ms")
        kbps  = tv.get("speed_kbps",0) or 0
        score = tv.get("score",0)
        lat_s  = f"{lat}ms" if lat else "—"
        kbps_s = f"{kbps}Kbps" if kbps else "—"
        sc_clr = G+BOLD if score>=60 else (Y if score>=30 else R)
        print(f"  {C}{tk:<25}{W} {Y}{lat_s:>6}{W} {G}{kbps_s:>10}{W} "
              f"{sc_clr}{score:>6}{W}")

    winner = bench.get("winner")
    if winner:
        print(G+BOLD+f"\n  ★ WINNER: {winner} (score:{bench['winner_score']})\n"+W)

        server = input(Y+"  VPS Server for config (Enter=skip): "+W).strip()
        if server:
            uid = input(Y+"  UUID (Enter=auto): "+W).strip() or None
            cfg = generate_3xui_config(ip, sni, isp_key, winner, uid, server)
            print(format_3xui_panel(cfg))

    input(Y+"\n  Enter ඔබන්න..."+W)


def _display_ip_results(results: List[Dict], isp_key: str):
    """Display IP scan results table."""
    if not results:
        print(R+"  [-] No results."+W); return

    print(G+BOLD+f"\n  ★ IP RANGE SCAN RESULTS — {isp_key}\n"+W)
    print(C+f"  {'IP':<18} {'LAT':>6} {'TLS':>5} {'TLS-LAT':>8} "
          f"{'WINNER TRANSPORT':<25} {'SCORE':>6}"+W)
    print(C+"  "+"─"*75+W)

    for r in results[:15]:
        lat_s   = f"{r['lat_ms']}ms" if r.get('lat_ms') else "—"
        tls_s   = G+"✔"+W if r.get('tls_ok') else R+"✘"+W
        tls_lat = f"{r['tls_lat']}ms" if r.get('tls_lat') else "—"
        bench   = r.get("transport_bench", {})
        winner  = bench.get("winner", "—")
        score   = bench.get("winner_score", 0)
        sc_clr  = G+BOLD if score>=60 else (Y if score>=30 else R)
        print(f"  {G}{r['ip']:<18}{W} {Y}{lat_s:>6}{W} {tls_s} "
              f"{Y}{tls_lat:>8}{W} {B}{winner:<25}{W} {sc_clr}{score:>5}{W}")


def _generate_configs_from_results(results: List[Dict], isp_key: str,
                                   server: str, uid: str = None):
    """Generate 3x-ui configs from top IP results."""
    print(G+BOLD+"\n  ★ GENERATED CONFIGS\n"+W)
    for r in results:
        bench  = r.get("transport_bench", {})
        winner = bench.get("winner")
        if not winner:
            continue
        sni  = r.get("sni", "zoom.us")
        ip   = r["ip"]
        cfg  = generate_3xui_config(ip, sni, isp_key, winner, uid, server)
        print(format_3xui_panel(cfg))

        # Also show alternatives
        alts = {k: v for k, v in bench.get("transports",{}).items()
                if k != winner and v.get("score",0) > 20}
        if alts:
            print(Y+f"  Alternative links:\n"+W)
            for tk in list(alts.keys())[:2]:
                alt = generate_3xui_config(ip, sni, isp_key, tk, uid, server)
                print(C+f"  [{tk}]"+W)
                print(Y+f"  {alt['share_link']}\n"+W)


# ================================================================
#  Standalone Main Menu
# ================================================================
def run_speed_hunter_menu(timeout=5.0):
    """Main Speed Hunter menu — call from sni_bug_finder.py or standalone."""
    while True:
        _banner_sh()
        print(Y+"  ┌──────────────────────────────────────────────┐"+W)
        print(Y+"  │         SPEED HUNTER MENU  v1.0              │"+W)
        print(Y+"  ├──────────────────────────────────────────────┤"+W)
        print(Y+"  │  "+W+"[1]  IP Range Speed Scanner              "+Y+"  │"+W)
        print(Y+"  │  "+W+"[2]  Transport Speed Benchmark (per IP)  "+Y+"  │"+W)
        print(Y+"  │  "+W+"[3]  Best Host Finder (SNI × ISP matrix) "+Y+"  │"+W)
        print(Y+"  │  "+W+"[4]  ISP Config Generator                "+Y+"  │"+W)
        print(Y+"  │  "+W+"[5]  ISP Profile Info                    "+Y+"  │"+W)
        print(Y+"  │  "+W+"[6]  Back / Exit                         "+Y+"  │"+W)
        print(Y+"  └──────────────────────────────────────────────┘\n"+W)

        ch = input(C+"  Choice (1-6): "+W).strip()
        if   ch == '1': menu_ip_range_scan(timeout)
        elif ch == '2': menu_transport_benchmark()
        elif ch == '3': menu_best_host_finder(timeout)
        elif ch == '4': menu_isp_config_generator()
        elif ch == '5': _show_isp_profiles()
        elif ch == '6': break
        else: print(R+"  [-] 1-6 ඇතුලත් කරන්න."+W); time.sleep(1)


def _show_isp_profiles():
    _banner_sh()
    print(G+BOLD+"  ISP PROFILES\n"+W)
    for isp_key, prf in ISP_PROFILES.items():
        if isp_key == "Unknown": continue
        print(G+BOLD+f"  ── {isp_key} ──"+W)
        print(C+f"  Name    : {prf['name']}"+W)
        print(C+f"  Ports   : {', '.join(str(p) for p in prf['ports'])}"+W)
        print(C+f"  TLS     : {', '.join(str(p) for p in prf['tls_ports'])}"+W)
        if prf.get("special_ports"):
            for sp_port, sp_note in prf["special_ports"].items():
                print(Y+f"  ★ Port {sp_port}: {sp_note}"+W)
        print(C+f"  Zero-SNI: {', '.join(prf['zero_rated_snis'][:5])}"+W)
        print(Y+f"  Best    : {', '.join(prf['best_transport'])}"+W)
        print(DIM+f"  Notes   : {prf['notes']}"+W)
        print()
    input(Y+"  Enter ඔබන්න..."+W)


if __name__ == "__main__":
    run_speed_hunter_menu()
