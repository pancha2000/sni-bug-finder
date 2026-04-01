# 🔍 SNI Bug Host Finder v2.0

A powerful multi-threaded SNI bug host scanner for educational and research purposes.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🚀 Multi-threading | Up to 50 threads — ඉක්මනින් ස්කෑන් |
| 🔐 SNI/TLS Check | SSL handshake + SNI mismatch detection |
| 🌐 3 Subdomain Sources | HackerTarget + CRT.sh + AlienVault OTX |
| 🛡️ CDN Detection | Cloudflare, Akamai, Fastly, AWS, Azure, GCP |
| 📊 Bug Score | 0–100% probability scoring |
| 💾 Save Results | TXT + JSON reports auto-saved |
| 🎨 Colorful UI | Terminal color-coded output |

---

## 📦 Installation

```bash
git clone https://github.com/yourname/sni-bug-finder
cd sni-bug-finder
pip install requests
```

---

## 🚀 Usage

```bash
python3 sni_bug_finder.py
```

### Menu Options:
1. **Domain Scan** — Subdomains discovery + full SNI scan
2. **Single Host Check** — Check one host in detail
3. **Exit**

---

## 🔬 How Bug Score Works

| Score | Meaning |
|---|---|
| 70–100% | ★ Strong Bug Host candidate |
| 40–69%  | ⚠ Possible Bug Host |
| 0–39%   | ✘ Likely not a Bug Host |

### Score factors:
- HTTP 200 OK → +30 pts
- HTTPS 200 OK → +20 pts
- SNI/TLS works → +25 pts
- SNI Mismatch detected → +15 pts (key indicator!)
- CDN detected (Cloudflare etc.) → +10 pts

---

## 📁 Output Files

After scan, results saved to `results_<domain>_<timestamp>/`:

```
bug_hosts.txt          ← Bug host list (plain)
sni_valid_hosts.txt    ← SNI working hosts + TLS info
full_report.json       ← Complete JSON report
```

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**.  
Do not use against systems you don't own or have permission to test.  
The author is not responsible for misuse.

---

## 📋 Requirements

- Python 3.7+
- `requests` library

```bash
pip install requests
```
