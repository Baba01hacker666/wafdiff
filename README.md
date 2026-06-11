# WafDiff

![WafDiff](https://img.shields.io/badge/Made%20by-baba01hacker-blue)
![Python](https://img.shields.io/badge/Python-3.6%2B-green)

**WafDiff** is an advanced security tool designed to find blind spots in Web Application Firewalls (WAF). It detects inconsistent blocking behavior by sending the exact same payload through multiple different paths/endpoints and comparing the HTTP status codes and response lengths.

Made by **baba01hacker**.

## Features
- **Inconsistency Detection:** Automatically groups and compares responses, loudly flagging any path that bypasses the global WAF rule.
- **High-Speed Threading:** Uses thread pooling to execute massive path/payload matrices in seconds.
- **Pre-loaded Payload Arsenal:** Comes with built-in default payloads for SQLi, XSS, LFI, and RCE, or supply your own.
- **Evasion Tactics:** Supports SOCKS/HTTP proxies, SSL bypass, custom headers, User-Agent rotation, and rate-limiting delays.

## Installation
```bash
pip install wafdiff
```
Or from source:
```bash
git clone https://github.com/baba01hacker/wafdiff.git
cd wafdiff
pip install .
```

## Usage
```bash
wafdiff -u https://target.com -p / /api /login /admin --payloads "' OR 1=1 --" "<script>alert(1)</script>"
```

### Options
- `-u`, `--url`: Target Base URL
- `-p`, `--paths`: List of paths to test (default includes `/`, `/api/`, `/login`, etc.)
- `--payloads`: Custom payloads to push through the WAF
- `-m`, `--method`: HTTP Method (GET or POST)
- `-x`, `--proxy`: Proxy your traffic
- `-t`, `--threads`: Number of concurrent workers (default 5)
