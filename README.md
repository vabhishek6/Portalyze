# Portalyze

Portalyze is an enterprise-grade, asynchronous TCP port scanner written in Python 3.  
It is designed for **authorized security testing**, **network diagnostics**, and **educational purposes**, providing high-performance scanning, service banner detection, and configurable options suitable for both manual and automated workflows.

---

## Overview

Portalyze uses Python's `asyncio` to perform **non-blocking concurrent scans** of multiple TCP ports.  
It can operate on sequential ranges or user-specified custom port lists/ranges, making it well-suited for penetration testing, vulnerability assessments, or network inventory projects within authorized environments.

Results are displayed in real time and can be logged to output files for reporting and further analysis.

---

## Features

- **Asynchronous Scanning** – High-speed scanning using `asyncio` for optimal efficiency.
- **Custom Port Selection** – Supports sequential ranges (`--max-port`) or explicit lists/ranges (`--ports`).
- **Rate Limiting** – Limits concurrency (`--rate-limit`) to avoid overloading target systems.
- **Service Banner Grabbing** – Attempts to identify services for common ports (HTTP, FTP, SSH, generic).
- **Logging** – Saves successfully identified ports to results file; errors to a separate log file.
- **Local IP Detection** – Automatically shows the local IP address.
- **Proxy Environment Awareness** – Detects HTTP/HTTPS proxies from environment variables (informational).
- **Non-Interactive CLI** – Fully scriptable for automation in enterprise workflows.

---

## Legal Notice

Portalyze is provided **solely** for:

- **Authorized security testing** where you have **explicit written permission**.
- **Educational and training** activities in controlled environments.

> **Unauthorized use of this tool may be illegal.**  
> Performing network scans without permission can violate laws such as the *Computer Fraud and Abuse Act* (U.S.) or similar legislation in other countries.  
> The authors and maintainers accept **no liability** for any misuse.  
> Always ensure compliance with applicable laws, contracts, and organizational policies.

---

## Requirements

- Python **3.7+**
- `colorama` for colored CLI output

Install dependencies:

```
pip install -r requirements.txt
```

---

## Command Line Usage

```
python3 portalyze.py  [options]
```

**Positional Arguments:**

| Argument | Description |
|----------|-------------|
| `host`   | Target hostname or IP address |

**Optional Arguments:**

| Option | Description | Default |
|--------|-------------|---------|
| `-p`, `--max-port` `` | Maximum TCP port number to scan | 1024 |
| `--ports` `"list/range"` | Comma-separated list and/or ranges (e.g., `22,80,443,1000-1010`) | None |
| `-r`, `--rate-limit` `` | Maximum concurrent scans | 100 |
| `-o`, `--output` `` | File to save results | `portalyze_results.txt` |
| `--no-color` | Disable colored terminal output | Off |

---

## Examples

**1. Scan ports 1–500 on a host with concurrency of 50 connections:**
```
python3 portalyze.py scanme.nmap.org --max-port 500 --rate-limit 50
```

**2. Scan only specific ports (22, 80, 443, and range 8080–8090):**
```
python3 portalyze.py scanme.nmap.org --ports "22,80,443,8080-8090"
```

**3. Full TCP scan with output saved to `fullscan.txt`:**
```
python3 portalyze.py 192.168.1.10 -p 65535 -o fullscan.txt
```

**4. Run without colored console output (good for logging pipelines):**
```
python3 portalyze.py 192.168.1.10 --no-color
```

---

## Output

### Example Console Output:
```
Local IP detected: 192.168.0.15
Scanning scanme.nmap.org on ports: 22,80,443,8080-8090 with concurrency 50...

Port    22 : OPEN | SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
Port    80 : OPEN | HTTP/1.1 200 OK
Port   443 : OPEN | HTTP/1.1 400 Bad Request

Scan complete in 5.27 seconds.

Results saved to portalyze_results.txt
```

**Files Created:**
- `portalyze_results.txt` – List of open ports and identified banners
- `portalyze_errors.log` – Connection and banner grab error details

---

## Licensing

Portalyze is distributed under the **MIT License**.  
You are free to use, modify, and distribute it in compliance with the license terms.

---

