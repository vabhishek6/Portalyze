#!/usr/bin/env python3
"""
Portalyze - Enterprise-Grade Async Port Scanner
Version: 1.3

Description:
------------
Portalyze is an advanced asynchronous TCP port scanner designed for authorized security
assessments, network diagnostics, and training purposes.

Key Features:
-------------
- Asynchronous non-blocking scanning with asyncio
- Custom ports via --ports (lists and ranges) or full range via --max-port
- Service banner discovery for common ports (HTTP, FTP, SSH, generic)
- Rate limiting for controlled concurrency
- Results and error logging to files
- Local IP detection
- Proxy environment variable awareness

Usage:
------
python3 portalyze.py <host> [options]

Legal Notice:
-------------
Use of this tool without authorization is illegal in many jurisdictions.
Obtain explicit written permission before scanning any system.
"""

import asyncio
import socket
import os
import sys
import time
import logging
import argparse
import re

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    Fore = Style = type('', (), {'RESET_ALL': '', 'RED': '', 'GREEN': '', 'YELLOW': '', 'CYAN': '', 'MAGENTA': '', 'BLUE': ''})()

# Configure logging
logging.basicConfig(filename="portalyze_errors.log",
                    level=logging.ERROR,
                    format="%(asctime)s %(levelname)s %(message)s")

logo = """\

8888888b.                888           888                         
888   Y88b               888           888                         
888    888               888           888                         
888   d88P .d88b. 888d888888888 8888b. 888888  88888888888 .d88b.  
8888888P" d88""88b888P"  888       "88b888888  888   d88P d8P  Y8b 
888       888  888888    888   .d888888888888  888  d88P  88888888 
888       Y88..88P888    Y88b. 888  888888Y88b 888 d88P   Y8b.     
888        "Y88P" 888     "Y888"Y888888888 "Y8888888888888 "Y8888  
                                               888                 
                                          Y8b d88P                 
                                           "Y88P"                  
"""

# -------------------- Validation & Utilities --------------------

def validate_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except Exception:
        print(Fore.RED + "Error: Invalid host or IP address." + Style.RESET_ALL)
        sys.exit(1)

def validate_port(port: int) -> int:
    if not (1 <= port <= 65535):
        print(Fore.RED + "Error: Port number must be between 1 and 65535." + Style.RESET_ALL)
        sys.exit(1)
    return port

def parse_port_list(port_str: str):
    """
    Parses a string like '22,80,443,1000-1010' into sorted unique port integers.
    """
    ports = set()
    port_pattern = re.compile(r'^\d+$')
    range_pattern = re.compile(r'^(\d+)-(\d+)$')

    for item in port_str.split(','):
        item = item.strip()
        if port_pattern.match(item):
            p = int(item)
            if 1 <= p <= 65535:
                ports.add(p)
            else:
                raise ValueError(f"Invalid port number: {item}")
        elif range_pattern.match(item):
            start, end = map(int, range_pattern.match(item).groups())
            if 1 <= start <= end <= 65535:
                ports.update(range(start, end+1))
            else:
                raise ValueError(f"Invalid port range: {item}")
        else:
            raise ValueError(f"Invalid port format: {item}")
    return sorted(ports)

def get_local_ip() -> str:
    """Determine local IP address in OS-agnostic way."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()

# -------------------- Banner Grabbing --------------------

async def grab_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> str:
    banner = "No banner"
    try:
        if port in (80, 8080):  # HTTP
            request = b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            writer.write(request)
            await writer.drain()
            data = await reader.read(1024)
            if data:
                banner = data.decode(errors='replace').split('\r\n')[0]
        elif port == 21:  # FTP
            data = await reader.read(1024)
            if data:
                banner = data.decode(errors='replace').strip()
        elif port == 22:  # SSH
            data = await reader.read(1024)
            if data:
                banner = data.decode(errors='replace').strip()
        else:
            writer.write(b"Hello\r\n")
            await writer.drain()
            data = await reader.read(1024)
            if data:
                banner = data.decode(errors='replace').strip()
    except Exception as e:
        logging.error(f"Banner grab error on port {port}: {e}")
    return banner

# -------------------- Scanning Logic --------------------

async def scan_port(semaphore, host: str, port: int, results: list, proxy=None):
    async with semaphore:
        try:
            if proxy:
                logging.info(f"Proxy detected for environment: {proxy} (Not used for connection)")
            
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=1)
            banner = await grab_banner(reader, writer, port)
            results.append(f"Port {port:5}: OPEN | {banner}")
            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass
        except Exception as e:
            logging.error(f"Unexpected error on port {port}: {e}")

async def main_scan(target: str, ports: list, rate_limit: int, proxy=None):
    semaphore = asyncio.Semaphore(rate_limit)
    results = []
    tasks = [scan_port(semaphore, target, p, results, proxy) for p in ports]
    await asyncio.gather(*tasks)
    return results

def save_results(results: list, filename="portalyze_results.txt"):
    with open(filename, "w") as f:
        f.write("\n".join(results))

# -------------------- CLI Parsing --------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Portalyze - Enterprise Async Port Scanner")
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--max-port", type=int, default=1024,
                        help="Maximum TCP port number to scan (default: 1024)")
    parser.add_argument("--ports", type=str,
                        help="Comma-separated list of ports and/or ranges (e.g., 22,80,443,1000-1010)")
    parser.add_argument("-r", "--rate-limit", type=int, default=100,
                        help="Maximum concurrent scans (default: 100)")
    parser.add_argument("-o", "--output", default="portalyze_results.txt",
                        help="File to save results (default: portalyze_results.txt)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    if args.ports:
        try:
            args.port_list = parse_port_list(args.ports)
        except ValueError as ve:
            print(Fore.RED + f"Error parsing ports: {ve}" + Style.RESET_ALL)
            sys.exit(1)
    else:
        args.max_port = validate_port(args.max_port)
        args.port_list = list(range(1, args.max_port + 1))
    return args

# -------------------- Main --------------------

def main():
    args = parse_args()

    if args.no_color:
        global Fore, Style
        Fore = Style = type('', (), {'RESET_ALL': '', 'RED': '', 'GREEN': '', 'YELLOW': '', 'CYAN': '', 'MAGENTA': '', 'BLUE': ''})()

    print(Fore.CYAN + LOGO + Style.RESET_ALL)
    print(Fore.MAGENTA + "Portalyze - Advanced Async Port Scanner for Authorized Security Testing\n" + Style.RESET_ALL)

    target = validate_host(args.host)
    ports_to_scan = args.port_list
    rate_limit = args.rate_limit
    output_file = args.output

    # Environment checks
    local_ip = get_local_ip()
    print(Fore.CYAN + f"Local IP detected: {local_ip}" + Style.RESET_ALL)

    proxy = os.environ.get("HTTP_PROXY") or os.environ.get("HTTPS_PROXY")
    if proxy:
        print(Fore.CYAN + f"Proxy detected in environment: {proxy} (Note: not used for scanning)" + Style.RESET_ALL)

    print(Fore.MAGENTA +
          f"\nScanning {target} on ports: {','.join(map(str, ports_to_scan))} "
          f"with concurrency {rate_limit}...\n" + Style.RESET_ALL)

    start_time = time.time()
    try:
        results = asyncio.run(main_scan(target, ports_to_scan, rate_limit, proxy))
    except KeyboardInterrupt:
        print(Fore.RED + "\nScan interrupted by user." + Style.RESET_ALL)
        sys.exit(1)

    elapsed = time.time() - start_time
    print(Fore.GREEN + f"\nScan complete in {elapsed:.2f} seconds.\n" + Style.RESET_ALL)

    if results:
        for line in results:
            print(line)
        save_results(results, filename=output_file)
        print(Fore.CYAN + f"\nResults saved to {output_file}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "No open ports detected." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
