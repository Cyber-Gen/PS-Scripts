"""DEPRECATED: merged into autorec.py (2026-05-24).

This script is kept for reference only. All functionality — multi-format nmap
output (-oA) and conditional vhost scanning, plus dynamic wordlist discovery,
requirements checks, concurrent sub-scans, per-target output isolation, and
multi-target mode — now lives in PS-Scripts/python/autorec.py. See
AUTOREC_PLAN.md for the consolidation notes.

Equivalent invocation on the new script:
    python3 autorec.py <target_ip> {Full|Basic} --report none
"""

import argparse
import subprocess
import os

WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

def resolve_wordlist(cli_arg):
    if cli_arg:
        if not os.path.exists(cli_arg):
            raise SystemExit(f"Error: wordlist not found: {cli_arg}")
        return cli_arg
    for candidate in WORDLIST_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    fallback = WORDLIST_CANDIDATES[0]
    print(f"Warning: no wordlist found locally; falling back to {fallback} (gobuster may fail)")
    return fallback

def run_nmap_scan(target_ip, scan_type):
    nmap_output_dir = "Nmap"
    os.makedirs(nmap_output_dir, exist_ok=True)

    if scan_type == "Full":
        nmap_command = ["nmap", "-A", "-T4", "-p-", "-sV", "-oA", f"{nmap_output_dir}/full_scan", target_ip]
    elif scan_type == "Basic":
        nmap_command = ["nmap", "-A", "-T4", "-p", "1-1000", "-sV", "-oA", f"{nmap_output_dir}/basic_scan", target_ip]
    else:
        print("Invalid scan type. Use 'Full' or 'Basic'")
        return

    subprocess.run(nmap_command)

def run_gobuster(target_ip, wordlist):
    gobuster_output_dir = "Gobuster"
    os.makedirs(gobuster_output_dir, exist_ok=True)

    gobuster_http_command = ["gobuster", "dir", "-u", f"http://{target_ip}", "-w", wordlist, "-o", f"{gobuster_output_dir}/http_dir_scan.txt"]
    gobuster_https_command = ["gobuster", "dir", "-u", f"https://{target_ip}", "-w", wordlist, "-o", f"{gobuster_output_dir}/https_dir_scan.txt"]

    subprocess.run(gobuster_http_command)
    subprocess.run(gobuster_https_command)

def run_virtual_host_scan(target_ip):
    nmap_output_dir = "Nmap"
    virtual_host_output = os.path.join(nmap_output_dir, "virtual_hosts.txt")

    nmap_command = ["nmap", "-p", "80,443", "--script=http-vhosts", target_ip, "-oN", virtual_host_output]
    subprocess.run(nmap_command)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a target IP address with Nmap and Gobuster")
    parser.add_argument("target_ip", help="The target IP address to scan")
    parser.add_argument("scan_type", choices=["Full", "Basic"], help="Scan type: 'Full' or 'Basic'")
    parser.add_argument("--wordlist", help="Path to gobuster wordlist")
    args = parser.parse_args()

    wordlist = resolve_wordlist(args.wordlist)

    run_nmap_scan(args.target_ip, args.scan_type)
    run_gobuster(args.target_ip, wordlist)

    # Check if port 80 or 443 is open before running the virtual host scan
    open_ports_command = ["nmap", "-p", "80,443", args.target_ip]
    open_ports_result = subprocess.run(open_ports_command, stdout=subprocess.PIPE, text=True)
    if "open" in open_ports_result.stdout and ("80/tcp" in open_ports_result.stdout or "443/tcp" in open_ports_result.stdout):
        run_virtual_host_scan(args.target_ip)
