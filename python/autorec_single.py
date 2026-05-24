"""DEPRECATED: merged into autorec.py (2026-05-24).

This script is kept for reference only. All functionality — combined report
output, plus dynamic wordlist discovery, requirements checks, concurrent
sub-scans, per-target output isolation, and multi-target mode — now lives in
PS-Scripts/python/autorec.py. See AUTOREC_PLAN.md for the consolidation notes.

Equivalent invocation on the new script:
    python3 autorec.py <target_ip> {Full|Basic} \\
        --nmap-format xml --report combined --vhost always
"""

import argparse
import subprocess
import os
import time

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
        nmap_output_file = f"{nmap_output_dir}/full_scan.xml"
        nmap_command = ["nmap", "-A", "-T4", "-p-", "-sV", "-oX", nmap_output_file, target_ip]
    elif scan_type == "Basic":
        nmap_output_file = f"{nmap_output_dir}/basic_scan.xml"
        nmap_command = ["nmap", "-A", "-T4", "-p", "1-1000", "-sV", "-oX", nmap_output_file, target_ip]
    else:
        print("Invalid scan type. Use 'Full' or 'Basic'")
        return

    subprocess.run(nmap_command)
    return nmap_output_file

def run_gobuster(target_ip, wordlist):
    gobuster_output_dir = "Gobuster"
    os.makedirs(gobuster_output_dir, exist_ok=True)

    gobuster_http_output_file = f"{gobuster_output_dir}/http_dir_scan.txt"
    gobuster_https_output_file = f"{gobuster_output_dir}/https_dir_scan.txt"

    gobuster_http_command = ["gobuster", "dir", "-u", f"http://{target_ip}", "-w", wordlist, "-o", gobuster_http_output_file]
    gobuster_https_command = ["gobuster", "dir", "-u", f"https://{target_ip}", "-w", wordlist, "-o", gobuster_https_output_file]

    subprocess.run(gobuster_http_command)
    subprocess.run(gobuster_https_command)

    return gobuster_http_output_file, gobuster_https_output_file

def run_virtual_host_scan(target_ip):
    nmap_output_dir = "Nmap"
    virtual_host_output = os.path.join(nmap_output_dir, "virtual_hosts.txt")

    nmap_command = ["nmap", "-p", "80,443", "--script=http-vhosts", target_ip, "-oN", virtual_host_output]
    subprocess.run(nmap_command)
    return virtual_host_output

def generate_report(nmap_output_file, gobuster_http_output_file, gobuster_https_output_file, virtual_host_output):
    report_dir = "Results"
    os.makedirs(report_dir, exist_ok=True)

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_filename = f"report-{timestamp}.txt"

    with open(f"{report_dir}/{report_filename}", "w") as report_file:
        if nmap_output_file:
            with open(nmap_output_file, "r") as nmap_file:
                report_file.write("=== Nmap Scan Results ===\n")
                report_file.write(nmap_file.read())

        if gobuster_http_output_file:
            with open(gobuster_http_output_file, "r") as gobuster_http_file:
                report_file.write("\n=== Gobuster HTTP Results ===\n")
                report_file.write(gobuster_http_file.read())

        if gobuster_https_output_file:
            with open(gobuster_https_output_file, "r") as gobuster_https_file:
                report_file.write("\n=== Gobuster HTTPS Results ===\n")
                report_file.write(gobuster_https_file.read())

        if virtual_host_output:
            with open(virtual_host_output, "r") as virtual_host_file:
                report_file.write("\n=== Virtual Host Scan Results ===\n")
                report_file.write(virtual_host_file.read())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a target IP address with Nmap and Gobuster")
    parser.add_argument("target_ip", help="The target IP address to scan")
    parser.add_argument("scan_type", choices=["Full", "Basic"], help="Scan type: 'Full' or 'Basic'")
    parser.add_argument("--wordlist", help="Path to gobuster wordlist")
    args = parser.parse_args()

    wordlist = resolve_wordlist(args.wordlist)

    nmap_output_file = run_nmap_scan(args.target_ip, args.scan_type)
    gobuster_http_output_file, gobuster_https_output_file = run_gobuster(args.target_ip, wordlist)
    virtual_host_output = run_virtual_host_scan(args.target_ip)

    generate_report(nmap_output_file, gobuster_http_output_file, gobuster_https_output_file, virtual_host_output)
