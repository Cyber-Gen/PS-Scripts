#!/usr/bin/env python3
"""Single-host recon: nmap + gobuster (HTTP/HTTPS) + optional vhost scan."""

import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

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
    print(
        f"Warning: no wordlist found locally; falling back to {fallback} (gobuster may fail)",
        file=sys.stderr,
    )
    return fallback


def run_cmd(cmd, *, dry_run=False, capture=False):
    """Run a command. Log invocation, warn on non-zero exit, never raise."""
    print(f"[run] {' '.join(cmd)}")
    if dry_run:
        return None
    kwargs = {"text": True, "check": False}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        print(
            f"[warn] {cmd[0]} exited with status {result.returncode}",
            file=sys.stderr,
        )
    return result


def run_nmap_scan(target_ip, scan_type, nmap_format, output_dir, dry_run):
    nmap_dir = output_dir / "Nmap"
    if not dry_run:
        nmap_dir.mkdir(parents=True, exist_ok=True)

    base_name = "full_scan" if scan_type == "Full" else "basic_scan"
    port_args = ["-p-"] if scan_type == "Full" else ["-p", "1-1000"]

    if nmap_format == "all":
        output_args = ["-oA", str(nmap_dir / base_name)]
        # -oA produces .nmap (normal/human-readable) — best source for a text report.
        report_source = nmap_dir / f"{base_name}.nmap"
    else:
        output_args = ["-oX", str(nmap_dir / f"{base_name}.xml")]
        report_source = nmap_dir / f"{base_name}.xml"

    cmd = ["nmap", "-A", "-T4", *port_args, "-sV", *output_args, target_ip]
    run_cmd(cmd, dry_run=dry_run)
    return report_source


def run_gobuster(target_ip, wordlist, output_dir, dry_run):
    gobuster_dir = output_dir / "Gobuster"
    if not dry_run:
        gobuster_dir.mkdir(parents=True, exist_ok=True)

    http_out = gobuster_dir / "http_dir_scan.txt"
    https_out = gobuster_dir / "https_dir_scan.txt"

    http_cmd = ["gobuster", "dir", "-u", f"http://{target_ip}", "-w", wordlist, "-o", str(http_out)]
    https_cmd = ["gobuster", "dir", "-u", f"https://{target_ip}", "-w", wordlist, "-o", str(https_out)]

    run_cmd(http_cmd, dry_run=dry_run)
    run_cmd(https_cmd, dry_run=dry_run)
    return http_out, https_out


# Matches grepable nmap Ports line entries like "80/open/tcp" or "443/open/tcp".
# Anchored on "Ports:" so banner text containing the word "open" won't false-match.
_PORT_OPEN_RE = re.compile(r"\bPorts:.*\b(?:80|443)/open\b")


def web_ports_open(target_ip, dry_run):
    """Probe target for ports 80/443. Returns True if at least one is open."""
    if dry_run:
        print(f"[dry-run] would probe {target_ip} for ports 80,443; assuming OPEN")
        return True
    cmd = ["nmap", "-p", "80,443", "-oG", "-", target_ip]
    result = run_cmd(cmd, capture=True)
    if result is None or result.returncode != 0:
        return False
    return bool(_PORT_OPEN_RE.search(result.stdout or ""))


def run_virtual_host_scan(target_ip, output_dir, dry_run):
    nmap_dir = output_dir / "Nmap"
    if not dry_run:
        nmap_dir.mkdir(parents=True, exist_ok=True)
    vhost_out = nmap_dir / "virtual_hosts.txt"

    cmd = ["nmap", "-p", "80,443", "--script=http-vhosts", target_ip, "-oN", str(vhost_out)]
    run_cmd(cmd, dry_run=dry_run)
    return vhost_out


def generate_report(sources, output_dir, dry_run):
    """Aggregate sub-scan outputs into a timestamped combined report.

    sources: iterable of (section_title, path_or_None). Missing files are noted
    in the report rather than crashing the run.
    """
    report_dir = output_dir / "Results"
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_path = report_dir / f"report-{timestamp}.txt"

    if dry_run:
        print(f"[dry-run] would write combined report: {report_path}")
        for title, path in sources:
            print(f"  - section '{title}' from {path}")
        return

    report_dir.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as report_file:
        for title, path in sources:
            report_file.write(f"\n=== {title} ===\n")
            if path is None or not Path(path).exists():
                report_file.write(f"(no output produced: {path})\n")
                continue
            with open(path, "r") as src:
                report_file.write(src.read())
    print(f"[ok] combined report written: {report_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Single-host recon: nmap + gobuster (HTTP/HTTPS) + optional vhost scan.",
    )
    parser.add_argument("target_ip", help="The target IP address or hostname to scan")
    parser.add_argument("scan_type", choices=["Full", "Basic"], help="Scan type")
    parser.add_argument("--wordlist", help="Path to gobuster wordlist")
    parser.add_argument(
        "--nmap-format",
        choices=["xml", "all"],
        default="all",
        help="nmap output format: 'all' uses -oA (.nmap/.gnmap/.xml), 'xml' uses -oX. Default: all",
    )
    parser.add_argument(
        "--report",
        choices=["none", "combined"],
        default="combined",
        help="Aggregate scan output into a single timestamped report. Default: combined",
    )
    parser.add_argument(
        "--vhost",
        choices=["always", "auto", "never"],
        default="auto",
        help="When to run the http-vhosts script. 'auto' probes 80/443 first. Default: auto",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Root directory for Nmap/, Gobuster/, Results/ subdirs. Default: CWD",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands that would run; do not execute scans or write outputs",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    wordlist = resolve_wordlist(args.wordlist)

    nmap_report_source = run_nmap_scan(
        args.target_ip, args.scan_type, args.nmap_format, output_dir, args.dry_run
    )
    http_out, https_out = run_gobuster(args.target_ip, wordlist, output_dir, args.dry_run)

    vhost_out = None
    if args.vhost == "always":
        vhost_out = run_virtual_host_scan(args.target_ip, output_dir, args.dry_run)
    elif args.vhost == "auto":
        if web_ports_open(args.target_ip, args.dry_run):
            vhost_out = run_virtual_host_scan(args.target_ip, output_dir, args.dry_run)
        else:
            print("[info] ports 80/443 not open; skipping vhost scan")

    if args.report == "combined":
        sources = [
            ("Nmap Scan Results", nmap_report_source),
            ("Gobuster HTTP Results", http_out),
            ("Gobuster HTTPS Results", https_out),
        ]
        if vhost_out is not None:
            sources.append(("Virtual Host Scan Results", vhost_out))
        generate_report(sources, output_dir, args.dry_run)


if __name__ == "__main__":
    main()
