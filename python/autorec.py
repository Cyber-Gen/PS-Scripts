#!/usr/bin/env python3
"""Recon driver: nmap + gobuster (HTTP/HTTPS) + optional vhost scan.

Supports one or many targets, dynamic wordlist discovery, requirement checks,
concurrent sub-scans, and per-target output isolation.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Optional


REQUIRED_TOOLS: tuple[str, ...] = ("nmap", "gobuster")

TOOL_INSTALL_HINTS: dict[str, str] = {
    "nmap": "apt install nmap   |   brew install nmap",
    "gobuster": "apt install gobuster   |   brew install gobuster",
}

# Roots searched when --wordlist is not provided. Missing roots are skipped silently.
WORDLIST_SEARCH_ROOTS: tuple[Path, ...] = (
    Path("/usr/share/wordlists"),
    Path("/usr/share/seclists"),
    Path("/usr/share/dirb"),
    Path("/usr/share/dirbuster"),
    Path("/opt/SecLists"),
    Path("/opt/wordlists"),
    Path.home() / "wordlists",
    Path.home() / "SecLists",
)

# Preference order — first match wins. Smaller lists first so initial recon is fast;
# user can override with --wordlist for exhaustive sweeps.
WORDLIST_PREFERENCES: tuple[str, ...] = (
    "common.txt",
    "directory-list-2.3-small.txt",
    "directory-list-lowercase-2.3-small.txt",
    "raft-small-directories.txt",
    "directory-list-2.3-medium.txt",
    "directory-list-lowercase-2.3-medium.txt",
    "raft-medium-directories.txt",
    "big.txt",
)

# Grepable nmap "Ports:" entries — anchored so the literal word "open" elsewhere
# in nmap output (banners, hostnames) cannot false-match.
_PORT_OPEN_RE = re.compile(r"\bPorts:.*?\b(?:80|443)/open\b")

# Filesystem-safe target slug (keep letters, digits, dot, dash, underscore).
_TARGET_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------

def check_requirements(dry_run: bool) -> None:
    """Verify required CLI tools are on PATH. Exit (or warn under --dry-run) on misses."""
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if not missing:
        return

    lines = ["Missing required tools:"]
    for tool in missing:
        hint = TOOL_INSTALL_HINTS.get(tool, "consult your package manager")
        lines.append(f"  - {tool}   (install: {hint})")

    if dry_run:
        for line in lines:
            print(f"[dry-run][warn] {line}", file=sys.stderr)
        return
    raise SystemExit("\n".join(lines))


# ---------------------------------------------------------------------------
# Wordlist discovery
# ---------------------------------------------------------------------------

def discover_wordlists(extra_roots: Iterable[Path] = ()) -> dict[str, Path]:
    """Walk known wordlist roots; return basename → first non-empty Path found."""
    found: dict[str, Path] = {}
    for root in (*WORDLIST_SEARCH_ROOTS, *extra_roots):
        if not root.is_dir():
            continue
        try:
            for path in root.rglob("*.txt"):
                try:
                    if path.is_file() and path.stat().st_size > 0:
                        found.setdefault(path.name, path)
                except OSError:
                    continue
        except OSError:
            continue
    return found


def resolve_wordlist(cli_arg: Optional[str], extra_roots: Iterable[Path] = ()) -> Path:
    """Resolve a wordlist path: explicit --wordlist > preferences > smallest available."""
    if cli_arg:
        path = Path(cli_arg)
        if not path.is_file():
            raise SystemExit(f"Error: wordlist not found: {cli_arg}")
        if path.stat().st_size == 0:
            raise SystemExit(f"Error: wordlist is empty: {cli_arg}")
        return path

    available = discover_wordlists(extra_roots)
    for preferred in WORDLIST_PREFERENCES:
        if preferred in available:
            chosen = available[preferred]
            print(f"[info] wordlist: {chosen}")
            return chosen

    if available:
        smallest = min(available.values(), key=lambda p: p.stat().st_size)
        print(f"[info] no preferred wordlist matched; using smallest available: {smallest}")
        return smallest

    raise SystemExit(
        "Error: no wordlist found in standard locations and none provided.\n"
        "  Install one: apt install seclists wordlists\n"
        "  Or fetch:    https://github.com/danielmiessler/SecLists\n"
        "  Or pass:     --wordlist /path/to/list.txt"
    )


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def run_cmd(
    cmd: list[str],
    *,
    dry_run: bool = False,
    capture: bool = False,
    label: str = "",
) -> Optional[subprocess.CompletedProcess]:
    """Log + run a command. Warn (don't raise) on non-zero exit. Returns None in dry-run."""
    prefix = f"[run{':' + label if label else ''}]"
    print(f"{prefix} {' '.join(cmd)}")
    if dry_run:
        return None
    kwargs: dict = {"text": True, "check": False}
    if capture:
        kwargs["stdout"] = subprocess.PIPE
        kwargs["stderr"] = subprocess.PIPE
    try:
        result = subprocess.run(cmd, **kwargs)
    except FileNotFoundError:
        print(f"[error] not found on PATH: {cmd[0]}", file=sys.stderr)
        return None
    if result.returncode != 0:
        print(f"[warn] {cmd[0]} exited with status {result.returncode}", file=sys.stderr)
    return result


# ---------------------------------------------------------------------------
# Scan steps (each returns the path it wrote to, or None)
# ---------------------------------------------------------------------------

def run_nmap_scan(
    target: str,
    scan_type: str,
    nmap_format: str,
    output_dir: Path,
    dry_run: bool,
) -> Path:
    nmap_dir = output_dir / "Nmap"
    if not dry_run:
        nmap_dir.mkdir(parents=True, exist_ok=True)

    base_name = "full_scan" if scan_type == "Full" else "basic_scan"
    port_args = ["-p-"] if scan_type == "Full" else ["-p", "1-1000"]

    if nmap_format == "all":
        output_args = ["-oA", str(nmap_dir / base_name)]
        report_source = nmap_dir / f"{base_name}.nmap"
    else:
        output_args = ["-oX", str(nmap_dir / f"{base_name}.xml")]
        report_source = nmap_dir / f"{base_name}.xml"

    cmd = ["nmap", "-A", "-T4", *port_args, "-sV", *output_args, target]
    run_cmd(cmd, dry_run=dry_run, label="nmap")
    return report_source


def run_gobuster_one(
    scheme: str,
    target: str,
    wordlist: Path,
    output_dir: Path,
    dry_run: bool,
) -> Path:
    gobuster_dir = output_dir / "Gobuster"
    if not dry_run:
        gobuster_dir.mkdir(parents=True, exist_ok=True)
    out = gobuster_dir / f"{scheme}_dir_scan.txt"
    cmd = ["gobuster", "dir", "-u", f"{scheme}://{target}", "-w", str(wordlist), "-o", str(out)]
    run_cmd(cmd, dry_run=dry_run, label=f"gobuster-{scheme}")
    return out


def web_ports_open(target: str, dry_run: bool) -> bool:
    """Probe target ports 80/443 via grepable nmap output. True if at least one is open."""
    if dry_run:
        print(f"[dry-run] would probe {target} for ports 80,443; assuming OPEN")
        return True
    cmd = ["nmap", "-p", "80,443", "-oG", "-", target]
    result = run_cmd(cmd, capture=True, label="probe")
    if result is None or result.returncode != 0:
        return False
    return bool(_PORT_OPEN_RE.search(result.stdout or ""))


def run_virtual_host_scan(target: str, output_dir: Path, dry_run: bool) -> Path:
    nmap_dir = output_dir / "Nmap"
    if not dry_run:
        nmap_dir.mkdir(parents=True, exist_ok=True)
    vhost_out = nmap_dir / "virtual_hosts.txt"
    cmd = ["nmap", "-p", "80,443", "--script=http-vhosts", target, "-oN", str(vhost_out)]
    run_cmd(cmd, dry_run=dry_run, label="vhost")
    return vhost_out


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def generate_report(
    sources: list[tuple[str, Optional[Path]]],
    output_dir: Path,
    dry_run: bool,
) -> None:
    report_dir = output_dir / "Results"
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    report_path = report_dir / f"report-{timestamp}.txt"

    if dry_run:
        print(f"[dry-run] would write combined report: {report_path}")
        for title, path in sources:
            print(f"  - section '{title}' from {path}")
        return

    report_dir.mkdir(parents=True, exist_ok=True)
    with report_path.open("w") as report_file:
        for title, path in sources:
            report_file.write(f"\n=== {title} ===\n")
            if path is None or not path.exists():
                report_file.write(f"(no output produced: {path})\n")
                continue
            try:
                report_file.write(path.read_text())
            except OSError as exc:
                report_file.write(f"(error reading {path}: {exc})\n")
    print(f"[ok] combined report written: {report_path}")


# ---------------------------------------------------------------------------
# Per-target orchestration
# ---------------------------------------------------------------------------

def safe_target_slug(target: str) -> str:
    slug = _TARGET_SAFE_RE.sub("_", target).strip("._-")
    return slug or "target"


def resolve_output_dir(
    target: str,
    output_dir_arg: Optional[str],
    multi_target: bool,
) -> Path:
    """Pick the output root for a single target.

    - Explicit --output-dir: used as-is for one target; nested under <root>/<slug>/ for many.
    - No --output-dir: defaults to ./recon-results/<slug>/.
    """
    slug = safe_target_slug(target)
    if output_dir_arg:
        base = Path(output_dir_arg)
        return base / slug if multi_target else base
    return Path("recon-results") / slug


def scan_target(
    target: str,
    *,
    scan_type: str,
    wordlist: Path,
    nmap_format: str,
    report_mode: str,
    vhost_mode: str,
    output_dir: Path,
    parallel: bool,
    dry_run: bool,
) -> None:
    print(f"\n========== target: {target}  ->  {output_dir} ==========")
    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    # nmap runs first and sequentially — running it concurrently with gobuster
    # would poison the service-version detection with bruteforce traffic.
    nmap_report_source = run_nmap_scan(target, scan_type, nmap_format, output_dir, dry_run)

    # vhost trigger (probe is sequential; vhost itself can run alongside gobuster)
    will_run_vhost = (
        vhost_mode == "always"
        or (vhost_mode == "auto" and web_ports_open(target, dry_run))
    )
    if vhost_mode == "auto" and not will_run_vhost:
        print("[info] ports 80/443 not open; skipping vhost scan")

    http_out: Optional[Path] = None
    https_out: Optional[Path] = None
    vhost_out: Optional[Path] = None

    if parallel:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures: dict[concurrent.futures.Future, str] = {}
            futures[pool.submit(run_gobuster_one, "http", target, wordlist, output_dir, dry_run)] = "http"
            futures[pool.submit(run_gobuster_one, "https", target, wordlist, output_dir, dry_run)] = "https"
            if will_run_vhost:
                futures[pool.submit(run_virtual_host_scan, target, output_dir, dry_run)] = "vhost"
            for fut in concurrent.futures.as_completed(futures):
                tag = futures[fut]
                try:
                    result_path = fut.result()
                except Exception as exc:
                    print(f"[error] {tag} task raised: {exc}", file=sys.stderr)
                    continue
                if tag == "http":
                    http_out = result_path
                elif tag == "https":
                    https_out = result_path
                elif tag == "vhost":
                    vhost_out = result_path
    else:
        http_out = run_gobuster_one("http", target, wordlist, output_dir, dry_run)
        https_out = run_gobuster_one("https", target, wordlist, output_dir, dry_run)
        if will_run_vhost:
            vhost_out = run_virtual_host_scan(target, output_dir, dry_run)

    if report_mode == "combined":
        sources: list[tuple[str, Optional[Path]]] = [
            ("Nmap Scan Results", nmap_report_source),
            ("Gobuster HTTP Results", http_out),
            ("Gobuster HTTPS Results", https_out),
        ]
        if will_run_vhost:
            sources.append(("Virtual Host Scan Results", vhost_out))
        generate_report(sources, output_dir, dry_run)


# ---------------------------------------------------------------------------
# Target list loading
# ---------------------------------------------------------------------------

def load_targets(target_arg: Optional[str], targets_file_arg: Optional[str]) -> list[str]:
    if targets_file_arg:
        targets_path = Path(targets_file_arg)
        if not targets_path.is_file():
            raise SystemExit(f"Error: targets file not found: {targets_file_arg}")
        targets: list[str] = []
        for raw in targets_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
        if not targets:
            raise SystemExit(f"Error: targets file is empty: {targets_file_arg}")
        return targets
    if target_arg:
        return [target_arg]
    raise SystemExit("Error: provide a target_ip or --targets FILE")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recon driver: nmap + gobuster + optional vhost scan, one or many hosts.",
    )
    parser.add_argument(
        "target_ip",
        nargs="?",
        help="Target IP/hostname (omit when using --targets).",
    )
    parser.add_argument(
        "scan_type",
        choices=["Full", "Basic"],
        help="Nmap scan profile.",
    )
    parser.add_argument("--targets", help="File of targets, one per line ('#' = comment).")
    parser.add_argument("--wordlist", help="Path to gobuster wordlist (overrides discovery).")
    parser.add_argument(
        "--wordlist-root",
        action="append",
        default=[],
        help="Extra directory to search for wordlists (repeatable).",
    )
    parser.add_argument(
        "--nmap-format",
        choices=["xml", "all"],
        default="all",
        help="nmap output format: 'all' -> -oA, 'xml' -> -oX. Default: all.",
    )
    parser.add_argument(
        "--report",
        choices=["none", "combined"],
        default="combined",
        help="Aggregate sub-scans into one timestamped report. Default: combined.",
    )
    parser.add_argument(
        "--vhost",
        choices=["always", "auto", "never"],
        default="auto",
        help="When to run the http-vhosts script. 'auto' probes 80/443 first. Default: auto.",
    )
    parser.add_argument(
        "--output-dir",
        help="Root output directory. Default: ./recon-results/<target>/.",
    )
    parser.add_argument(
        "--no-parallel",
        action="store_true",
        help="Run gobuster HTTP, gobuster HTTPS, and vhost sequentially.",
    )
    parser.add_argument(
        "--skip-requirements-check",
        action="store_true",
        help="Skip nmap/gobuster PATH check (use if tools live outside PATH).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands that would run; do not execute or write outputs.",
    )
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.skip_requirements_check:
        check_requirements(args.dry_run)

    targets = load_targets(args.target_ip, args.targets)
    multi = len(targets) > 1

    extra_roots = [Path(r) for r in args.wordlist_root]
    wordlist = resolve_wordlist(args.wordlist, extra_roots)

    for target in targets:
        output_dir = resolve_output_dir(target, args.output_dir, multi)
        scan_target(
            target,
            scan_type=args.scan_type,
            wordlist=wordlist,
            nmap_format=args.nmap_format,
            report_mode=args.report,
            vhost_mode=args.vhost,
            output_dir=output_dir,
            parallel=not args.no_parallel,
            dry_run=args.dry_run,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
