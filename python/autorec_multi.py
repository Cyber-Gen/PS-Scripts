import argparse
import subprocess
import os

def run_nmap_scan(target_ip, scan_type):
    nmap_output_dir = "Nmap"
    os.makedirs(nmap_output_dir, exist_ok=True)

    if scan_type == "Full":
        nmap_command = f"nmap -A -T4 -p- -sV -oA {nmap_output_dir}/full_scan {target_ip}"
    elif scan_type == "Basic":
        nmap_command = f"nmap -A -T4 -p 1-1000 -sV -oA {nmap_output_dir}/basic_scan {target_ip}"
    else:
        print("Invalid scan type. Use 'Full' or 'Basic'")
        return

    subprocess.run(nmap_command, shell=True)

def run_gobuster(target_ip):
    gobuster_output_dir = "Gobuster"
    os.makedirs(gobuster_output_dir, exist_ok=True)

    gobuster_http_command = f"gobuster dir -u http://{target_ip} -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -o {gobuster_output_dir}/http_dir_scan.txt"
    gobuster_https_command = f"gobuster dir -u https://{target_ip} -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -o {gobuster_output_dir}/https_dir_scan.txt"

    subprocess.run(gobuster_http_command, shell=True)
    subprocess.run(gobuster_https_command, shell=True)

def run_virtual_host_scan(target_ip):
    nmap_output_dir = "Nmap"
    virtual_host_output = os.path.join(nmap_output_dir, "virtual_hosts.txt")

    nmap_command = f"nmap -p 80,443 --script=http-vhosts {target_ip} -oN {virtual_host_output}"
    subprocess.run(nmap_command, shell=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan a target IP address with Nmap and Gobuster")
    parser.add_argument("target_ip", help="The target IP address to scan")
    parser.add_argument("scan_type", choices=["Full", "Basic"], help="Scan type: 'Full' or 'Basic'")
    args = parser.parse_args()

    run_nmap_scan(args.target_ip, args.scan_type)
    run_gobuster(args.target_ip)

    # Check if port 80 or 443 is open before running the virtual host scan
    open_ports_command = f"nmap -p 80,443 {args.target_ip} | grep 'open'"
    open_ports_result = subprocess.run(open_ports_command, shell=True, stdout=subprocess.PIPE, text=True)
    if "80/tcp" in open_ports_result.stdout or "443/tcp" in open_ports_result.stdout:
        run_virtual_host_scan(args.target_ip)
