from Reconnoitre.lib.file_helper import check_directory
from Reconnoitre.lib.subprocess_helper import run_scan


def ping_sweeper(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = f"{output_directory}/targets.txt"

    print(f"[+] Performing ping sweep over {target_hosts}")

    lines = call_nmap_sweep(target_hosts)
    live_hosts = parse_nmap_output_for_live_hosts(lines)
    write_live_hosts_list_to_file(output_file, live_hosts)

    for ip_address in live_hosts:
        print(f"   [>] Discovered host: {ip_address}")

    print(f"[*] Found {len(live_hosts)} live hosts")
    print(f"[*] Created target list {output_file}")


def call_nmap_sweep(target_hosts):
    SWEEP = f"nmap -n -sP {target_hosts}"

    results = run_scan(SWEEP)
    return str(results).split("\n")


def parse_nmap_output_for_live_hosts(lines):
    def get_ip_from_nmap_line(line):
        return line.split()[4]

    live_hosts = [get_ip_from_nmap_line(line)
                  for line in lines
                  if "Nmap scan report for" in line]

    return live_hosts


def write_live_hosts_list_to_file(output_file, live_hosts):
    print(f"[+] Writing discovered targets to: {output_file}")
    with open(output_file, 'w') as f:
        f.write("\n".join(live_hosts))
