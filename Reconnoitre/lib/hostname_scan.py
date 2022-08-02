import os

from Reconnoitre.lib.file_helper import check_directory
from Reconnoitre.lib.subprocess_helper import run_scan


def hostname_scan(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    output_file = f"{output_directory}/hostnames.txt"
    with open(output_file, 'w') as f:
        print(f"[+] Writing hostnames to: {output_file}")

        hostnames = 0
        SWEEP = ''

        if (os.path.isfile(target_hosts)):
            SWEEP = f"nbtscan -q -f {target_hosts}"
        else:
            SWEEP = f"nbtscan -q {target_hosts}"

        results = run_scan(SWEEP)
        lines = results.split("\n")

        for line in lines:
            line = line.strip()
            line = line.rstrip()

            # Final line is blank which causes list index issues if we don't
            # continue past it.
            if " " not in line:
                continue

            while "  " in line:
                line = line.replace("  ", " ")

            ip_address = line.split(" ")[0]
            host = line.split(" ")[1]

            if (hostnames > 0):
                f.write('\n')

            print(f"   [>] Discovered hostname: {host} ({ip_address})")
            f.write(f"{host} - {ip_address}")
            hostnames += 1

        print(f"[*] Found {hostnames} hostnames.")
        print(f"[*] Created hostname list {output_file}")
