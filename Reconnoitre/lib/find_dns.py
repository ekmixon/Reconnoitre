from Reconnoitre.lib.file_helper import check_directory
from Reconnoitre.lib.file_helper import load_targets
from Reconnoitre.lib.subprocess_helper import run_scan


def find_dns(target_hosts, output_directory, quiet):
    check_directory(output_directory)
    dns_server_list = []
    results = 0
    hostcount = 0
    dnscount = 0

    with open(f"{output_directory}/DNS-Detailed.txt", 'w') as output_file:
        output_targets = open(f"{output_directory}/DNS-targets.txt", 'w')

        targets = load_targets(target_hosts, output_directory, quiet)
        target_file = open(targets, 'r')

        print(f"[*] Loaded targets from: {targets}")
        print("[+] Enumerating TCP port 53 over targets to find dns servers")

        for ip_address in target_file:
            hostcount += 1
            ip_address = ip_address.strip()
            ip_address = ip_address.rstrip()

            print(f"   [>] Testing {ip_address} for DNS")
            DNSSCAN = f"nmap -n -sV -Pn -vv -p53 {ip_address}"
            results = run_scan(DNSSCAN)
            lines = results.split("\n")

            for line in lines:
                line = line.strip()
                line = line.rstrip()
                if (("53/tcp" in line) and ("open" in line)
                    and ("Discovered" not in line)):
                    print(f"      [=] Found DNS service running on: {ip_address}")
                    output_file.write(
                        "[*] Found DNS service running on: %s\n" %
                        (ip_address))
                    output_file.write("   [>] %s\n" % (line))
                    output_targets.write("%s\n" % (ip_address))
                    dns_server_list.append(ip_address)
                    dnscount += 1
        print(f"[*] Found {str(dnscount)} DNS servers within {str(hostcount)} hosts")
    output_targets.close()
    return ','.join(dns_server_list) if dns_server_list else ''
