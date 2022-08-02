import multiprocessing
import socket

from Reconnoitre.lib.file_helper import check_directory
from Reconnoitre.lib.file_helper import create_dir_structure
from Reconnoitre.lib.file_helper import get_config_options
from Reconnoitre.lib.file_helper import load_targets
from Reconnoitre.lib.file_helper import write_recommendations
from Reconnoitre.lib.subprocess_helper import run_scan


def nmap_scan(
        ip_address,
        output_directory,
        dns_server,
        quick,
        no_udp_service_scan):
    ip_address = ip_address.strip()

    print(f"[+] Starting quick nmap scan for {ip_address}")
    flags = get_config_options('nmap', 'quickscan')
    QUICKSCAN = f"nmap {flags} {ip_address} -oA '{output_directory}/{ip_address}.quick'"
    quickresults = run_scan(QUICKSCAN)

    write_recommendations(quickresults, ip_address, output_directory)
    print(f"[*] TCP quick scans completed for {ip_address}")

    if (quick):
        return

    if dns_server:
        print(
            "[+] Starting detailed TCP%s nmap scans for "
            "%s using DNS Server %s" %
            (("" if no_udp_service_scan is True else "/UDP"),
             ip_address,
             dns_server))
        print(f"[+] Using DNS server {dns_server}")
        flags = get_config_options("nmap", "tcpscan")
        TCPSCAN = f"nmap {flags} --dns-servers {dns_server} -oN\
        '{output_directory}/{ip_address}.nmap' -oX\
        '{output_directory}/{ip_address}_nmap_scan_import.xml' {ip_address}"

        flags = get_config_options("nmap", "dnsudpscan")
        UDPSCAN = f"nmap {flags} \
        --dns-servers {dns_server} -oN '{output_directory}/{ip_address}U.nmap' \
        -oX '{output_directory}/{ip_address}U_nmap_scan_import.xml' {ip_address}"

    else:
        print(
            f'[+] Starting detailed TCP{"" if no_udp_service_scan is True else "/UDP"} nmap scans for {ip_address}'
        )

        flags = get_config_options("nmap", "tcpscan")
        TCPSCAN = f"nmap {flags} -oN\
        '{output_directory}/{ip_address}.nmap' -oX\
        '{output_directory}/{ip_address}_nmap_scan_import.xml' {ip_address}"

        flags = get_config_options("nmap", "udpscan")
        UDPSCAN = f"nmap {flags} {ip_address} -oA '{output_directory}/{ip_address}-udp'"

    udpresult = "" if no_udp_service_scan is True else run_scan(UDPSCAN)
    tcpresults = run_scan(TCPSCAN)

    write_recommendations(tcpresults + udpresult, ip_address, output_directory)
    print(
        f'[*] TCP{"" if no_udp_service_scan is True else "/UDP"} scans completed for {ip_address}'
    )


def valid_ip(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False


def target_file(
        target_hosts,
        output_directory,
        dns_server,
        quiet,
        quick,
        no_udp_service_scan):
    targets = load_targets(target_hosts, output_directory, quiet)
    target_file = open(targets, 'r')
    try:
        target_file = open(targets, 'r')
        print(f"[*] Loaded targets from: {targets}")
    except Exception:
        print(f"[!] Unable to load: {targets}")

    for ip_address in target_file:
        ip_address = ip_address.strip()
        create_dir_structure(ip_address, output_directory)

        host_directory = f"{output_directory}/{ip_address}"
        nmap_directory = f"{host_directory}/scans"

        p = multiprocessing.Process(
            target=nmap_scan,
            args=(
                ip_address,
                nmap_directory,
                dns_server,
                quick,
                no_udp_service_scan))
        jobs = [p]
        p.start()
    target_file.close()


def target_ip(
        target_hosts,
        output_directory,
        dns_server,
        quiet,
        quick,
        no_udp_service_scan):
    print(f"[*] Loaded single target: {target_hosts}")
    target_hosts = target_hosts.strip()
    create_dir_structure(target_hosts, output_directory)

    host_directory = f"{output_directory}/{target_hosts}"
    nmap_directory = f"{host_directory}/scans"

    p = multiprocessing.Process(
        target=nmap_scan,
        args=(
            target_hosts,
            nmap_directory,
            dns_server,
            quick,
            no_udp_service_scan))
    jobs = [p]
    p.start()


def service_scan(
        target_hosts,
        output_directory,
        dns_server,
        quiet,
        quick,
        no_udp_service_scan):
    check_directory(output_directory)

    if (valid_ip(target_hosts)):
        target_ip(
            target_hosts,
            output_directory,
            dns_server,
            quiet,
            quick,
            no_udp_service_scan)
    else:
        target_file(
            target_hosts,
            output_directory,
            dns_server,
            quiet,
            quick,
            no_udp_service_scan)
