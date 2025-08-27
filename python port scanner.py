#!/usr/bin/python3

import socket
import sys
import threading
import time
from colorama import Fore, init
init(autoreset=True)

usage = "python3 port_scanner.py Target Start_port End_port"
threads = []
open_ports = []
scanned = 0
scanned_lock = threading.Lock()  
print_lock = threading.Lock()    

common_ports= {
    0: "Reserved",
    1: "TCP Port Service Multiplexer (TCPMUX)",
    2: "CompressNET Management Utility",
    3: "CompressNET Compression Process",
    5: "Remote Job Entry (RJE)",
    7: "Echo Protocol",
    9: "Discard Protocol",
    11: "Active Users (systat service)",
    13: "Daytime Protocol",
    15: "Unassigned",
    17: "Quote of the Day (QOTD)",
    18: "Message Send Protocol",
    19: "Character Generator Protocol (CHARGEN)",
    20: "File Transfer Protocol (FTP) Data Transfer",
    21: "File Transfer Protocol (FTP) Command Control",
    22: "Secure Shell (SSH)",
    23: "Telnet",
    25: "Simple Mail Transfer Protocol (SMTP)",
    53: "Domain Name System (DNS)",
    67: "Dynamic Host Configuration Protocol (DHCP) Server",
    68: "DHCP Client",
    69: "Trivial File Transfer Protocol (TFTP)",
    80: "Hypertext Transfer Protocol (HTTP)",
    88: "Kerberos",
    110: "Post Office Protocol v3 (POP3)",
    119: "Network News Transfer Protocol (NNTP)",
    123: "Network Time Protocol (NTP)",
    135: "Remote Procedure Call (RPC)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "Internet Message Access Protocol (IMAP)",
    161: "Simple Network Management Protocol (SNMP)",
    162: "SNMP Trap",
    179: "Border Gateway Protocol (BGP)",
    194: "Internet Relay Chat (IRC)",
    443: "Hypertext Transfer Protocol Secure (HTTPS)",
    445: "Microsoft-DS",
    465: "SMTP over SSL",
    514: "Syslog",
    587: "SMTP Mail Submission",
    636: "LDAP over SSL",
    873: "rsync",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    3389: "Remote Desktop Protocol (RDP)",
    5432: "PostgreSQL Database",
    6379: "Redis",
    8080: "HTTP Alternate (commonly used for proxy and caching servers)",
    8443: "HTTPS Alternate",
    9000: "SonarQube",
    27017: "MongoDB",
    50000: "SAP NetWeaver",
    49152: "Dynamic/Private Ports Start",
    65535: "Dynamic/Private Ports End"
}


print("Python port scanner")

if len(sys.argv) != 4:
    print(usage)
    sys.exit()

try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print("Name resolution error")
    sys.exit()

start_port = int(sys.argv[2])
end_port = int(sys.argv[3])

if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
    print("Ports must be between 0 and 65535")
    sys.exit()

total = end_port - start_port + 1
semaphore = threading.Semaphore(100)

def scan_port(port):
    global scanned
    with semaphore:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        conn = s.connect_ex((target, port))
        s.close()

        service = common_ports.get(port, "Unknown")
        if conn == 0:
            open_ports.append((port, service))
            with print_lock:
                print(Fore.GREEN + f"Port {port} is OPEN ({service})")
        else:
            with print_lock:
                print(Fore.LIGHTBLACK_EX + f"Port {port} is closed")

        with scanned_lock:
            scanned += 1
            if scanned % 50 == 0 or scanned == total:
                with print_lock:
                    print(f"Scanned {scanned}/{total} ports...")

try:
    start_time = time.time()

    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

except KeyboardInterrupt:
    print("\nScan aborted by user")
    sys.exit()

if open_ports:
    print("\nSummary of open ports:")
    for port, service in sorted(open_ports):
        print(f" - {port}: {service}")
else:
    print("\nNo open ports found.")

print(f"\nScan completed in {time.time()-start_time:.2f} seconds")

with open("scan_results.txt", "w") as f:
    for port, service in open_ports:
        f.write(f"{port}: {service}\n")
