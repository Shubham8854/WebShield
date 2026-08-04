import socket

from modules.reporting.results import set_result

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Proxy"
}


def scan_ports(domain):

    print("\n[+] Port Scan")
    print("-" * 40)

    ports = []

    for port, service in COMMON_PORTS.items():

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        result = sock.connect_ex((domain, port))

        if result == 0:

            print(f"[+] Port {port} OPEN ({service})")

            ports.append({
                "port": port,
                "service": service,
                "status": "OPEN"
            })

        else:

            print(f"[-] Port {port} CLOSED ({service})")

        sock.close()

    set_result("ports", ports)

    return ports
