import socket

from modules.reporting.results import set_result
from utils.ui import show_port_scan


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

    ports = []

    for port, service in COMMON_PORTS.items():

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        try:

            result = sock.connect_ex(
                (domain, port)
            )

            status = (
                "OPEN"
                if result == 0
                else
                "CLOSED"
            )

            ports.append({
                "port": port,
                "service": service,
                "status": status
            })

        except Exception:

            ports.append({
                "port": port,
                "service": service,
                "status": "ERROR"
            })

        finally:

            sock.close()


    set_result(
        "ports",
        ports
    )


    show_port_scan(
        ports
    )


    return ports
