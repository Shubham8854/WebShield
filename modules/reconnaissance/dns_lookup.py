import socket

from modules.reporting.results import set_result
from utils.ui import show_dns_info


def dns_scan(domain):

    dns_data = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": []
    }

    try:
        ipv4 = socket.gethostbyname_ex(domain)

        dns_data["A"] = ipv4[2]

    except Exception:
        pass

    try:
        ipv6 = socket.getaddrinfo(
            domain,
            None,
            socket.AF_INET6
        )

        dns_data["AAAA"] = list(
            set(
                item[4][0]
                for item in ipv6
            )
        )

    except Exception:
        pass

    set_result(
        "dns",
        dns_data
    )

    show_dns_info(
        dns_data
    )

    return dns_data
