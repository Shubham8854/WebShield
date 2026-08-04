import socket

from modules.reporting.results import set_result

def dns_scan(domain):

    print("\n[+] DNS Lookup")
    print("-" * 40)

    dns_data = {}

    try:

        ip = socket.gethostbyname(domain)

        print(f"[+] IP Address: {ip}")

        dns_data["ip"] = ip

    except Exception as error:

        print("[-] DNS Lookup Failed")
        print(error)

        dns_data["error"] = str(error)

    set_result("dns", dns_data)

    return dns_data
