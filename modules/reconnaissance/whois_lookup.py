import whois

from modules.reporting.results import set_result

def lookup(domain):

    print("\n[+] WHOIS Information")
    print("-" * 40)

    whois_data = {}

    try:

        info = whois.whois(domain)

        registrar = str(info.registrar)
        creation = str(info.creation_date)
        expiration = str(info.expiration_date)

        print(f"[+] Registrar: {registrar}")
        print(f"[+] Created: {creation}")
        print(f"[+] Expires: {expiration}")

        whois_data = {
            "registrar": registrar,
            "creation_date": creation,
            "expiration_date": expiration
        }

    except Exception as error:

        print("[-] WHOIS Lookup Failed")
        print(error)

        whois_data["error"] = str(error)

    set_result("whois", whois_data)

    return whois_data
