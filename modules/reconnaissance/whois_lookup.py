import whois

from modules.reporting.results import set_result


def lookup(domain):

    whois_data = {}

    try:

        info = whois.whois(domain)

        whois_data = {

            "registrar": str(
                info.registrar
            ),

            "creation_date": str(
                info.creation_date
            ),

            "expiration_date": str(
                info.expiration_date
            ),

            "name_servers": str(
                info.name_servers
            )

        }

    except Exception as error:

        whois_data = {
            "error": str(error)
        }

    set_result(
        "whois",
        whois_data
    )

    return whois_data
