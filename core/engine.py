from modules.report import generate_report
from modules.scanner import scan

from modules.web.headers import check_headers
from modules.web.ssl_checker import check_ssl

from modules.reconnaissance.whois_lookup import lookup
from modules.reconnaissance.dns_lookup import dns_scan
from modules.reconnaissance.tech_detector import detect

from modules.network.port_scan import scan_ports

from modules.reporting.results import get_results, set_result

from utils.helpers import clean_domain, normalize_url
from utils.logger import log_info, log_error

from utils.ui import (
    show_banner,
    loading_animation,
    show_target_info
)


def start():

    show_banner()

    loading_animation()


    target = input(
        "Enter target (domain, URL, or IP): "
    ).strip()


    try:

        target = normalize_url(target)

        domain = clean_domain(target)


        set_result(
            "target",
            domain
        )


        log_info(
            f"Scan started for {domain}"
        )


        response = scan(target)


        if not response:

            print(
                "[-] Scan failed"
            )

            return



        # Target Box
        show_target_info(response)



        # Security Checks

        check_headers(response)


        check_ssl(domain)


        lookup(domain)


        dns_scan(domain)


        detect(response)


        scan_ports(domain)



        results = get_results()



        generate_report(
            results
        )


        log_info(
            "Scan completed"
        )


    except Exception as error:

        log_error(
            str(error)
        )

        print(
            f"\n[-] Error: {error}"
        )
