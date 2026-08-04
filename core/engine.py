from utils.ui import show_target_info
from modules.report import generate_report
from modules.scanner import scan

from modules.web.headers import check_headers
from modules.web.ssl_checker import check_ssl

from modules.reconnaissance.whois_lookup import lookup
from modules.reconnaissance.dns_lookup import dns_scan
from modules.reconnaissance.tech_detector import detect

from modules.network.port_scan import scan_ports

from modules.reporting.results import get_results

from utils.helpers import clean_domain, normalize_url
from utils.logger import log_info, log_error
from utils.ui import show_banner, loading_animation


def start():

    show_banner()
    loading_animation()

    target = input("Enter target (domain, URL, or IP): ").strip()

    try:

        target = normalize_url(target)

        domain = clean_domain(target)

        log_info(f"Scan started for {domain}")

        scan_data = scan(target)
        
       response = scan(target)

        if not response:
            print("\n[-] Scan failed.")
            log_error("HTTP scan failed")
            return

        log_info("HTTP scan completed")

        check_headers(response)
        check_ssl(domain)
        lookup(domain)
        dns_scan(domain)
        detect(response)
        scan_ports(domain)

        log_info("Scan completed successfully")

        results = get_results()

        print("\n[+] Scan Data Collected")
        print(results)

        generate_report(results)

    except Exception as error:

        log_error(str(error))
        print(f"\n[-] Error: {error}")
