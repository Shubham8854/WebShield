from modules.report import generate_report
from modules.scanner import scan

from modules.web.headers import check_headers
from modules.web.ssl_checker import check_ssl

from modules.reconnaissance.whois_lookup import lookup
from modules.reconnaissance.dns_lookup import dns_scan
from modules.reconnaissance.tech_detector import detect

from modules.network.port_scan import scan_ports

from modules.reporting.results import get_results, set_result
from modules.reporting.summary import (
    generate_summary,
    show_final_security_summary
)

from modules.vulnerability.cve_engine import scan_technologies

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

        # -----------------------------------------
        # NORMALIZE TARGET
        # -----------------------------------------

        target = normalize_url(target)

        domain = clean_domain(target)

        set_result(
            "target",
            domain
        )

        log_info(
            f"Scan started for {domain}"
        )

        # -----------------------------------------
        # HTTP SCAN
        # -----------------------------------------

        response = scan(target)

        technologies = []

        if response:


            show_target_info(
                response
            )

            # -----------------------------------------
            # SECURITY HEADERS
            # -----------------------------------------

            check_headers(
                response
            )

            # -----------------------------------------
            # TECHNOLOGY DETECTION
            # -----------------------------------------

            technologies = detect(
                response
            )

        else:

            print(
                "[-] HTTP response unavailable"
            )

            print(
                "[*] Continuing with network/recon checks..."
            )

        # -----------------------------------------
        # SSL / TLS
        # -----------------------------------------

        check_ssl(
            domain
        )

        # -----------------------------------------
        # WHOIS
        # -----------------------------------------

        lookup(
            domain
        )

        # -----------------------------------------
        # DNS
        # -----------------------------------------

        dns_scan(
            domain
        )

        # -----------------------------------------
        # NETWORK PORTS
        # -----------------------------------------

        scan_ports(
            domain
        )

        # -----------------------------------------
        # CVE / NVD ANALYSIS
        # -----------------------------------------

        if technologies:

            print(
                "\n🔎 VULNERABILITY / CVE ANALYSIS"
            )

            scan_technologies(
                technologies
            )

        else:

            set_result(
                "cves",
                []
            )

        # -----------------------------------------
        # CALCULATE OPEN PORTS
        # -----------------------------------------

        results = get_results()

        open_ports = len([
            port
            for port in results.get(
                "ports",
                []
            )
            if port.get("status") == "OPEN"
        ])

        set_result(
            "open_ports",
            open_ports
        )

        # -----------------------------------------
        # FINAL SUMMARY
        # -----------------------------------------

        summary = generate_summary()

        # -----------------------------------------
        # FINAL STATE
        # -----------------------------------------

        set_result(
            "score",
            summary["score"]
        )

        set_result(
            "risk_level",
            summary["risk_level"]
        )

        set_result(
            "rating",
            summary["risk_level"]
        )

        set_result(
            "findings",
            summary["findings"]
        )

        set_result(
            "recommendations",
            summary["recommendations"]
        )

        # -----------------------------------------
        # DISPLAY FINAL SUMMARY
        # -----------------------------------------

        show_final_security_summary()

        # -----------------------------------------
        # REPORT GENERATION
        # -----------------------------------------

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
