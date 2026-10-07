from modules.reporting.results import set_result
from utils.ui import show_security_headers


SECURITY_HEADERS = {

    "Strict-Transport-Security": {
        "risk": "HIGH",
        "info": "Protects against HTTPS downgrade attacks",
    },

    "Content-Security-Policy": {
        "risk": "HIGH",
        "info": "Helps prevent Cross-Site Scripting attacks",
    },

    "X-Frame-Options": {
        "risk": "MEDIUM",
        "info": "Protects against clickjacking attacks",
    },

    "X-Content-Type-Options": {
        "risk": "MEDIUM",
        "info": "Prevents MIME type sniffing",
    },

    "Referrer-Policy": {
        "risk": "LOW",
        "info": "Controls referrer information leakage",
    },
}


def check_headers(response):

    findings = {}

    for header, info in SECURITY_HEADERS.items():

        present = header in response.headers

        status = (
            "PRESENT"
            if present
            else
            "MISSING"
        )

        findings[header] = {

            "status": status,

            "risk": info["risk"],

            "info": info["info"]

        }

    set_result(
        "headers",
        findings
    )

    show_security_headers(
        findings
    )

    return findings
