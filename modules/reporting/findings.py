from modules.reporting.results import set_result


SEVERITY_DEDUCTIONS = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
}


def add_finding(
    findings,
    title,
    severity,
    category,
    description,
    recommendation
):
    findings.append({
        "title": title,
        "severity": severity,
        "category": category,
        "description": description,
        "recommendation": recommendation
    })


def analyze_headers(headers, findings):
    for header, data in headers.items():

        if data.get("status") == "MISSING":

            add_finding(
                findings,
                f"Missing {header} header",
                data.get("risk", "LOW"),
                "Security Headers",
                data.get("info", ""),
                f"Configure the {header} security header."
            )


def analyze_ssl(ssl_data, findings):

    status = ssl_data.get("status")

    if status == "INVALID":

        add_finding(
            findings,
            "Invalid SSL/TLS certificate",
            "HIGH",
            "SSL/TLS",
            ssl_data.get(
                "details",
                "Certificate verification failed."
            ),
            "Install a valid certificate from a trusted certificate authority."
        )

    elif status == "FAILED":

        # A failed connection is not automatically
        # considered a vulnerability.
        pass


def analyze_ports(ports, findings):

    for port in ports:

        if port.get("status") != "OPEN":
            continue

        port_number = port.get("port")
        service = port.get("service", "Unknown")

        # Open ports are exposure, not automatically
        # vulnerabilities.
        if port_number == 21:

            add_finding(
                findings,
                "FTP service exposed",
                "HIGH",
                "Network Exposure",
                "FTP port 21 is publicly reachable.",
                "Disable FTP if unnecessary or replace it with secure alternatives such as SFTP."
            )

        elif port_number == 3306:

            add_finding(
                findings,
                "MySQL service exposed",
                "HIGH",
                "Network Exposure",
                "MySQL port 3306 is reachable.",
                "Restrict database access to trusted hosts or networks."
            )

        elif port_number == 25:

            add_finding(
                findings,
                "SMTP service exposed",
                "MEDIUM",
                "Network Exposure",
                "SMTP port 25 is reachable.",
                "Restrict SMTP access and verify that the service is securely configured."
            )


def calculate_score(findings):

    score = 100

    for finding in findings:

        severity = finding.get("severity", "LOW")

        deduction = SEVERITY_DEDUCTIONS.get(
            severity,
            0
        )

        score -= deduction

    return max(score, 0)


def calculate_risk_level(score):

    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def generate_findings(results):

    findings = []

    analyze_headers(
        results.get("headers", {}),
        findings
    )

    analyze_ssl(
        results.get("ssl", {}),
        findings
    )

    analyze_ports(
        results.get("ports", []),
        findings
    )

    score = calculate_score(findings)

    risk_level = calculate_risk_level(score)

    open_ports = sum(
        1
        for port in results.get("ports", [])
        if port.get("status") == "OPEN"
    )

    set_result(
        "findings",
        findings
    )

    set_result(
        "score",
        score
    )

    set_result(
        "risk_level",
        risk_level
    )

    set_result(
        "open_ports",
        open_ports
    )

    return findings
