from modules.reporting.results import get_results, set_result

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


console = Console()


def calculate_score(results):
    """
    Calculate a security score from detected findings.

    Starts at 100 and deducts points for:
    - Missing security headers
    - Invalid SSL/TLS
    - Open ports
    - Confirmed CVEs
    """

    score = 100

    # -----------------------------------------
    # SECURITY HEADERS
    # -----------------------------------------

    headers = results.get("headers", {})

    header_penalties = {
        "HIGH": 15,
        "MEDIUM": 10,
        "LOW": 5
    }

    for data in headers.values():

        if data.get("status") == "MISSING":

            risk = data.get("risk", "LOW")

            score -= header_penalties.get(
                risk,
                5
            )

    # -----------------------------------------
    # SSL / TLS
    # -----------------------------------------

    ssl_data = results.get(
        "ssl",
        {}
    )

    if ssl_data.get("status") not in (
        None,
        "",
        "VALID"
    ):

        score -= 20

    # -----------------------------------------
    # OPEN PORTS
    # -----------------------------------------

    open_ports = results.get(
        "open_ports",
        0
    )

    # Small penalty for exposed services
    score -= min(
        open_ports * 2,
        10
    )

    # -----------------------------------------
    # CVEs
    # -----------------------------------------

    cves = results.get(
        "cves",
        []
    )

    for cve in cves:

        severity = str(
            cve.get(
                "severity",
                ""
            )
        ).upper()

        if severity == "CRITICAL":
            score -= 20

        elif severity == "HIGH":
            score -= 15

        elif severity == "MEDIUM":
            score -= 8

        elif severity == "LOW":
            score -= 3

    return max(
        0,
        min(
            100,
            score
        )
    )


def calculate_risk(score):

    if score >= 80:
        return "LOW"

    if score >= 60:
        return "MEDIUM"

    return "HIGH"


def build_findings(results):

    findings = []

    # -----------------------------------------
    # SECURITY HEADERS
    # -----------------------------------------

    headers = results.get(
        "headers",
        {}
    )

    for header, data in headers.items():

        if data.get("status") == "MISSING":

            findings.append({
                "title": f"Missing {header} header",
                "severity": data.get(
                    "risk",
                    "LOW"
                ),
                "category": "Security Headers",
                "recommendation":
                    f"Configure the {header} security header."
            })

    # -----------------------------------------
    # SSL
    # -----------------------------------------

    ssl_data = results.get(
        "ssl",
        {}
    )

    if ssl_data.get("status") not in (
        None,
        "",
        "VALID"
    ):

        findings.append({
            "title": "Invalid SSL/TLS certificate",
            "severity": "HIGH",
            "category": "SSL/TLS",
            "recommendation":
                "Install a valid certificate from a trusted certificate authority."
        })

    # -----------------------------------------
    # OPEN PORTS
    # -----------------------------------------

    ports = results.get(
        "ports",
        []
    )

    for port in ports:

        if port.get("status") == "OPEN":

            findings.append({
                "title":
                    f"Open {port.get('service', 'unknown')} port {port.get('port')}",
                "severity": "MEDIUM",
                "category": "Network Exposure",
                "recommendation":
                    f"Review whether port {port.get('port')} "
                    f"({port.get('service', 'unknown')}) needs to be exposed."
            })

    # -----------------------------------------
    # CVEs
    # -----------------------------------------

    cves = results.get(
        "cves",
        []
    )

    for cve in cves:

        findings.append({
            "title":
                f"{cve.get('id', 'Unknown CVE')}",
            "severity":
                cve.get(
                    "severity",
                    "UNKNOWN"
                ),
            "category":
                "CVE",
            "recommendation":
                f"Update {cve.get('product', 'software')} "
                f"to a secure version."
        })

    return findings


def generate_recommendations(findings):

    recommendations = []

    for finding in findings:

        recommendation = finding.get(
            "recommendation"
        )

        if (
            recommendation
            and recommendation not in recommendations
        ):

            recommendations.append(
                recommendation
            )

    return recommendations


def generate_summary():

    results = get_results()

    # -----------------------------------------
    # CALCULATE
    # -----------------------------------------

    score = calculate_score(
        results
    )

    risk_level = calculate_risk(
        score
    )

    findings = build_findings(
        results
    )

    recommendations = generate_recommendations(
        findings
    )

    # -----------------------------------------
    # STORE
    # -----------------------------------------

    set_result(
        "score",
        score
    )

    set_result(
        "risk_level",
        risk_level
    )

    set_result(
        "findings",
        findings
    )

    set_result(
        "recommendations",
        recommendations
    )

    return {
        "score": score,
        "risk_level": risk_level,
        "rating": risk_level,
        "findings": findings,
        "open_ports": results.get(
            "open_ports",
            0
        ),
        "recommendations": recommendations
    }


def show_final_security_summary():

    summary = generate_summary()

    score = summary["score"]
    risk_level = summary["risk_level"]
    findings = summary["findings"]
    open_ports = summary["open_ports"]
    recommendations = summary["recommendations"]

    # -----------------------------------------
    # SUMMARY PANEL
    # -----------------------------------------

    table = Table(
        title="🛡 FINAL SECURITY SUMMARY",
        show_header=True
    )

    table.add_column(
        "Property"
    )

    table.add_column(
        "Value"
    )

    table.add_row(
        "Security Score",
        f"{score}/100"
    )

    table.add_row(
        "Risk Level",
        risk_level
    )

    table.add_row(
        "Findings",
        str(len(findings))
    )

    table.add_row(
        "Open Ports",
        str(open_ports)
    )

    console.print()

    console.print(
        Panel(
            table,
            title="WebShield 2.0",
            border_style="cyan"
        )
    )

    # -----------------------------------------
    # FINDINGS
    # -----------------------------------------

    if findings:

        finding_table = Table(
            title="🔎 KEY FINDINGS"
        )

        finding_table.add_column(
            "Finding"
        )

        finding_table.add_column(
            "Severity"
        )

        finding_table.add_column(
            "Category"
        )

        for finding in findings:

            finding_table.add_row(
                finding.get(
                    "title",
                    "Unknown"
                ),
                finding.get(
                    "severity",
                    "UNKNOWN"
                ),
                finding.get(
                    "category",
                    "General"
                )
            )

        console.print(
            finding_table
        )

    else:

        console.print(
            "[green]✓ No security findings detected[/green]"
        )

    # -----------------------------------------
    # RECOMMENDATIONS
    # -----------------------------------------

    if recommendations:

        recommendation_table = Table(
            title="💡 RECOMMENDATIONS"
        )

        recommendation_table.add_column(
            "#"
        )

        recommendation_table.add_column(
            "Recommendation"
        )

        for index, recommendation in enumerate(
            recommendations,
            1
        ):

            recommendation_table.add_row(
                str(index),
                recommendation
            )

        console.print(
            recommendation_table
        )

    return summary
