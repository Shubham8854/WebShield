from modules.reporting.results import get_results


def generate_summary():

    results = get_results()

    score = results.get("score", 0)

    findings = []
    recommendations = []


    # Header findings

    headers = results.get("headers", {})

    for header, data in headers.items():

        if data["status"] == "MISSING":

            findings.append({
                "name": header,
                "risk": data["risk"]
            })

            recommendations.append(
                f"Enable {header} security header"
            )


    # SSL findings

    ssl = results.get("ssl", {})

    if ssl.get("status") != "VALID":

        findings.append({
            "name": "SSL Certificate",
            "risk": "HIGH"
        })

        recommendations.append(
            "Fix SSL/TLS certificate configuration"
        )


    # Rating

    if score >= 80:

        rating = "LOW"

    elif score >= 60:

        rating = "MEDIUM"

    else:

        rating = "HIGH"


    summary = {

        "score": score,

        "rating": rating,

        "findings": findings,

        "recommendations": recommendations

    }


    return summary
