import json
from datetime import datetime
from pathlib import Path

from modules.reporting.html_report import generate_html
from modules.reporting.summary import generate_summary


def generate_report(data, filename="webshield_report"):

    Path("reports").mkdir(
        parents=True,
        exist_ok=True
    )

    # Generate executive security summary
    summary = generate_summary()

    # Merge summary into report data
    report_data = dict(data)

    report_data.update({
        "score": summary.get("score", 0),
        "rating": summary.get("rating", "UNKNOWN"),
        "findings": summary.get("findings", []),
        "recommendations": summary.get(
            "recommendations",
            []
        )
    })

    # Complete report
    report = {
        "scan_time": str(datetime.now()),
        "results": report_data
    }

    # JSON Report
    with open(
        f"reports/{filename}.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    # HTML Report
    generate_html(
        report_data,
        filename
    )

    print(
        "\n[+] JSON Report Generated"
    )

    print(
        "[+] HTML Report Generated"
    )
