import json
from datetime import datetime

from modules.reporting.html_report import generate_html


def generate_report(data, filename="webshield_report"):

    report = {

        "scan_time": str(datetime.now()),

        "results": data

    }


    # JSON Report

    with open(
        f"reports/{filename}.json",
        "w"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )


    # HTML Report

    generate_html(
        data,
        filename
    )


    print(
        "\n[+] JSON Report Generated"
    )

    print(
        "[+] HTML Report Generated"
    )
