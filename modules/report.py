import json
from datetime import datetime


def generate_report(data, filename="webshield_report"):

    report = {
        "scan_time": str(datetime.now()),
        "results": data
    }

    with open(f"reports/{filename}.json", "w") as file:

        json.dump(report, file, indent=4)

    print(f"\n[+] Report saved to reports/{filename}.json")
