import re

from modules.reporting.results import set_result
from utils.ui import show_technology_info


VERSION_PATTERNS = [

    r"(?P<product>[A-Za-z][A-Za-z0-9._-]*)/(?P<version>\d+(?:\.\d+)+)",

    r"(?P<product>nginx)[ /](?P<version>\d+(?:\.\d+)+)",

    r"(?P<product>Apache)[ /](?P<version>\d+(?:\.\d+)+)",

    r"(?P<product>OpenSSH)[_ /](?P<version>\d+(?:\.\d+)+)",

    r"(?P<product>PHP)[ /](?P<version>\d+(?:\.\d+)+)",

]


def parse_technology(value):

    for pattern in VERSION_PATTERNS:

        match = re.search(
            pattern,
            value,
            re.IGNORECASE
        )

        if match:

            product = match.group(
                "product"
            )

            version = match.group(
                "version"
            )

            return {
                "product": product,
                "version": version,
                "raw": value
            }

    return {
        "product": value,
        "version": None,
        "raw": value
    }


def detect(response):

    technologies = []

    headers = response.headers


    # -----------------------------------------
    # SERVER
    # -----------------------------------------

    if "Server" in headers:

        server = headers["Server"]

        if server:

            technology = parse_technology(
                server
            )

            technologies.append({
                "type": "Web Server",
                "value": server,
                "product": technology["product"],
                "version": technology["version"],
                "raw": technology["raw"]
            })


    # -----------------------------------------
    # X-POWERED-BY
    # -----------------------------------------

    if "X-Powered-By" in headers:

        powered = headers["X-Powered-By"]

        if powered:

            technology = parse_technology(
                powered
            )

            technologies.append({
                "type": "Powered By",
                "value": powered,
                "product": technology["product"],
                "version": technology["version"],
                "raw": technology["raw"]
            })


    # -----------------------------------------
    # UNKNOWN
    # -----------------------------------------

    if not technologies:

        technologies.append({
            "type": "Web Server",
            "value": "Unknown",
            "product": None,
            "version": None,
            "raw": None
        })


    set_result(
        "technology",
        technologies
    )


    show_technology_info(
        technologies
    )


    return technologies
