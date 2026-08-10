from modules.reporting.results import set_result
from utils.ui import show_technology_info


def detect(response):

    technologies = []

    headers = response.headers

    if "Server" in headers:

        server = headers["Server"]

        if server:

            technologies.append({
                "type": "Web Server",
                "value": server
            })

    if "X-Powered-By" in headers:

        powered = headers["X-Powered-By"]

        if powered:

            technologies.append({
                "type": "Powered By",
                "value": powered
            })

    if not technologies:

        technologies.append({
            "type": "Web Server",
            "value": "Unknown"
        })

    set_result(
        "technology",
        technologies
    )

    show_technology_info(
        technologies
    )

    return technologies
