import requests
import time

from modules.reporting.results import set_result


def scan(url):

    start = time.time()

    try:

        response = requests.get(
            url,
            timeout=(5, 15),
            allow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "WebShield/2.0 Security Scanner"
            }
        )

        response_time = round(
            time.time() - start,
            3
        )

        set_result(
            "http",
            {
                "status": response.status_code,
                "url": response.url,
                "response_time": response_time,
                "reachable": True
            }
        )

        return response

    except requests.exceptions.Timeout as error:

        response_time = round(
            time.time() - start,
            3
        )

        set_result(
            "http",
            {
                "status": None,
                "url": url,
                "response_time": response_time,
                "reachable": False,
                "error": "Connection timed out"
            }
        )

        print(
            f"[-] HTTP connection timed out: {url}"
        )

        return None

    except requests.exceptions.ConnectionError as error:

        response_time = round(
            time.time() - start,
            3
        )

        set_result(
            "http",
            {
                "status": None,
                "url": url,
                "response_time": response_time,
                "reachable": False,
                "error": "Connection failed"
            }
        )

        print(
            f"[-] HTTP connection failed: {url}"
        )

        return None

    except requests.exceptions.RequestException as error:

        response_time = round(
            time.time() - start,
            3
        )

        set_result(
            "http",
            {
                "status": None,
                "url": url,
                "response_time": response_time,
                "reachable": False,
                "error": str(error)
            }
        )

        print(
            f"[-] HTTP request error: {error}"
        )

        return None
