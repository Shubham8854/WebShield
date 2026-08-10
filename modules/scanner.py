
import requests
import socket
import time


def scan(url):

    try:

        start = time.time()


        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )


        response_time = round(
            time.time() - start,
            3
        )


        print(
            "\n[+] Website:",
            response.url
        )

        print(
            "[+] Status Code:",
            response.status_code
        )


        print(
            "\n[+] Headers Found:"
        )


        for header, value in response.headers.items():

            print(
                f"{header}: {value}"
            )


        return response


    except requests.exceptions.RequestException as error:


        print(
            "[-] Error:",
            error
        )

        return None
