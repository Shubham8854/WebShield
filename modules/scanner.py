import socket
import time
import requests


def scan(url):
    try:
        start = time.time()

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        elapsed = round((time.time() - start) * 1000)

        hostname = response.url.split("//")[1].split("/")[0]
        ip = socket.gethostbyname(hostname)

        return {
            "response": response,
            "target": {
                "url": response.url,
                "status": response.status_code,
                "server": response.headers.get("Server", "Unknown"),
                "content_type": response.headers.get("Content-Type", "Unknown"),
                "ip": ip,
                "response_time": f"{elapsed} ms"
            }
        }

    except Exception:
        return None
