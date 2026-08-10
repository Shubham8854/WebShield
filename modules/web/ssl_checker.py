import ssl
import socket
from datetime import datetime

from modules.reporting.results import set_result
from utils.ui import show_ssl_info

def check_ssl(domain):

    ssl_data = {}

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssock:

                cert = ssock.getpeercert()

                issuer = dict(
                    x[0] for x in cert["issuer"]
                )

                subject = dict(
                    x[0] for x in cert["subject"]
                )

                expiry = cert["notAfter"]

                expiry_date = datetime.strptime(
                    expiry,
                    "%b %d %H:%M:%S %Y %Z"
                )

                remaining_days = (
                    expiry_date - datetime.now()
                ).days

                ssl_data = {
                    "status": "VALID",
                    "issuer": issuer.get(
                        "organizationName",
                        "Unknown"
                    ),
                    "subject": subject.get(
                        "commonName",
                        "Unknown"
                    ),
                    "expires": expiry_date.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                    "days_remaining": remaining_days
                }

    except ssl.SSLCertVerificationError as error:

        ssl_data = {
            "status": "INVALID",
            "error": "Certificate verification failed",
            "details": str(error)
        }

    except socket.timeout:

        ssl_data = {
            "status": "FAILED",
            "error": "SSL connection timed out"
        }

    except ConnectionRefusedError:

        ssl_data = {
            "status": "FAILED",
            "error": "Port 443 connection refused"
        }

    except Exception as error:

        ssl_data = {
            "status": "FAILED",
            "error": str(error)
        }

    set_result(
    "ssl",
    ssl_data
)


    show_ssl_info(
    ssl_data
)


    return ssl_data
