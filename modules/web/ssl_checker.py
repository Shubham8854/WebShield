import ssl
import socket
from datetime import datetime

from modules.reporting.results import set_result

def check_ssl(domain):

    print("\n[+] SSL Certificate Analysis")
    print("-" * 40)


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

                    "expires": str(
                        expiry_date
                    ),

                    "days_remaining": remaining_days

                }



                print(
                    "[+] SSL Certificate Valid"
                )

                print(
                    f"[+] Issuer: {ssl_data['issuer']}"
                )

                print(
                    f"[+] Expires: {ssl_data['expires']}"
                )

                print(
                    f"[+] Days Remaining: {remaining_days}"
                )



    except Exception as error:


        ssl_data = {

            "status": "FAILED",

            "error": str(error)

        }


        print(
            "[-] SSL Check Failed"
        )

        print(error)



    set_result(
        "ssl",
        ssl_data
    )


    return ssl_data
