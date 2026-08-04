from modules.reporting.results import set_result

def detect(response):

    print("\n[+] Technology Detection")
    print("-" * 40)

    technologies = []

    headers = response.headers

    if "Server" in headers:

        server = headers["Server"]

        print(f"[+] Server: {server}")

        technologies.append(server)

    if "X-Powered-By" in headers:

        powered = headers["X-Powered-By"]

        print(f"[+] Powered By: {powered}")

        technologies.append(powered)

    set_result("technology", technologies)

    return technologies
