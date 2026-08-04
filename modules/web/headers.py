from modules.reporting.results import set_result


SECURITY_HEADERS = {

    "Strict-Transport-Security": {
        "risk": "HIGH",
        "info": "Protects against HTTPS downgrade attacks"
    },

    "Content-Security-Policy": {
        "risk": "HIGH",
        "info": "Helps prevent Cross-Site Scripting attacks"
    },

    "X-Frame-Options": {
        "risk": "MEDIUM",
        "info": "Protects against clickjacking attacks"
    },

    "X-Content-Type-Options": {
        "risk": "MEDIUM",
        "info": "Prevents MIME type sniffing"
    },

    "Referrer-Policy": {
        "risk": "LOW",
        "info": "Controls referrer information leakage"
    }

}


def check_headers(response):

    print("\n[+] Security Header Analysis")
    print("-" * 40)


    findings = {}

    score = 100


    for header, info in SECURITY_HEADERS.items():


        if header in response.headers:

            print(
                f"[+] {header}"
            )

            print(
                f"    Status: PRESENT"
            )

            print(
                f"    Risk: {info['risk']}"
            )

            print(
                f"    Info: {info['info']}"
            )


            findings[header] = {

                "status": "PRESENT",

                "risk": info["risk"],

                "info": info["info"]

            }



        else:

            print(
                f"[-] {header}"
            )

            print(
                f"    Status: MISSING"
            )

            print(
                f"    Risk: {info['risk']}"
            )

            print(
                f"    Info: {info['info']}"
            )


            findings[header] = {

                "status": "MISSING",

                "risk": info["risk"],

                "info": info["info"]

            }


            if info["risk"] == "HIGH":

                score -= 25

            elif info["risk"] == "MEDIUM":

                score -= 15

            else:

                score -= 5



    if score < 0:

        score = 0



    print("\n" + "-" * 40)

    print(
        f"[+] Security Score: {score}/100"
    )


    # Save results for reports

    set_result(
        "headers",
        findings
    )


    set_result(
        "score",
        score
    )


    return findings
