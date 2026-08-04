from datetime import datetime


def generate_html(data, filename="webshield_report"):

    html = f"""
<!DOCTYPE html>

<html>

<head>

<title>WebShield Report</title>

<style>

body {{
    font-family: Arial;
    margin: 40px;
}}

h1 {{
    color: #333;
}}

.box {{
    padding: 20px;
    border: 1px solid #ccc;
}}

</style>

</head>


<body>


<h1>WebShield Security Report</h1>


<div class="box">


<p><b>Scan Time:</b> {datetime.now()}</p>

<p><b>Target:</b> {data.get("target")}</p>

<p><b>Security Score:</b> {data.get("score")}/100</p>

<p><b>Rating:</b> {data.get("rating")}</p>


<h3>Findings</h3>

<ul>

"""


    for finding in data.get("findings", []):

        html += f"<li>{finding}</li>"


    html += """

</ul>


</div>


</body>


</html>

"""


    with open(
        f"reports/{filename}.html",
        "w"
    ) as file:

        file.write(html)


    print(
        "[+] HTML Report Generated"
    )
