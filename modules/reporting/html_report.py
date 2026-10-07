from datetime import datetime
from html import escape


def generate_html(data, filename="webshield_report"):

    score = data.get("score", 0)
    rating = data.get("rating", "UNKNOWN")

    headers = data.get("headers", {})
    ssl_data = data.get("ssl", {})
    dns_data = data.get("dns", {})
    ports = data.get("ports", [])
    technologies = data.get("technology", [])
    findings = data.get("findings", [])
    recommendations = data.get("recommendations", [])

    # --------------------------------------------------
    # Score styling
    # --------------------------------------------------

    if score >= 80:
        score_color = "#00ff88"
        risk_class = "low"
        risk_icon = "🟢"

    elif score >= 60:
        score_color = "#ffaa00"
        risk_class = "medium"
        risk_icon = "🟡"

    else:
        score_color = "#ff4444"
        risk_class = "high"
        risk_icon = "🔴"

    # --------------------------------------------------
    # Statistics
    # --------------------------------------------------

    missing_headers = sum(
        1
        for value in headers.values()
        if value.get("status") == "MISSING"
    )

    open_ports = sum(
        1
        for port in ports
        if port.get("status") == "OPEN"
    )

    total_ports = len(ports)

    # --------------------------------------------------
    # Security headers
    # --------------------------------------------------

    header_rows = ""

    for header, info in headers.items():

        status = info.get("status", "UNKNOWN")
        risk = info.get("risk", "UNKNOWN")

        if status == "PRESENT":
            status_html = '<span class="status-present">✓ PRESENT</span>'
        else:
            status_html = '<span class="status-missing">✗ MISSING</span>'

        header_rows += f"""
        <tr>
            <td>{escape(str(header))}</td>
            <td>{status_html}</td>
            <td>
                <span class="risk {risk.lower()}">
                    {escape(str(risk))}
                </span>
            </td>
        </tr>
        """

    # --------------------------------------------------
    # Findings
    # --------------------------------------------------

    finding_html = ""

    if findings:

        for finding in findings:

            name = escape(
                str(finding.get("name", "Unknown"))
            )

            risk = finding.get(
                "risk",
                "UNKNOWN"
            )

            finding_html += f"""
            <div class="finding">
                <div>
                    <strong>{name}</strong>
                </div>

                <span class="risk {risk.lower()}">
                    {escape(str(risk))}
                </span>
            </div>
            """

    else:

        finding_html = """
        <div class="success-message">
            ✓ No major security findings detected.
        </div>
        """

    # --------------------------------------------------
    # Recommendations
    # --------------------------------------------------

    recommendation_html = ""

    if recommendations:

        for recommendation in recommendations:

            recommendation_html += f"""
            <div class="recommendation">
                <span>→</span>
                <span>{escape(str(recommendation))}</span>
            </div>
            """

    else:

        recommendation_html = """
        <div class="success-message">
            ✓ No recommendations required.
        </div>
        """

    # --------------------------------------------------
    # SSL
    # --------------------------------------------------

    ssl_status = ssl_data.get(
        "status",
        "UNKNOWN"
    )

    if ssl_status == "VALID":
        ssl_badge = '<span class="status-present">✓ VALID</span>'
    elif ssl_status == "INVALID":
        ssl_badge = '<span class="status-missing">✗ INVALID</span>'
    else:
        ssl_badge = '<span class="status-warning">⚠ FAILED</span>'

    ssl_rows = ""

    for key, value in ssl_data.items():

        ssl_rows += f"""
        <tr>
            <td>{escape(str(key).replace("_", " ").title())}</td>
            <td>{escape(str(value))}</td>
        </tr>
        """

    # --------------------------------------------------
    # DNS
    # --------------------------------------------------

    dns_rows = ""

    for record_type, values in dns_data.items():

        if isinstance(values, list):

            value = ", ".join(
                str(item)
                for item in values
            )

        else:

            value = str(values)

        if not value:
            value = "None"

        dns_rows += f"""
        <tr>
            <td>{escape(str(record_type))}</td>
            <td>{escape(value)}</td>
        </tr>
        """

    # --------------------------------------------------
    # Ports
    # --------------------------------------------------

    port_rows = ""

    for port in ports:

        status = port.get(
            "status",
            "UNKNOWN"
        )

        if status == "OPEN":

            status_html = """
            <span class="status-open">
                🔴 OPEN
            </span>
            """

        else:

            status_html = """
            <span class="status-closed">
                ✓ CLOSED
            </span>
            """

        port_rows += f"""
        <tr>
            <td>{escape(str(port.get("port", "")))}</td>
            <td>{escape(str(port.get("service", "")))}</td>
            <td>{status_html}</td>
        </tr>
        """

    # --------------------------------------------------
    # Technology
    # --------------------------------------------------

    technology_html = ""

    for tech in technologies:

        if isinstance(tech, dict):

            tech_type = escape(
                str(tech.get("type", "Technology"))
            )

            tech_value = escape(
                str(tech.get("value", "Unknown"))
            )

            technology_html += f"""
            <div class="tech-item">
                <span>{tech_type}</span>
                <strong>{tech_value}</strong>
            </div>
            """

        else:

            technology_html += f"""
            <div class="tech-item">
                <strong>{escape(str(tech))}</strong>
            </div>
            """

    if not technology_html:

        technology_html = """
        <div class="muted">
            No technology information detected.
        </div>
        """

    # --------------------------------------------------
    # Final HTML
    # --------------------------------------------------

    html = f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1.0">

<title>WebShield 2.0 Security Report</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    background:
        radial-gradient(
            circle at top right,
            #14213d,
            #070b12 45%
        );

    color: #f8fafc;

    font-family:
        "Segoe UI",
        Arial,
        sans-serif;

    min-height: 100vh;

}}

.container {{

    max-width: 1200px;

    margin: auto;

    padding: 35px 25px 60px;

}}

.header {{

    background:
        linear-gradient(
            135deg,
            #0066ff,
            #00c6ff
        );

    border-radius: 20px;

    padding: 35px;

    text-align: center;

    box-shadow:
        0 15px 40px
        rgba(0,0,0,0.35);

}}

.logo {{

    font-size: 48px;

    margin-bottom: 5px;

}}

.header h1 {{

    margin: 0;

    font-size: 36px;

}}

.header p {{

    margin-top: 8px;

    opacity: 0.9;

    font-size: 17px;

}}

.meta {{

    display: grid;

    grid-template-columns:
        repeat(auto-fit, minmax(250px, 1fr));

    gap: 15px;

    margin-top: 20px;

}}

.meta-card {{

    background: #111827;

    border: 1px solid #263244;

    border-radius: 12px;

    padding: 18px;

}}

.meta-label {{

    color: #94a3b8;

    font-size: 13px;

    text-transform: uppercase;

    letter-spacing: 1px;

}}

.meta-value {{

    margin-top: 7px;

    font-size: 17px;

    font-weight: 600;

    word-break: break-word;

}}

.card {{

    background:
        rgba(17,24,39,0.92);

    border:
        1px solid #263244;

    border-radius: 18px;

    padding: 25px;

    margin-top: 22px;

    box-shadow:
        0 10px 30px
        rgba(0,0,0,0.22);

}}

.card h2 {{

    margin-top: 0;

    color: #38bdf8;

}}

.score-card {{

    text-align: center;

}}

.score {{

    font-size: 82px;

    line-height: 1;

    font-weight: 800;

    color: {score_color};

    margin: 20px 0 10px;

}}

.score-label {{

    color: #94a3b8;

    font-size: 14px;

    letter-spacing: 2px;

}}

.risk-badge {{

    display: inline-block;

    margin-top: 15px;

    padding: 9px 20px;

    border-radius: 999px;

    font-weight: bold;

    color: {score_color};

    border: 1px solid {score_color};

    background: rgba(255,255,255,0.03);

}}

.stats {{

    display: grid;

    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));

    gap: 15px;

    margin-top: 25px;

}}

.stat {{

    background: #0b1220;

    border: 1px solid #263244;

    border-radius: 12px;

    padding: 20px;

    text-align: center;

}}

.stat-number {{

    font-size: 30px;

    font-weight: bold;

}}

.stat-label {{

    color: #94a3b8;

    margin-top: 5px;

}}

table {{

    width: 100%;

    border-collapse: collapse;

}}

th {{

    background: #1e293b;

    color: #38bdf8;

    text-align: left;

}}

td,
th {{

    padding: 14px;

    border-bottom:
        1px solid #263244;

}}

tr:hover {{

    background: #172033;

}}

.status-present,
.status-open {{

    color: #00ff88;

    font-weight: bold;

}}

.status-missing {{

    color: #ff4444;

    font-weight: bold;

}}

.status-warning {{

    color: #ffaa00;

    font-weight: bold;

}}

.status-closed {{

    color: #64748b;

}}

.risk {{

    font-weight: bold;

}}

.high {{

    color: #ff4444;

}}

.medium {{

    color: #ffaa00;

}}

.low {{

    color: #00ff88;

}}

.finding {{

    display: flex;

    justify-content: space-between;

    align-items: center;

    padding: 15px;

    margin-bottom: 10px;

    border-radius: 10px;

    background: #0b1220;

    border-left: 4px solid #ff4444;

}}

.recommendation {{

    display: flex;

    gap: 12px;

    padding: 13px;

    margin-bottom: 8px;

    border-radius: 8px;

    background: #0b1220;

    color: #cbd5e1;

}}

.recommendation span:first-child {{

    color: #38bdf8;

    font-weight: bold;

}}

.success-message {{

    color: #00ff88;

    padding: 15px;

    background: #062016;

    border-radius: 10px;

}}

.tech-item {{

    display: flex;

    justify-content: space-between;

    padding: 15px;

    margin-bottom: 8px;

    background: #0b1220;

    border-radius: 9px;

}}

.muted {{

    color: #64748b;

}}

.footer {{

    text-align: center;

    margin-top: 45px;

    color: #64748b;

    line-height: 1.8;

}}

@media(max-width:700px) {{

    .container {{
        padding: 15px;
    }}

    .header h1 {{
        font-size: 27px;
    }}

    .score {{
        font-size: 60px;
    }}

    .card {{
        padding: 18px;
        overflow-x: auto;
    }}

}}

</style>

</head>


<body>


<div class="container">


<!-- HEADER -->

<div class="header">

<div class="logo">🛡️</div>

<h1>WebShield 2.0</h1>

<p>
Web Security Assessment Framework
</p>

</div>


<!-- META -->

<div class="meta">

<div class="meta-card">

<div class="meta-label">
Target
</div>

<div class="meta-value">
{escape(str(data.get("target", "Unknown")))}
</div>

</div>


<div class="meta-card">

<div class="meta-label">
Scan Time
</div>

<div class="meta-value">
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</div>

</div>

</div>


<!-- SCORE -->

<div class="card score-card">

<h2>📊 Security Overview</h2>

<div class="score">
{score}
</div>

<div class="score-label">
SECURITY SCORE / 100
</div>

<div class="risk-badge">
{risk_icon} {escape(str(rating))} RISK
</div>


<div class="stats">

<div class="stat">

<div class="stat-number">
{missing_headers}
</div>

<div class="stat-label">
Missing Headers
</div>

</div>


<div class="stat">

<div class="stat-number">
{open_ports}
</div>

<div class="stat-label">
Open Ports
</div>

</div>


<div class="stat">

<div class="stat-number">
{total_ports}
</div>

<div class="stat-label">
Ports Tested
</div>

</div>


<div class="stat">

<div class="stat-number">
{len(findings)}
</div>

<div class="stat-label">
Security Findings
</div>

</div>

</div>

</div>


<!-- FINDINGS -->

<div class="card">

<h2>🚨 Security Findings</h2>

{finding_html}

</div>


<!-- RECOMMENDATIONS -->

<div class="card">

<h2>🛠 Recommendations</h2>

{recommendation_html}

</div>


<!-- HEADERS -->

<div class="card">

<h2>🔐 Security Headers</h2>

<table>

<tr>
<th>Header</th>
<th>Status</th>
<th>Risk</th>
</tr>

{header_rows}

</table>

</div>


<!-- SSL -->

<div class="card">

<h2>🔒 SSL / TLS Analysis</h2>

<p>
Status: {ssl_badge}
</p>

<table>

{ssl_rows}

</table>

</div>


<!-- DNS -->

<div class="card">

<h2>🌐 DNS Information</h2>

<table>

{dns_rows}

</table>

</div>


<!-- PORTS -->

<div class="card">

<h2>🚪 Network Exposure</h2>

<table>

<tr>
<th>Port</th>
<th>Service</th>
<th>Status</th>
</tr>

{port_rows}

</table>

</div>


<!-- TECHNOLOGY -->

<div class="card">

<h2>⚙️ Technology Detection</h2>

{technology_html}

</div>


<!-- FOOTER -->

<div class="footer">

<strong>WebShield 2.0</strong><br>

Web Security Assessment Framework<br>

Generated automatically from authorized security assessment data.

</div>


</div>


</body>

</html>
"""

    with open(
        f"reports/{filename}.html",
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print(
        "[+] Professional HTML Report Generated"
    )
