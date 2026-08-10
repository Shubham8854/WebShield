from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from pyfiglet import Figlet
import time
import socket


console = Console()


def show_banner():

    fig = Figlet(font="slant")

    logo = fig.renderText("WebShield")


    panel = Panel.fit(

        f"[bold cyan]{logo}[/bold cyan]\n"
        "[bold green]Web Security Assessment Framework[/bold green]\n"
        "[yellow]Version 2.0[/yellow]",

        border_style="bright_blue"

    )


    console.print(
        Align.center(panel)
    )



def loading_animation():

    steps = [

        "Loading Reconnaissance Modules...",
        "Loading Web Security Modules...",
        "Loading Network Scanner...",
        "Loading Reporting Engine...",
        "Initializing Scan Engine..."

    ]


    with Progress(

        SpinnerColumn(),
        TextColumn("[cyan]{task.description}"),
        transient=True

    ) as progress:


        for step in steps:

            task = progress.add_task(
                step,
                total=None
            )

            time.sleep(0.5)

            progress.remove_task(task)


    console.print(
        "[bold green]✓ Framework Ready![/bold green]\n"
    )



def section(title):

    console.print(
        Rule(
            f"[bold cyan]{title}"
        )
    )



def show_target_info(response):

    table = Table(

        title="🎯 TARGET INFORMATION",

        border_style="bright_blue",

        show_lines=True

    )


    table.add_column(
        "Property",
        style="cyan"
    )


    table.add_column(
        "Value"
    )


    hostname = response.url.split("//")[-1].split("/")[0]


    try:

        ip = socket.gethostbyname(hostname)

    except:

        ip = "Unknown"



    table.add_row(
        "🌐 URL",
        response.url
    )


    table.add_row(
        "📡 IP Address",
        ip
    )


    table.add_row(
        "📊 Status",
        str(response.status_code)
    )


    table.add_row(
        "🖥 Server",
        response.headers.get(
            "Server",
            "Unknown"
        )
    )


    table.add_row(
        "📄 Content-Type",
        response.headers.get(
            "Content-Type",
            "Unknown"
        )
    )


    console.print(table)



def show_summary(summary):

    section(
        "📊 FINAL SECURITY SUMMARY"
    )


    table = Table(
        border_style="bright_blue"
    )


    table.add_column(
        "Category",
        style="cyan"
    )


    table.add_column(
        "Value"
    )


    table.add_row(
        "Security Score",
        f"{summary['score']}/100"
    )


    table.add_row(
        "Risk Level",
        summary["rating"]
    )


    table.add_row(
        "Findings",
        str(len(summary["findings"]))
    )


    console.print(table)



    console.print(
        "\n[bold red]Findings:[/bold red]"
    )


    for item in summary["findings"]:

        console.print(
            f" • {item['name']} ({item['risk']})"
        )



    console.print(
        "\n[bold yellow]Recommendations:[/bold yellow]"
    )


    for item in summary["recommendations"]:

        console.print(
            f" → {item}"
        )
def show_security_headers(findings, score):

    table = Table(
        title="🔐 SECURITY HEADERS ANALYSIS",
        border_style="bright_blue",
        show_lines=True
    )


    table.add_column(
        "Header",
        style="cyan"
    )

    table.add_column(
        "Status"
    )

    table.add_column(
        "Risk"
    )

    table.add_column(
        "Description"
    )


    for header, data in findings.items():

        status = data["status"]

        if status == "PRESENT":

            status_display = "[green]✓ PRESENT[/green]"

        else:

            status_display = "[red]✗ MISSING[/red]"



        risk = data["risk"]


        if risk == "HIGH":

            risk_display = "[red]HIGH[/red]"

        elif risk == "MEDIUM":

            risk_display = "[yellow]MEDIUM[/yellow]"

        else:

            risk_display = "[green]LOW[/green]"



        table.add_row(

            header,

            status_display,

            risk_display,

            data["info"]

        )



    console.print(table)



    score_color = (
        "green"
        if score >= 80
        else
        "yellow"
        if score >= 60
        else
        "red"
    )


    console.print(
        Panel(
            f"[bold {score_color}]Security Score: {score}/100[/bold {score_color}]",
            border_style=score_color
        )
    )
def show_ssl_info(ssl_data):

    table = Table(
        title="🔒 SSL / TLS ANALYSIS",
        border_style="bright_blue",
        show_lines=True
    )


    table.add_column(
        "Property",
        style="cyan"
    )

    table.add_column(
        "Value"
    )


    for key, value in ssl_data.items():

        if key == "status":

            if value == "VALID":

                value = "[green]✓ VALID[/green]"

            elif value == "INVALID":

                value = "[red]✗ INVALID[/red]"

            else:

                value = f"[yellow]{value}[/yellow]"


        table.add_row(
            key.replace("_", " ").title(),
            str(value)
        )


    console.print(table)
def show_dns_info(dns_data):

    table = Table(
        title="🌐 DNS INFORMATION",
        border_style="bright_blue",
        show_lines=True
    )

    table.add_column(
        "Record",
        style="cyan",
        width=12
    )

    table.add_column(
        "Value"
    )

    for record in ["A", "AAAA", "MX", "NS"]:

        values = dns_data.get(
            record,
            []
        )

        if values:

            value = "\n".join(
                str(item)
                for item in values
            )

        else:

            value = "[dim]Not Found[/dim]"

        table.add_row(
            record,
            value
        )

    console.print(table)
def show_technology_info(technologies):

    table = Table(
        title="⚙ TECHNOLOGY DETECTION",
        border_style="bright_blue",
        show_lines=True
    )

    table.add_column(
        "Technology Type",
        style="cyan"
    )

    table.add_column(
        "Value"
    )

    for tech in technologies:

        value = tech.get(
            "value",
            "Unknown"
        )

        table.add_row(
            tech.get("type", "Unknown"),
            value if value else "Unknown"
        )

    console.print(table)
def show_port_scan(ports):

    table = Table(
        title="🚪 NETWORK EXPOSURE",
        border_style="bright_blue",
        show_lines=True
    )

    table.add_column(
        "Port",
        style="cyan",
        justify="center"
    )

    table.add_column(
        "Service",
        style="white"
    )

    table.add_column(
        "Status",
        justify="center"
    )


    open_count = 0


    for port in ports:

        status = port.get(
            "status",
            "UNKNOWN"
        )


        if status == "OPEN":

            status_display = "[green]✓ OPEN[/green]"
            open_count += 1

        elif status == "CLOSED":

            status_display = "[dim]✗ CLOSED[/dim]"

        else:

            status_display = "[yellow]⚠ ERROR[/yellow]"


        table.add_row(

            str(port.get("port")),

            port.get(
                "service",
                "Unknown"
            ),

            status_display

        )


    console.print(table)


    if open_count == 0:

        message = "[green]No open common ports detected[/green]"

    elif open_count <= 2:

        message = (
            f"[yellow]{open_count} open common port(s) detected[/yellow]"
        )

    else:

        message = (
            f"[red]{open_count} open common port(s) detected[/red]"
        )


    console.print(
        Panel(
            message,
            border_style="bright_blue"
        )
    )
