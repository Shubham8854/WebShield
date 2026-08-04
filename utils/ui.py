from rich.table import Table


def show_target_info(data):

    table = Table(
        title="🎯 Target Information",
        border_style="bright_blue",
        show_header=True,
        header_style="bold cyan"
    )

    table.add_column("Property", style="cyan", width=20)
    table.add_column("Value", style="white")

    table.add_row("URL", data["url"])
    table.add_row("IP Address", data["ip"])
    table.add_row("Status", f"[green]{data['status']}[/green]")
    table.add_row("Server", data["server"])
    table.add_row("Content-Type", data["content_type"])
    table.add_row("Response Time", data["response_time"])

    console.print(table)
from rich.table import Table
import time
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.rule import Rule
from rich.text import Text
from pyfiglet import Figlet

console = Console()


def show_banner():

    fig = Figlet(font="slant")

    logo = fig.renderText("WebShield")

    panel = Panel.fit(
        f"[bold cyan]{logo}[/bold cyan]\n"
        "[bold green]Web Security Assessment Framework[/bold green]\n"
        "[yellow]Version 2.0[/yellow]",
        border_style="bright_blue",
    )

    console.print(Align.center(panel))


def section(title):
    console.print(Rule(f"[bold cyan]{title}"))


def success(message):
    console.print(f"[green]✓[/green] {message}")


def warning(message):
    console.print(f"[yellow]⚠[/yellow] {message}")


def error(message):
    console.print(f"[red]✗[/red] {message}")


def info(message):
    console.print(f"[cyan]ℹ[/cyan] {message}")

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
        transient=True,
    ) as progress:

        for step in steps:
            task = progress.add_task(step, total=None)
            time.sleep(0.6)
            progress.remove_task(task)

    console.print("[bold green]✓ Framework Ready![/bold green]\n")
def show_target_info(response):

    table = Table(title="Target Information", show_lines=True)

    table.add_column("Property", style="cyan", width=20)
    table.add_column("Value", style="green")

    table.add_row("URL", response.url)
    table.add_row("Status", str(response.status_code))
    table.add_row("Server", response.headers.get("Server", "Unknown"))
    table.add_row("Content-Type", response.headers.get("Content-Type", "Unknown"))

    console.print(table)
from rich.table import Table


def show_target_info(response):

    table = Table(
        title="[bold cyan]TARGET INFORMATION[/bold cyan]",
        border_style="bright_blue",
        show_lines=True,
        expand=True,
    )

    table.add_column("Property", style="cyan", width=22)
    table.add_column("Value", style="white")

    table.add_row("🌐 URL", response.url)
    table.add_row("📡 Status", str(response.status_code))
    table.add_row("🖥 Server", response.headers.get("Server", "Unknown"))
    table.add_row("📄 Content-Type", response.headers.get("Content-Type", "Unknown"))

    console.print(table)
