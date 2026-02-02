""" output.py
Console Output & JSON Export Module
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from protocols.base import Result


console = Console()


def print_banner():
    """Display the ITK banner."""
    banner = Text()
    banner.append("╔══════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║  ", style="bold cyan")
    banner.append("ITK", style="bold red")
    banner.append(" - ICS Tool Kit", style="bold white")
    banner.append("                  ║\n", style="bold cyan")
    banner.append("║  ", style="bold cyan")
    banner.append("Industrial Control System Auditor", style="dim white")
    banner.append("   ║\n", style="bold cyan")
    banner.append("╚══════════════════════════════════════╝", style="bold cyan")
    console.print(banner)


def print_result(result: Result, use_json: bool = False):
    """Print a Result object in console or JSON format."""
    if use_json:
        console.print(result.to_json())
        return

    if result.success:
        style = "bold green"
        icon = "SUCCESS"
    else:
        style = "bold red"
        icon = "FAILURE"

    panel = Panel(
        f"[{style}]{icon}[/{style}] {result.operation}\n"
        f"[dim]Protocol:[/dim] {result.protocol}\n"
        f"[dim]Target:[/dim] {result.target}\n"
        f"[dim]Data:[/dim] {result.data if result.success else result.error}",
        title=f"[bold cyan]{result.protocol.upper()}[/bold cyan]",
        border_style="cyan"
    )
    console.print(panel)


def print_table(title: str, columns: list, rows: list):
    """Print data as a styled table."""
    table = Table(title=title, border_style="cyan")
    for col in columns:
        table.add_column(col, style="cyan")
    for row in rows:
        table.add_row(*[str(item) for item in row])
    console.print(table)


def status(message: str, status_type: str = "info"):
    """Print a status message with appropriate styling."""
    styles = {
        "info": ("INFO", "blue"),
        "success": ("SUCCESS", "green"),
        "warning": ("WARNING", "yellow"),
        "error": ("ERROR", "red"),
        "exploit": ("EXPLOIT", "magenta"),
    }
    icon, color = styles.get(status_type, ("•", "white"))
    console.print(f"[bold {color}]{icon}[/bold {color}] {message}")
