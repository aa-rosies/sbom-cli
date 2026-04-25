import platform

import typer
from rich.console import Console
from rich.table import Table

from sbom_cli.lib.utils import truncate

app = typer.Typer(help="Example subcommand", no_args_is_help=True)

console = Console()


@app.command()
def info():
    """Print basic system information."""
    table = Table()
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="magenta")
    table.add_row("OS", f"{platform.system()} {platform.release()}")
    table.add_row("Python", platform.python_version())
    table.add_row("Machine", truncate(platform.machine(), 20))

    console.print(table)
