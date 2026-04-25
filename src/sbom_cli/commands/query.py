from pathlib import PurePosixPath

import typer
from rich.table import Table

from sbom_cli.db import get_connection
from sbom_cli.db.repository import query_by_license, query_components
from sbom_cli.lib.output import console


def query_command(
        component: str | None, version: str | None, license: str | None
) -> None:
    """Query ingested SBOM data by component or license."""
    if component and license:
        console.print("[red]Error:[/red] --component and --license are mutually exclusive")
        raise typer.Exit(code=1)
    if not component and not license:
        console.print("[red]Error:[/red] Provide --component or --license")
        raise typer.Exit(code=1)
    if version and not component:
        console.print("[red]Error:[/red] --version requires --component")
        raise typer.Exit(code=1)

    conn = get_connection()
    try:
        if component:
            _show_components(conn, component, version)
        else:
            _show_by_license(conn, license)
    finally:
        conn.close()


def _show_components(conn, name: str, version: str | None) -> None:
    rows = query_components(conn, name, version)
    if not rows:
        console.print("No components found.")
        return

    table = Table()
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("Type")
    table.add_column("PURL", style="dim")
    table.add_column("BOM", style="dim")

    for row in rows:
        filename = PurePosixPath(row["source_path"]).name
        table.add_row(
            row["name"],
            row["version"] or "",
            row["type"],
            row["purl"] or "",
            f"{filename} (#{row['bom_id']})",
        )

    console.print(table)


def _show_by_license(conn, license: str) -> None:
    rows = query_by_license(conn, license)
    if not rows:
        console.print("No components found.")
        return

    table = Table()
    table.add_column("Name", style="cyan")
    table.add_column("Version", style="green")
    table.add_column("License")
    table.add_column("PURL", style="dim")
    table.add_column("BOM", style="dim")

    for row in rows:
        license_display = row["license_id"] or row["license_name"] or ""
        filename = PurePosixPath(row["source_path"]).name
        table.add_row(
            row["name"],
            row["version"] or "",
            license_display,
            row["purl"] or "",
            f"{filename} (#{row['bom_id']})",
        )

    console.print(table)
