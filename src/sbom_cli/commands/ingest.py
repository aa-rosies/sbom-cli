from pathlib import Path

import typer

from sbom_cli.db import get_connection, init_db
from sbom_cli.db.repository import insert_bom
from sbom_cli.lib.output import console
from sbom_cli.lib.sbom import load_and_validate


def ingest_command(filepath: Path) -> None:
    """Parse and store a CycloneDX 1.6 JSON SBOM."""
    if not filepath.exists():
        console.print(f"[red]Error:[/red] File not found: {filepath}")
        raise typer.Exit(code=1)

    try:
        sbom = load_and_validate(filepath)
    except (ValueError, Exception) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1)

    conn = get_connection()
    try:
        init_db(conn)
        bom_id = insert_bom(conn, sbom, str(filepath.resolve()))
        component_count = conn.execute(
            "SELECT COUNT(*) FROM component WHERE bom_id = ?", (bom_id,)
        ).fetchone()[0]
        console.print(
            f"[green]Ingested[/green] {filepath.name}: "
            f"{component_count} components (bom id: {bom_id})"
        )
    finally:
        conn.close()
