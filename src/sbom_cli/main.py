from pathlib import Path
from typing import Annotated, Optional

import typer

from sbom_cli.commands.ingest import ingest_command
from sbom_cli.commands.query import query_command
from sbom_cli.subcommands import example

app = typer.Typer(no_args_is_help=True)
app.add_typer(example.app, name="example")


def version_callback(value: bool):
    if value:
        from importlib.metadata import version
        typer.echo(version("sbom_cli"))
        raise typer.Exit()


# noinspection PyUnusedLocal
@app.callback()
def main(
        version: Annotated[
            Optional[bool],
            typer.Option("--version", "-v", callback=version_callback, is_eager=True, help="Show version and exit.")
        ] = None,
):
    pass


@app.command()
def ingest(
    filepath: Annotated[Path, typer.Argument(help="Path to a CycloneDX 1.6 JSON SBOM file")],
):
    """Ingest a CycloneDX 1.6 SBOM file"""
    ingest_command(filepath)


@app.command()
def query(
    component: Annotated[Optional[str], typer.Option("--component", "-c", help="Component name to search")] = None,
    version: Annotated[Optional[str], typer.Option("--version", help="Version filter (requires --component)")] = None,
    license: Annotated[Optional[str], typer.Option("--license", "-l", help="License to search")] = None,
):
    """Query ingested SBOM data"""
    query_command(component, version, license)


if __name__ == "__main__":
    app()
