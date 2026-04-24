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
def ingest():
    """Ingest SBOM data"""
    ingest_command()


@app.command()
def query():
    """Query SBOM data"""
    query_command()


if __name__ == "__main__":
    app()
