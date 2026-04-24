# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the CLI without installing
uv run sbom-cli

# Run tests
uv run pytest

# Run a single test file
uv run pytest tests/sbom_cli/lib/test_utils.py

# Lint and format
uv run ruff check .
uv run ruff format .

# Install in editable mode for development
uv tool install . --editable

# Reinstall after changes
uv tool install . --reinstall
```

## Architecture

This is a [Typer](https://typer.tiangolo.com/)-based CLI app. The entrypoint is `src/sbom_cli/main.py`, which registers commands and subcommand groups on the root `app = typer.Typer()` instance.

**Two patterns for adding commands:**

1. **Top-level commands** (`ingest`, `query`): decorated with `@app.command()` in `main.py`, delegating to a function imported from `src/sbom_cli/commands/`.

2. **Subcommand groups** (`example`): a separate `typer.Typer()` instance defined in `src/sbom_cli/subcommands/`, then registered via `app.add_typer(example.app, name="example")` in `main.py`. Each command in the group uses `@app.command()` on the subcommand's own `app`.

Shared utilities live in `src/sbom_cli/lib/`. [Rich](https://github.com/Textualize/rich) is available for formatted terminal output (tables, styled text, etc.).

Tests mirror the `src/` layout under `tests/sbom_cli/`.
