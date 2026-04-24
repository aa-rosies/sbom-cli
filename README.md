# sbom-cli

`sbom-cli` CLI app for Manifest Cyber.

## Tooling

- [uv](https://docs.astral.sh/uv/) for dependency and tool management
- [Typer](https://typer.tiangolo.com/) for CLI development
- [pytest](https://docs.pytest.org/) for testing
- [ruff](https://ruff.rs/) for linting and formatting

See [`pyproject.toml`](./pyproject.toml) for configuration details.

All commands and subcommands are self-documenting via the `--help` flag.

## Project Structure

```
sbom-cli/
├── src/
│   └── sbom_cli/
│       ├── __init__.py
│       ├── main.py
│       ├── commands/
│       │   ├── __init__.py
│       │   ├── greet.py
│       │   └── system.py
│       └── lib/
│           ├── __init__.py
│           └── utils.py
├── tests/
│   └── sbom_cli/
│       ├── __init__.py
│       ├── commands/
│       │   ├── __init__.py
│       │   ├── test_greet.py
│       │   └── test_system.py
│       └── lib/
│           ├── __init__.py
│           └── test_utils.py
└── pyproject.toml
```

## Setup

1. Install [`mise`](https://mise.jdx.dev/)
2. Run `mise trust` in the root of the repo
3. Run `mise install` to install required tools
4. Run `uv sync` to install dependencies

### Development

```bash
# Install sbom-cli in editable mode for development
uv tool install . --editable

# Run without installing
uv run sbom-cli

# Run tests
uv run pytest

# Reinstall after changes
uv tool install . --reinstall
```

### Installation

```bash
# Install as a global CLI tool
uv tool install .

# Reinstall if already installed
uv tool install . --reinstall
```

After install, `sbom-cli` is available as a standalone command in your shell.

#### Autocompletion

To enable autocompletion for `sbom-cli`, run the following command:

```bash
sbom-cli --install-completion
```
