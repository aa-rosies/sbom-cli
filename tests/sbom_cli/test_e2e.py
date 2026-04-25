"""End-to-end tests exercising the full CLI via CliRunner."""

from pathlib import Path

from typer.testing import CliRunner

from sbom_cli.main import app

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
runner = CliRunner()


class TestIngestAndQuery:
    """Ingest a fixture, then query it through the CLI."""

    def test_ingest_then_query_component(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CLI_DB", str(tmp_path / "test.db"))
        fixture = str(FIXTURES_DIR / "sample-cdx-1.6.json")

        result = runner.invoke(app, ["ingest", fixture])
        assert result.exit_code == 0

        result = runner.invoke(app, ["query", "--component", "requests"])
        assert result.exit_code == 0
        assert "requests" in result.output
        assert "2.31.0" in result.output

    def test_ingest_then_query_component_with_version(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CLI_DB", str(tmp_path / "test.db"))
        fixture = str(FIXTURES_DIR / "sample-cdx-1.6.json")

        runner.invoke(app, ["ingest", fixture])

        result = runner.invoke(app, ["query", "--component", "requests", "--version", "2.31.0"])
        assert result.exit_code == 0
        assert "requests" in result.output

        result = runner.invoke(app, ["query", "--component", "requests", "--version", "9.9.9"])
        assert result.exit_code == 0
        assert "No components found" in result.output

    def test_ingest_then_query_license(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CLI_DB", str(tmp_path / "test.db"))
        fixture = str(FIXTURES_DIR / "sample-cdx-1.6.json")

        runner.invoke(app, ["ingest", fixture])

        result = runner.invoke(app, ["query", "--license", "MIT"])
        assert result.exit_code == 0
        assert "urllib3" in result.output

    def test_query_on_empty_db(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CLI_DB", str(tmp_path / "test.db"))

        result = runner.invoke(app, ["query", "--component", "anything"])
        assert result.exit_code == 0
        assert "No components found" in result.output
