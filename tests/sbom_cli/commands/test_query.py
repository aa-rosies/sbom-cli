from pathlib import Path

from typer.testing import CliRunner

from sbom_cli.main import app

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"
runner = CliRunner()


def _ingest(monkeypatch, tmp_path):
    """Helper: ingest the sample fixture into a temp DB."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("SBOM_CLI_DB", str(db_path))
    runner.invoke(app, ["ingest", str(FIXTURES_DIR / "sample-cdx-1.6.json")])
    return db_path


class TestQueryCommand:
    def test_query_component(self, tmp_path, monkeypatch):
        _ingest(monkeypatch, tmp_path)
        result = runner.invoke(app, ["query", "--component", "requests"])
        assert result.exit_code == 0
        assert "requests" in result.output
        assert "2.31.0" in result.output

    def test_query_component_with_version(self, tmp_path, monkeypatch):
        _ingest(monkeypatch, tmp_path)
        result = runner.invoke(app, ["query", "--component", "requests", "--version", "2.31.0"])
        assert result.exit_code == 0
        assert "requests" in result.output

    def test_query_component_no_results(self, tmp_path, monkeypatch):
        _ingest(monkeypatch, tmp_path)
        result = runner.invoke(app, ["query", "--component", "nonexistent"])
        assert result.exit_code == 0
        assert "No components found" in result.output

    def test_query_license(self, tmp_path, monkeypatch):
        _ingest(monkeypatch, tmp_path)
        result = runner.invoke(app, ["query", "--license", "MIT"])
        assert result.exit_code == 0
        assert "urllib3" in result.output

    def test_no_flags_shows_error(self, tmp_path, monkeypatch):
        _ingest(monkeypatch, tmp_path)
        result = runner.invoke(app, ["query"])
        assert result.exit_code == 1
        assert "Provide --component or --license" in result.output

    def test_both_flags_shows_error(self, tmp_path, monkeypatch):
        _ingest(monkeypatch, tmp_path)
        result = runner.invoke(app, ["query", "--component", "x", "--license", "y"])
        assert result.exit_code == 1
        assert "mutually exclusive" in result.output
