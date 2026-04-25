import json
from pathlib import Path

from typer.testing import CliRunner

from sbom_cli.main import app

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"
runner = CliRunner()


class TestIngestCommand:
    def test_ingest_valid_sbom(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test.db"
        monkeypatch.setenv("SBOM_CLI_DB", str(db_path))

        result = runner.invoke(app, ["ingest", str(FIXTURES_DIR / "sample-cdx-1.6.json")])
        assert result.exit_code == 0
        assert "Ingested" in result.output
        assert "5 components" in result.output

    def test_ingest_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CLI_DB", str(tmp_path / "test.db"))

        result = runner.invoke(app, ["ingest", "/nonexistent/file.json"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_ingest_invalid_format(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SBOM_CLI_DB", str(tmp_path / "test.db"))

        bad_file = tmp_path / "bad.json"
        bad_file.write_text(json.dumps({"bomFormat": "SPDX", "specVersion": "1.6"}))

        result = runner.invoke(app, ["ingest", str(bad_file)])
        assert result.exit_code == 1
        assert "Unsupported BOM format" in result.output

    def test_ingest_requires_filepath_arg(self):
        result = runner.invoke(app, ["ingest"])
        assert result.exit_code != 0
