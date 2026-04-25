import sqlite3
from pathlib import Path

import pytest
import typer

from sbom_cli.db import init_db
from sbom_cli.db.repository import insert_bom
from sbom_cli.lib.sbom import load_and_validate
from sbom_cli.commands.query import query_command

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


@pytest.fixture
def populated_db(tmp_path, monkeypatch):
    """Create a temp DB with sample data and point SBOM_CLI_DB at it."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("SBOM_CLI_DB", str(db_path))
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    sbom = load_and_validate(FIXTURES_DIR / "sample-cdx-1.6.json")
    insert_bom(conn, sbom, "/tmp/test.json")
    conn.close()


class TestQueryCommand:
    def test_no_flags_exits_with_error(self):
        with pytest.raises(typer.Exit) as exc_info:
            query_command(None, None, None)
        assert exc_info.value.exit_code == 1

    def test_both_flags_exits_with_error(self):
        with pytest.raises(typer.Exit) as exc_info:
            query_command("requests", None, "MIT")
        assert exc_info.value.exit_code == 1

    def test_version_without_component_exits_with_error(self):
        with pytest.raises(typer.Exit) as exc_info:
            query_command(None, "1.0", None)
        assert exc_info.value.exit_code == 1

    def test_query_component(self, populated_db, capsys):
        query_command("requests", None, None)
        # No exception means success; actual query results tested in test_repository.py

    def test_query_license(self, populated_db, capsys):
        query_command(None, None, "MIT")

    def test_query_no_results(self, populated_db, capsys):
        query_command("nonexistent", None, None)
