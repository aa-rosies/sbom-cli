import os
import sqlite3
from pathlib import Path

from sbom_cli.db.schema import init_schema

DEFAULT_DB_DIR = Path.home() / ".sbom-cli"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "sbom.db"


def get_db_path() -> Path:
    env = os.environ.get("SBOM_CLI_DB")
    if env:
        return Path(env)
    return DEFAULT_DB_PATH


def get_connection(db_path: Path | str = None) -> sqlite3.Connection:
    if db_path is None:
        db_path = get_db_path()
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    init_schema(conn)
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    init_schema(conn)
