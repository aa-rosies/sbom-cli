import sqlite3

SCHEMA_VERSION = 1

MIGRATIONS = {
    1: [
        """
        CREATE TABLE bom (
            id              INTEGER PRIMARY KEY,
            serial_number   TEXT UNIQUE,
            version         INTEGER NOT NULL DEFAULT 1,
            spec_version    TEXT NOT NULL,
            source_path     TEXT NOT NULL,
            ingested_at     TEXT NOT NULL DEFAULT (datetime('now')),
            metadata_json   TEXT
        )
        """,
        """
        CREATE TABLE component (
            id              INTEGER PRIMARY KEY,
            bom_id          INTEGER NOT NULL REFERENCES bom(id) ON DELETE CASCADE,
            type            TEXT NOT NULL,
            name            TEXT NOT NULL,
            version         TEXT,
            purl            TEXT,
            cpe             TEXT,
            bom_ref         TEXT,
            group_name      TEXT,
            publisher       TEXT,
            description     TEXT,
            scope           TEXT,
            hashes_json     TEXT,
            external_refs_json TEXT,
            properties_json TEXT,
            UNIQUE(bom_id, bom_ref)
        )
        """,
        "CREATE INDEX idx_component_name_version ON component(name, version)",
        "CREATE INDEX idx_component_purl ON component(purl)",
        "CREATE INDEX idx_component_bom ON component(bom_id)",
        """
        CREATE TABLE license (
            id              INTEGER PRIMARY KEY,
            license_id      TEXT,
            license_name    TEXT,
            UNIQUE(license_id, license_name)
        )
        """,
        "CREATE INDEX idx_license_id ON license(license_id)",
        "CREATE INDEX idx_license_name ON license(license_name)",
        """
        CREATE TABLE component_license (
            component_id    INTEGER NOT NULL REFERENCES component(id) ON DELETE CASCADE,
            license_id      INTEGER NOT NULL REFERENCES license(id) ON DELETE CASCADE,
            PRIMARY KEY (component_id, license_id)
        )
        """,
        "CREATE INDEX idx_cl_license ON component_license(license_id)",
        """
        CREATE TABLE dependency (
            id              INTEGER PRIMARY KEY,
            bom_id          INTEGER NOT NULL REFERENCES bom(id) ON DELETE CASCADE,
            ref             TEXT NOT NULL,
            depends_on_ref  TEXT NOT NULL,
            UNIQUE(bom_id, ref, depends_on_ref)
        )
        """,
        "CREATE INDEX idx_dep_ref ON dependency(bom_id, ref)",
        "CREATE INDEX idx_dep_depends ON dependency(bom_id, depends_on_ref)",
    ],
}


def get_schema_version(conn: sqlite3.Connection) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(f"PRAGMA user_version = {version}")


def init_schema(conn: sqlite3.Connection) -> None:
    current = get_schema_version(conn)
    if current >= SCHEMA_VERSION:
        return
    for ver in range(current + 1, SCHEMA_VERSION + 1):
        statements = MIGRATIONS[ver]
        for stmt in statements:
            conn.execute(stmt)
        set_schema_version(conn, ver)
    conn.commit()
