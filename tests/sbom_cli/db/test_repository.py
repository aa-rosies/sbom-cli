import json
import sqlite3
from pathlib import Path

import pytest

from sbom_cli.db import init_db
from sbom_cli.db.repository import insert_bom, query_by_license, query_components
from sbom_cli.lib.sbom import load_and_validate

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    init_db(c)
    yield c
    c.close()


@pytest.fixture
def sample_sbom():
    return load_and_validate(FIXTURES_DIR / "sample-cdx-1.6.json")


@pytest.fixture
def second_sbom():
    return load_and_validate(FIXTURES_DIR / "sample-cdx-1.6-second.json")


class TestInsertBom:
    def test_inserts_bom_record(self, conn, sample_sbom):
        bom_id = insert_bom(conn, sample_sbom, "/tmp/test.json")

        row = conn.execute("SELECT * FROM bom WHERE id = ?", (bom_id,)).fetchone()
        assert row["serial_number"] == "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
        assert row["spec_version"] == "1.6"
        assert row["version"] == 1
        assert row["source_path"] == "/tmp/test.json"

    def test_inserts_components(self, conn, sample_sbom):
        bom_id = insert_bom(conn, sample_sbom, "/tmp/test.json")

        rows = conn.execute(
            "SELECT name, version, purl, type FROM component WHERE bom_id = ? ORDER BY name",
            (bom_id,),
        ).fetchall()
        names = [r["name"] for r in rows]
        # 4 components + 1 metadata component
        assert "requests" in names
        assert "urllib3" in names
        assert "certifi" in names
        assert "idna" in names
        assert "my-app" in names

    def test_inserts_licenses(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")

        licenses = conn.execute("SELECT license_id, license_name FROM license ORDER BY license_id").fetchall()
        license_ids = [r["license_id"] for r in licenses]
        assert "Apache-2.0" in license_ids
        assert "MIT" in license_ids
        assert "BSD-3-Clause" in license_ids

        # certifi has a freeform name, not an SPDX id
        license_names = [r["license_name"] for r in licenses]
        assert "Mozilla Public License 2.0" in license_names

    def test_links_component_licenses(self, conn, sample_sbom):
        bom_id = insert_bom(conn, sample_sbom, "/tmp/test.json")

        rows = conn.execute(
            """
            SELECT c.name, l.license_id, l.license_name
            FROM component c
            JOIN component_license cl ON cl.component_id = c.id
            JOIN license l ON l.id = cl.license_id
            WHERE c.bom_id = ?
            ORDER BY c.name
            """,
            (bom_id,),
        ).fetchall()
        by_name = {r["name"]: r for r in rows}
        assert by_name["requests"]["license_id"] == "Apache-2.0"
        assert by_name["urllib3"]["license_id"] == "MIT"
        assert by_name["certifi"]["license_name"] == "Mozilla Public License 2.0"

    def test_inserts_dependencies(self, conn, sample_sbom):
        bom_id = insert_bom(conn, sample_sbom, "/tmp/test.json")

        rows = conn.execute(
            "SELECT ref, depends_on_ref FROM dependency WHERE bom_id = ? ORDER BY ref, depends_on_ref",
            (bom_id,),
        ).fetchall()
        deps = [(r["ref"], r["depends_on_ref"]) for r in rows]
        assert ("my-app", "requests") in deps
        assert ("requests", "urllib3") in deps
        assert ("requests", "certifi") in deps
        assert ("requests", "idna") in deps

    def test_stores_hashes_as_json(self, conn, sample_sbom):
        bom_id = insert_bom(conn, sample_sbom, "/tmp/test.json")

        row = conn.execute(
            "SELECT hashes_json FROM component WHERE bom_id = ? AND name = 'requests'",
            (bom_id,),
        ).fetchone()
        hashes = json.loads(row["hashes_json"])
        assert hashes[0]["alg"] == "SHA-256"

    def test_duplicate_serial_number_raises(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        with pytest.raises(sqlite3.IntegrityError):
            insert_bom(conn, sample_sbom, "/tmp/test2.json")

    def test_stores_metadata_json(self, conn, sample_sbom):
        bom_id = insert_bom(conn, sample_sbom, "/tmp/test.json")

        row = conn.execute("SELECT metadata_json FROM bom WHERE id = ?", (bom_id,)).fetchone()
        metadata = json.loads(row["metadata_json"])
        assert metadata["timestamp"] == "2024-01-15T10:00:00Z"

    def test_multiple_boms(self, conn, sample_sbom, second_sbom):
        bom_id_1 = insert_bom(conn, sample_sbom, "/tmp/first.json")
        bom_id_2 = insert_bom(conn, second_sbom, "/tmp/second.json")

        assert bom_id_1 != bom_id_2
        bom_count = conn.execute("SELECT COUNT(*) FROM bom").fetchone()[0]
        assert bom_count == 2

    def test_multiple_boms_components_isolated(self, conn, sample_sbom, second_sbom):
        bom_id_1 = insert_bom(conn, sample_sbom, "/tmp/first.json")
        bom_id_2 = insert_bom(conn, second_sbom, "/tmp/second.json")

        count_1 = conn.execute(
            "SELECT COUNT(*) FROM component WHERE bom_id = ?", (bom_id_1,)
        ).fetchone()[0]
        count_2 = conn.execute(
            "SELECT COUNT(*) FROM component WHERE bom_id = ?", (bom_id_2,)
        ).fetchone()[0]
        assert count_1 == 5  # 4 components + metadata component
        assert count_2 == 4  # 3 components + metadata component

    def test_multiple_boms_shared_license_deduplication(self, conn, sample_sbom, second_sbom):
        """BSD-3-Clause appears in both BOMs but should be one license row."""
        insert_bom(conn, sample_sbom, "/tmp/first.json")
        insert_bom(conn, second_sbom, "/tmp/second.json")

        bsd_rows = conn.execute(
            "SELECT COUNT(*) FROM license WHERE license_id = 'BSD-3-Clause'"
        ).fetchone()[0]
        assert bsd_rows == 1


class TestQueryComponents:
    def test_exact_name_match(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_components(conn, "requests")
        assert len(rows) == 1
        assert rows[0]["name"] == "requests"
        assert rows[0]["version"] == "2.31.0"

    def test_name_with_version(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_components(conn, "requests", version="2.31.0")
        assert len(rows) == 1
        assert rows[0]["purl"] == "pkg:pypi/requests@2.31.0"

    def test_wrong_version_returns_empty(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_components(conn, "requests", version="9.9.9")
        assert rows == []

    def test_no_match_returns_empty(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_components(conn, "nonexistent")
        assert rows == []

    def test_substring_does_not_match(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_components(conn, "req")
        assert rows == []

    def test_includes_source_path(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_components(conn, "requests")
        assert rows[0]["source_path"] == "/tmp/test.json"

    def test_same_name_different_versions_across_boms(self, conn, sample_sbom, second_sbom):
        """requests 2.31.0 in first BOM, requests 2.32.0 in second."""
        insert_bom(conn, sample_sbom, "/tmp/first.json")
        insert_bom(conn, second_sbom, "/tmp/second.json")

        rows = query_components(conn, "requests")
        assert len(rows) == 2
        versions = {r["version"] for r in rows}
        assert versions == {"2.31.0", "2.32.0"}

    def test_same_name_filtered_by_version(self, conn, sample_sbom, second_sbom):
        insert_bom(conn, sample_sbom, "/tmp/first.json")
        insert_bom(conn, second_sbom, "/tmp/second.json")

        rows = query_components(conn, "requests", version="2.32.0")
        assert len(rows) == 1
        assert rows[0]["source_path"] == "/tmp/second.json"


class TestQueryByLicense:
    def test_spdx_id_match(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_by_license(conn, "MIT")
        assert len(rows) == 1
        assert rows[0]["name"] == "urllib3"

    def test_spdx_id_case_insensitive(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_by_license(conn, "mit")
        assert len(rows) == 1
        assert rows[0]["name"] == "urllib3"

    def test_freeform_name_match(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_by_license(conn, "Mozilla")
        assert len(rows) == 1
        assert rows[0]["name"] == "certifi"

    def test_no_match_returns_empty(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_by_license(conn, "AGPL-3.0")
        assert rows == []

    def test_includes_license_info(self, conn, sample_sbom):
        insert_bom(conn, sample_sbom, "/tmp/test.json")
        rows = query_by_license(conn, "Apache-2.0")
        assert len(rows) == 1
        assert rows[0]["license_id"] == "Apache-2.0"
        assert rows[0]["name"] == "requests"

    def test_multiple_components_same_license(self, conn, second_sbom):
        """flask and click both have BSD-3-Clause in the second fixture."""
        insert_bom(conn, second_sbom, "/tmp/second.json")

        rows = query_by_license(conn, "BSD-3-Clause")
        names = {r["name"] for r in rows}
        assert "flask" in names
        assert "click" in names
        assert len(rows) == 2

    def test_shared_license_across_boms(self, conn, sample_sbom, second_sbom):
        """BSD-3-Clause used by idna (first BOM) and flask+click (second BOM)."""
        insert_bom(conn, sample_sbom, "/tmp/first.json")
        insert_bom(conn, second_sbom, "/tmp/second.json")

        rows = query_by_license(conn, "BSD-3-Clause")
        names = {r["name"] for r in rows}
        assert names == {"idna", "flask", "click"}

    def test_license_query_across_boms(self, conn, sample_sbom, second_sbom):
        """Apache-2.0 used by requests in both BOMs (different versions)."""
        insert_bom(conn, sample_sbom, "/tmp/first.json")
        insert_bom(conn, second_sbom, "/tmp/second.json")

        rows = query_by_license(conn, "Apache-2.0")
        assert len(rows) == 2
        versions = {r["version"] for r in rows}
        assert versions == {"2.31.0", "2.32.0"}
