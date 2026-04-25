import json
import sqlite3


def insert_bom(conn: sqlite3.Connection, sbom: dict, source_path: str) -> int:
    """Insert a CycloneDX SBOM into the database. Returns the bom id."""
    with conn:
        # Insert BOM record
        metadata = sbom.get("metadata")
        bom_id = conn.execute(
            """
            INSERT INTO bom (serial_number, version, spec_version, source_path, metadata_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                sbom.get("serialNumber"),
                sbom.get("version", 1),
                sbom["specVersion"],
                source_path,
                json.dumps(metadata) if metadata else None,
            ),
        ).lastrowid

        # Insert components
        components = sbom.get("components", [])
        component_id_by_ref: dict[str, int] = {}
        for comp in components:
            comp_id = _insert_component(conn, bom_id, comp)
            bom_ref = comp.get("bom-ref")
            if bom_ref:
                component_id_by_ref[bom_ref] = comp_id

        # Also handle the metadata component if present
        if metadata and "component" in metadata:
            meta_comp = metadata["component"]
            comp_id = _insert_component(conn, bom_id, meta_comp)
            bom_ref = meta_comp.get("bom-ref")
            if bom_ref:
                component_id_by_ref[bom_ref] = comp_id

        # Insert dependencies
        for dep in sbom.get("dependencies", []):
            ref = dep.get("ref")
            for depends_on in dep.get("dependsOn", []):
                conn.execute(
                    """
                    INSERT OR IGNORE INTO dependency (bom_id, ref, depends_on_ref)
                    VALUES (?, ?, ?)
                    """,
                    (bom_id, ref, depends_on),
                )

    return bom_id


def _insert_component(conn: sqlite3.Connection, bom_id: int, comp: dict) -> int:
    """Insert a single component and its licenses. Returns the component id."""
    hashes = comp.get("hashes")
    ext_refs = comp.get("externalReferences")
    properties = comp.get("properties")

    comp_id = conn.execute(
        """
        INSERT INTO component
            (bom_id, type, name, version, purl, cpe, bom_ref,
             group_name, publisher, description, scope,
             hashes_json, external_refs_json, properties_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            bom_id,
            comp.get("type", "library"),
            comp["name"],
            comp.get("version"),
            comp.get("purl"),
            comp.get("cpe"),
            comp.get("bom-ref"),
            comp.get("group"),
            comp.get("publisher"),
            comp.get("description"),
            comp.get("scope"),
            json.dumps(hashes) if hashes else None,
            json.dumps(ext_refs) if ext_refs else None,
            json.dumps(properties) if properties else None,
        ),
    ).lastrowid

    # Insert licenses
    for license_entry in comp.get("licenses", []):
        _link_license(conn, comp_id, license_entry)

    return comp_id


def _link_license(
    conn: sqlite3.Connection, component_id: int, license_entry: dict
) -> None:
    """Resolve or create a license record and link it to a component."""
    lic = license_entry.get("license", {})
    license_id = lic.get("id")  # SPDX identifier
    license_name = lic.get("name")  # freeform name

    # Also handle SPDX expression at the entry level
    if not license_id and not license_name:
        expression = license_entry.get("expression")
        if expression:
            license_id = expression

    if not license_id and not license_name:
        return

    # Upsert license
    row = conn.execute(
        "SELECT id FROM license WHERE license_id IS ? AND license_name IS ?",
        (license_id, license_name),
    ).fetchone()

    if row:
        lic_row_id = row[0]
    else:
        lic_row_id = conn.execute(
            "INSERT INTO license (license_id, license_name) VALUES (?, ?)",
            (license_id, license_name),
        ).lastrowid

    conn.execute(
        "INSERT OR IGNORE INTO component_license (component_id, license_id) VALUES (?, ?)",
        (component_id, lic_row_id),
    )


