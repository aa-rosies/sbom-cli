from dataclasses import dataclass


@dataclass
class Bom:
    id: int | None
    serial_number: str | None
    version: int
    spec_version: str
    source_path: str
    ingested_at: str | None = None
    metadata_json: str | None = None


@dataclass
class Component:
    id: int | None
    bom_id: int
    type: str
    name: str
    version: str | None = None
    purl: str | None = None
    cpe: str | None = None
    bom_ref: str | None = None
    group_name: str | None = None
    publisher: str | None = None
    description: str | None = None
    scope: str | None = None
    hashes_json: str | None = None
    external_refs_json: str | None = None
    properties_json: str | None = None


@dataclass
class License:
    id: int | None
    license_id: str | None = None
    license_name: str | None = None
