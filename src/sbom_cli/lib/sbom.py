import json
from pathlib import Path


def load_and_validate(filepath: Path) -> dict:
    """Load a JSON file and validate it is a CycloneDX 1.6 SBOM."""
    with open(filepath) as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("SBOM file must contain a JSON object")

    bom_format = data.get("bomFormat")
    if bom_format != "CycloneDX":
        raise ValueError(
            f"Unsupported BOM format: {bom_format!r} (expected 'CycloneDX')"
        )

    spec_version = data.get("specVersion")
    if spec_version != "1.6":
        raise ValueError(
            f"Unsupported spec version: {spec_version!r} (expected '1.6')"
        )

    return data
