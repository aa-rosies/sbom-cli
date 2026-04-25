import json
from pathlib import Path

import pytest

from sbom_cli.lib.sbom import load_and_validate

FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"


class TestLoadAndValidate:
    def test_loads_valid_file(self):
        data = load_and_validate(FIXTURES_DIR / "sample-cdx-1.6.json")
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.6"

    def test_rejects_wrong_format(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text(json.dumps({"bomFormat": "SPDX", "specVersion": "1.6"}))
        with pytest.raises(ValueError, match="Unsupported BOM format"):
            load_and_validate(f)

    def test_rejects_wrong_version(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.4"}))
        with pytest.raises(ValueError, match="Unsupported spec version"):
            load_and_validate(f)

    def test_rejects_non_object(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("[]")
        with pytest.raises(ValueError, match="must contain a JSON object"):
            load_and_validate(f)
