# SPDX-License-Identifier: AGPL-3.0-only
import copy
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
V012_ROOT = ROOT.parent

for label, schema_path, examples_dir, expected_count in [
    ("legacy-9-kind", ROOT / "schemas" / "wutong-core.schema.json", ROOT / "examples", 9),
    ("v0.1.2-24-kind", V012_ROOT / "schemas" / "core.schema.json", V012_ROOT / "examples", 24),
]:
    schema = json.loads(schema_path.read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    Draft202012Validator.check_schema(schema)
    examples = sorted(examples_dir.glob("*.json"))
    assert len(examples) == expected_count, (label, len(examples))
    for f in examples:
        msg = json.loads(f.read_text())
        errors = list(validator.iter_errors(msg))
        assert not errors, (label, f.name, errors)
        bad = copy.deepcopy(msg)
        bad["protocol"] = "wutong/999"
        assert not validator.is_valid(bad), f"protocol accepted: {f.name}"
        bad = copy.deepcopy(msg)
        bad["id"] = "relative/path"
        assert not validator.is_valid(bad), f"non-UUID ID accepted: {f.name}"
        bad = copy.deepcopy(msg)
        bad["evil"] = "unexpected"
        assert not validator.is_valid(bad), f"unknown top field accepted: {f.name}"
        bad = copy.deepcopy(msg)
        bad["payload"].pop(next(iter(bad["payload"])))
        assert not validator.is_valid(bad), f"missing required payload field accepted: {f.name}"

# Also verify OpenAPI 3.1.0 specification structure
openapi = json.loads((V012_ROOT / "openapi" / "wutong-federation-v0.1.openapi.json").read_text())
assert openapi["openapi"] == "3.1.0"
assert openapi["info"]["version"] == "0.1.2"
assert len(openapi["paths"]) == 7

print("PASS: 24 v0.1.2 examples + 9 legacy examples, 132 negative-schema checks, OpenAPI 3.1.0 & JSON Schema Draft 2020-12 valid")
