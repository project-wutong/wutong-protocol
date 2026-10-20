# SPDX-License-Identifier: AGPL-3.0-only
"""Generate cross-language conformance vectors from the Python reference implementation.

Outputs vectors/crosslang/*.json consumed by the Rust core (wutong-core) and other SDKs:
- signatures.json: for every example kind, the unsigned envelope, JCS signing bytes,
  dCBOR hex, Ed25519 JCS signature and dCBOR signature (seed 0x00..0x1f).
- strict_json_negative.json: inputs every strict parser MUST reject.
- task_transitions.json: exhaustive 8x8 Task state matrix.
- relative_paths.json: accepted / rejected portable relative paths.
"""
import json, pathlib, sys, hashlib
ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
sys.path.insert(0, str(ROOT / "src"))
from wtp.wire import sign_envelope, canonical_bytes, strict_loads, WtpError
from wtp.cbor_wire import dcbor_dumps, sign_cbor_envelope
from wtp.policy import TRANSITIONS, check_transition
from wtp.semantic import validate_relative_path

SEED = bytes(range(32))
SIGNER = "urn:uuid:019a1111-1111-7111-8111-000000000001"
out = ROOT / "vectors" / "crosslang"
out.mkdir(parents=True, exist_ok=True)

sigs = []
for p in sorted((ROOT / "examples").glob("*.json")):
    m = json.loads(p.read_text())
    s = sign_envelope(m, SEED, signer_id=SIGNER, key_id="local-key-01",
                      issued_at="2026-10-18T10:00:00Z", nonce="A" * 24)
    unsigned = {k: v for k, v in s.items() if k != "proof"}
    c = sign_cbor_envelope(m, SEED, signer_id=SIGNER, key_id="local-key-01",
                           issued_at="2026-10-18T10:00:00Z", nonce="A" * 24, include_encoding=True)
    sigs.append({
        "name": p.stem,
        "kind": m["kind"],
        "example": m,
        "jcs_unsigned_example": canonical_bytes(m).decode(),
        "jcs_sha256": "sha256:" + hashlib.sha256(canonical_bytes(m)).hexdigest(),
        "dcbor_hex_example": dcbor_dumps(m).hex(),
        "signed_jcs": s,
        "jcs_signing_input": canonical_bytes(unsigned).decode(),
        "signed_dcbor_hex": c.hex(),
    })
(out / "signatures.json").write_text(json.dumps({
    "seed_hex": SEED.hex(), "signer_id": SIGNER, "key_id": "local-key-01",
    "issued_at": "2026-10-18T10:00:00Z", "nonce": "A" * 24, "cases": sigs}, ensure_ascii=False, indent=1))

neg = [b'{"a":1,"a":2}', b'{"x": NaN}', b'{"x":Infinity}', b'{"x":1.2}', b'{"x":9007199254740992}',
       b'{"\xff"}', b'{"x":"\\ud800"}', b'{"\xc3\xa9":1}', b"[" * 41 + b"0" + b"]" * 41,
       b'{"x":1e3}', b'{"x":-9007199254740992}', b'{"x":01}']
rows = []
for raw in neg:
    try:
        strict_loads(raw); rejected = False
    except WtpError:
        rejected = True
    rows.append({"hex": raw.hex(), "python_rejects": rejected})
(out / "strict_json_negative.json").write_text(json.dumps(rows, indent=1))

states = list(TRANSITIONS)
matrix = []
for a in states:
    for b in states:
        try:
            check_transition(a, b); ok = True
        except WtpError:
            ok = False
        matrix.append({"from": a, "to": b, "allowed": ok})
(out / "task_transitions.json").write_text(json.dumps(matrix, indent=1))

paths = ["notes/demo.md", "a/b/c.typ", "中文/笔记.md", "../escape.md", "a/../../secret", "/etc/passwd",
         "C:/Windows/system.ini", "dir\\file.md", "./notes.md", "a//b.md", "a/CON", "file.", "a/trailing ",
         "nul.txt", "LPT1", "com9.md", ""]
pr = []
for x in paths:
    try:
        validate_relative_path(x); ok = True
    except WtpError:
        ok = False
    pr.append({"path": x, "valid": ok})
(out / "relative_paths.json").write_text(json.dumps(pr, ensure_ascii=False, indent=1))
print("wrote", len(sigs), "signature cases")
