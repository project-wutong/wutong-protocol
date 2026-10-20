# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from wtp.cbor_wire import dcbor_dumps, dcbor_loads, sign_cbor_envelope
from wtp.wire import canonical_bytes, sign_envelope

digest_bin = sys.argv[1]
verify_bin = sys.argv[2] if len(sys.argv) > 2 else None

fixtures = [
    b"",
    b"hello Wutong",
    "# 梧桐计划\n".encode(),
    "# 梧桐计划\r\n".encode(),
    b"\xef\xbb\xbfUTF-8 BOM\n",
    bytes(range(256)),
    bytes([i % 256 for i in range(1024 * 128)]),
]

with tempfile.TemporaryDirectory() as td:
    for idx, data in enumerate(fixtures):
        path = pathlib.Path(td) / str(idx)
        path.write_bytes(data)
        actual = subprocess.check_output([digest_bin, str(path)], text=True).strip()
        assert actual == hashlib.sha256(data).hexdigest(), (idx, actual)

if verify_bin:
    # 3-language (Python, Node.js, C++23) JCS & dCBOR encoder + decoder verification
    tricky = [
        {"z": "中文", "a": ["\u2028", "\n", "𝌆", 1, -42, 0, 255, 65536, True, False, None]},
        {"p": {"z": "e\u0301", "a": "é"}, "a": 0, "aa": 1, "b": 2},
        {"p": "\t\b\u0000", "q": "hello/世界"},
    ]
    for obj in tricky:
        raw_in = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        py_jcs = canonical_bytes(obj)
        cpp_jcs = subprocess.check_output([verify_bin, "--jcs"], input=raw_in)
        node_jcs = subprocess.check_output(
            ["node", str(ROOT / "tools" / "jcs_node.cjs")], input=raw_in
        )
        assert py_jcs == cpp_jcs == node_jcs

        py_cbor_hex = dcbor_dumps(obj).hex()
        cpp_cbor_hex = subprocess.check_output(
            [verify_bin, "--dcbor-hex"], input=raw_in
        ).decode("ascii").strip()
        node_cbor_hex = subprocess.check_output(
            ["node", str(ROOT / "tools" / "dcbor_node.cjs")], input=raw_in
        ).decode("ascii").strip()
        assert py_cbor_hex == cpp_cbor_hex == node_cbor_hex

        # Also decode raw dCBOR hex directly inside C++23 back into canonical JCS
        cpp_decoded_jcs = subprocess.check_output(
            [verify_bin, "--dcbor-decode-hex"],
            input=py_cbor_hex.encode("ascii"),
        )
        assert cpp_decoded_jcs == py_jcs

    # Astral-plane UTF-16 sorting check across Python, Node.js, and C++23
    astral_obj = {"\uE000": 1, "𐍈": 2}
    raw_astral = json.dumps(astral_obj, ensure_ascii=False).encode("utf-8")
    py_astral = canonical_bytes(astral_obj, allow_unicode_keys=True)
    cpp_astral = subprocess.check_output(
        [verify_bin, "--jcs", "--unicode-keys"], input=raw_astral
    )
    node_astral = subprocess.check_output(
        ["node", str(ROOT / "tools" / "jcs_node.cjs"), "--unicode-keys"],
        input=raw_astral,
    )
    assert py_astral == cpp_astral == node_astral == '{"𐍈":2,"\ue000":1}'.encode("utf-8")

    # Sign all 24 v0.1.2 examples in Python (both JCS and dCBOR) and verify every single one in C++23 OpenSSL and Node.js
    seed = bytes(range(32))
    pubkey_hex = (ROOT / "vectors" / "public_key.hex").read_text().strip()
    examples = sorted((ROOT / "examples").glob("*.json"))
    assert len(examples) == 24
    for ex_path in examples:
        msg = json.loads(ex_path.read_text())
        signed_json = sign_envelope(
            msg,
            seed,
            signer_id="urn:uuid:019a1111-1111-7111-8111-000000000001",
            key_id="local-key-01",
            issued_at="2026-10-18T10:00:00Z",
            nonce="A" * 24,
        )
        out_json = subprocess.check_output(
            [verify_bin, "--verify", pubkey_hex],
            input=json.dumps(signed_json, ensure_ascii=False).encode("utf-8"),
        )
        assert out_json == b"OK", f"C++23 failed JCS verify on {ex_path.name}"

        signed_cbor_bytes = sign_cbor_envelope(
            msg,
            seed,
            signer_id="urn:uuid:019a1111-1111-7111-8111-000000000001",
            key_id="local-key-01",
            issued_at="2026-10-18T10:00:00Z",
            nonce="B" * 24,
        )
        # Verify directly from raw CBOR hex in C++23
        out_raw_cbor_cpp = subprocess.check_output(
            [verify_bin, "--verify-raw-cbor-hex", pubkey_hex],
            input=signed_cbor_bytes.hex().encode("ascii"),
        )
        assert out_raw_cbor_cpp == b"OK", f"C++23 failed raw dCBOR verify on {ex_path.name}"

        decoded_cbor_env = dcbor_loads(signed_cbor_bytes)
        out_cbor_cpp = subprocess.check_output(
            [verify_bin, "--verify-cbor", pubkey_hex],
            input=json.dumps(decoded_cbor_env, ensure_ascii=False).encode("utf-8"),
        )
        assert out_cbor_cpp == b"OK", f"C++23 failed dCBOR verify on {ex_path.name}"
        out_cbor_node = subprocess.check_output(
            ["node", str(ROOT / "tools" / "dcbor_node.cjs"), "--verify-seed0"],
            input=json.dumps(decoded_cbor_env, ensure_ascii=False).encode("utf-8"),
        )
        assert out_cbor_node == b"OK", f"Node failed dCBOR verify on {ex_path.name}"

print(
    f"PASS: C++23 OpenSSL SHA-256 ({len(fixtures)} vectors) + 3-language (Python/Node/C++23) RFC 8785 JCS, native RFC 8949 dCBOR & 24-kind Ed25519 JSON+CBOR envelope verification"
)
