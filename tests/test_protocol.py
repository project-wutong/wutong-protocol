# SPDX-License-Identifier: AGPL-3.0-only
import copy
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
try:
    import pytest
except ImportError:
    from wtp import testshim as pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

from wtp.cbor_wire import (
    dcbor_dumps,
    dcbor_loads,
    sign_cbor_envelope,
    verify_cbor_envelope,
)
from wtp.document_patch import apply_source_patches, validate_provenance
from wtp.e2ee import (
    DecryptionError,
    SpaceEpochKeyring,
    create_space_epoch_envelope,
    open_encrypted_envelope,
    seal_encrypted_envelope,
    unwrap_space_epoch_for_member,
)
from wtp.federation import (
    FederationNode,
    InteropProjectionTracker,
    RevisionDAG,
    compute_http_content_digest,
    reanchor_annotation,
    validate_federation_endpoint,
    verify_http_content_digest,
)
from wtp.filecoord import FileConflict, FileCoordinator, SimulatedCrash, sha
from wtp.policy import (
    TRANSITIONS,
    KeyRegistry,
    authorize_chain,
    authorize_signed_capability_chain,
    check_transition,
)
from wtp.replay import DurableReplayLedger
from wtp.semantic import validate_relative_path, validate_semantics
from wtp.sync import SyncReplica, negotiate_sync_codec, synchronize_replicas
from wtp.wire import (
    ED25519_L,
    EquivocationError,
    ReplayCache,
    ReplayError,
    WtpError,
    b64u,
    canonical_bytes,
    canonical_sha256,
    deb64u,
    sign_envelope,
    strict_loads,
    validate_public_key_hex,
    verify_envelope,
)

P = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = json.loads((P / "schemas/core.schema.json").read_text())
VALIDATOR = Draft202012Validator(SCHEMA, format_checker=FormatChecker())
FILES = sorted((P / "examples").glob("*.json"))
U = lambda n: f"urn:uuid:019a1111-1111-7111-8111-{n:012x}"
NOW = dt.datetime(2026, 10, 18, 10, 0, tzinfo=dt.timezone.utc)

SEED = bytes(range(32))
PRIV = Ed25519PrivateKey.from_private_bytes(SEED)
PUB = PRIV.public_key()
PUB_HEX = PUB.public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
).hex()

SEED2 = bytes(range(1, 33))
PRIV2 = Ed25519PrivateKey.from_private_bytes(SEED2)
PUB2 = PRIV2.public_key()
PUB2_HEX = PUB2.public_key_bytes if hasattr(PUB2, "public_key_bytes") else PUB2.public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
).hex()

SEED3 = bytes(range(2, 34))
PRIV3 = Ed25519PrivateKey.from_private_bytes(SEED3)
PUB3 = PRIV3.public_key()
PUB3_HEX = PUB3.public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
).hex()


def sample():
    return json.loads((P / "examples/object.json").read_text())


def sign(
    m,
    nonce="A" * 24,
    seed=SEED,
    signer_id=None,
    key_id="local-key-01",
    issued_at="2026-10-18T10:00:00Z",
):
    return sign_envelope(
        m,
        seed,
        signer_id=signer_id or U(1),
        key_id=key_id,
        issued_at=issued_at,
        nonce=nonce,
    )


def lookup(signer, key):
    if signer == U(1) and key == "local-key-01":
        return PUB
    if signer == U(2) and key == "local-key-02":
        return PUB2
    return None


def test_24_examples_and_openapi_present():
    assert len(FILES) == 24
    openapi = json.loads((P / "openapi/wutong-federation-v0.1.openapi.json").read_text())
    assert openapi["openapi"] == "3.1.0"
    assert openapi["info"]["version"] == "0.1.2"
    assert len(openapi["paths"]) == 7


@pytest.mark.parametrize("path", FILES, ids=lambda x: x.stem)
def test_valid_messages(path):
    m = strict_loads(path.read_bytes())
    VALIDATOR.validate(m)


@pytest.mark.parametrize("path", FILES, ids=lambda x: x.stem)
def test_missing_required_payload_rejected(path):
    m = json.loads(path.read_text())
    m["payload"].pop(next(iter(m["payload"])))
    assert not VALIDATOR.is_valid(m)


@pytest.mark.parametrize("path", FILES, ids=lambda x: x.stem)
def test_unknown_payload_member_rejected(path):
    m = json.loads(path.read_text())
    m["payload"]["UNRECOGNIZED"] = 5
    assert not VALIDATOR.is_valid(m)


def test_metaschema_and_urn_id():
    Draft202012Validator.check_schema(SCHEMA)
    assert SCHEMA["$id"] == "urn:wutong:schema:core:0.1.2"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"x": NaN}',
        b'{"x":Infinity}',
        b'{"x":1.2}',
        b'{"x":9007199254740992}',
        b'{"\xff"}',
        b'{"x":"\\ud800"}',
        b'{"\xc3\xa9":1}',
        b"[" * 41 + b"0" + b"]" * 41,
    ],
)
def test_strict_json_rejections(raw):
    with pytest.raises(WtpError):
        strict_loads(raw)


def test_service_invocation_and_signed_receipt_closure(tmp_path):
    root = U(1)
    agent = U(2)
    obj = U(4)
    reg = KeyRegistry()
    reg.register_trust_root(root, "local-key-01", PUB_HEX, binding_id=U(8501))
    reg.register_trust_root(agent, "local-key-02", PUB2_HEX, binding_id=U(8502))
    ledger = DurableReplayLedger(tmp_path / "rpc.sqlite")
    node = FederationNode(
        node_id=U(500),
        operator_id=root,
        base_url="https://node-a.wutong.space",
        key_id="local-key-01",
        private_seed=SEED,
        registry=reg,
        replay_ledger=ledger,
    )

    cap_id = U(7501)
    cap = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.capability",
            "id": U(7502),
            "occurred_at": "2026-10-18T00:00:00Z",
            "payload": {
                "capability_id": cap_id,
                "issuer_id": root,
                "audience_id": agent,
                "resource_ref": obj,
                "actions": ["document.propose"],
                "not_before": "2026-10-18T00:00:00Z",
                "expires_at": "2026-10-19T00:00:00Z",
                "delegable": False,
            },
        },
        seed=SEED,
        signer_id=root,
        key_id="local-key-01",
        issued_at="2026-10-18T00:00:00Z",
        nonce="CAP7501" + "A" * 17,
    )
    inv = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.service_invocation",
            "id": U(7503),
            "occurred_at": "2026-10-18T10:00:00Z",
            "payload": {
                "invocation_id": U(7504),
                "service_id": U(311),
                "action": "document.propose",
                "caller_id": agent,
                "target_ref": obj,
                "capability_ids": [cap_id],
                "arguments": {"mode": "minimal-patch"},
                "idempotency_key": "idem-v012-0001",
            },
        },
        seed=SEED2,
        signer_id=agent,
        key_id="local-key-02",
        issued_at="2026-10-18T10:00:00Z",
        nonce="INV7503" + "B" * 17,
    )
    VALIDATOR.validate(inv)
    assert validate_semantics(inv)

    receipt = node.invoke_protected_action(
        inv,
        signed_capabilities=[cap],
        root_owner=root,
        resource_ref=obj,
        action="document.propose",
        revocation_freshness_at="2026-10-18T09:55:00Z",
        now=NOW,
    )
    VALIDATOR.validate(receipt)
    assert validate_semantics(receipt)
    assert verify_envelope(receipt, reg.lookup_key, now=NOW)
    assert receipt["payload"]["status"] == "accepted"
    assert receipt["payload"]["request_id"] == inv["id"]
    ledger.close()


def test_key_compromise_retroactive_rejection_vs_notarized_archive():
    root = U(1)
    reg = KeyRegistry()
    reg.register_trust_root(
        root,
        "key-compromised-v1",
        PUB_HEX,
        binding_id=U(9101),
        valid_from="2026-10-01T00:00:00Z",
        valid_until="2026-12-01T00:00:00Z",
    )
    reg.register_trust_root(
        root,
        "key-recovery-v2",
        PUB2_HEX,
        binding_id=U(9102),
        valid_from="2026-10-01T00:00:00Z",
        valid_until="2026-12-01T00:00:00Z",
    )
    rev_comp = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.revocation",
            "id": U(9103),
            "occurred_at": "2026-10-16T00:00:00Z",
            "payload": {
                "revocation_id": U(9104),
                "issuer_id": root,
                "target_kind": "key_binding",
                "target_id": U(9101),
                "revoked_at": "2026-10-16T00:00:00Z",
                "effective_from": "2026-10-16T00:00:00Z",
                "reason": "compromised",
            },
        },
        seed=SEED2,
        signer_id=root,
        key_id="key-recovery-v2",
        issued_at="2026-10-16T00:00:00Z",
        nonce="COMP" * 6,
    )
    reg.register_signed_revocation(rev_comp)

    backdated_attack = sign(
        sample(),
        seed=SEED,
        signer_id=root,
        key_id="key-compromised-v1",
        issued_at="2026-10-10T00:00:00Z",
        nonce="BACK" * 6,
    )
    with pytest.raises(WtpError, match="ERR_KEY_REVOKED"):
        verify_envelope(backdated_attack, reg.lookup_key, mode="archive")

    assert (
        reg.lookup_key(
            root,
            "key-compromised-v1",
            at_time="2026-10-10T00:00:00Z",
            notarized_before_revocation=True,
        )
        is not None
    )


def test_capability_temporal_issuance_monotonicity():
    root = U(1)
    agent = U(2)
    sub = U(3)
    obj = U(4)
    reg = KeyRegistry()
    reg.register_trust_root(root, "root-k1", PUB_HEX, binding_id=U(8601))
    reg.register_trust_root(agent, "agent-k1", PUB2_HEX, binding_id=U(8602))
    reg.register_trust_root(sub, "sub-k1", PUB3_HEX, binding_id=U(8603))

    c1_id = U(7601)
    c1 = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.capability",
            "id": U(7611),
            "occurred_at": "2026-10-18T02:00:00Z",
            "payload": {
                "capability_id": c1_id,
                "issuer_id": root,
                "audience_id": agent,
                "resource_ref": obj,
                "actions": ["document.propose"],
                "not_before": "2026-10-18T02:00:00Z",
                "expires_at": "2026-10-19T00:00:00Z",
                "delegable": True,
            },
        },
        seed=SEED,
        signer_id=root,
        key_id="root-k1",
        issued_at="2026-10-18T02:00:00Z",
        nonce="TC1" * 8,
    )
    c2_backdated = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.capability",
            "id": U(7612),
            "occurred_at": "2026-10-18T01:00:00Z",
            "payload": {
                "capability_id": U(7602),
                "issuer_id": agent,
                "audience_id": sub,
                "resource_ref": obj,
                "actions": ["document.propose"],
                "not_before": "2026-10-18T02:00:00Z",
                "expires_at": "2026-10-18T20:00:00Z",
                "delegable": False,
                "parent_id": c1_id,
            },
        },
        seed=SEED2,
        signer_id=agent,
        key_id="agent-k1",
        issued_at="2026-10-18T01:00:00Z",
        nonce="TC2" * 8,
    )
    assert not authorize_signed_capability_chain(
        [c1, c2_backdated],
        registry=reg,
        root_owner=root,
        actor=sub,
        resource=obj,
        action="document.propose",
        at="2026-10-18T10:00:00Z",
        revocation_freshness_at="2026-10-18T09:55:00Z",
    )


def test_sync_ephemeral_presence_isolated_from_durable_dag():
    space_id = U(300)
    object_id = U(301)
    session_id = U(302)
    peer_a = SyncReplica(
        principal_id=U(1),
        key_id="local-key-01",
        private_seed=SEED,
        space_id=space_id,
        object_id=object_id,
    )
    peer_b = SyncReplica(
        principal_id=U(2),
        key_id="local-key-02",
        private_seed=SEED2,
        space_id=space_id,
        object_id=object_id,
    )
    pres = peer_a.build_presence_frame(
        session_id=session_id,
        frame_id=U(399),
        presence_state="typing",
        ttl_seconds=15,
    )
    VALIDATOR.validate(pres)
    assert validate_semantics(pres)
    info = peer_b.ingest_presence_frame(pres, lookup_public_key=lookup, now=NOW)
    assert info["state"] == "typing"
    assert info["ttl_seconds"] == 15
    assert len(peer_b.chunks) == 0
    assert len(peer_b.heads) == 0


def test_ed25519_malleability_s_ge_l_and_small_order_keys_rejected():
    m = sign(sample())
    raw_sig = deb64u(m["proof"]["sig"])
    r_part = raw_sig[:32]
    s_part = int.from_bytes(raw_sig[32:64], "little")
    malleable_s = (s_part + ED25519_L).to_bytes(32, "little")
    m_malleable = copy.deepcopy(m)
    m_malleable["proof"]["sig"] = b64u(r_part + malleable_s)
    with pytest.raises(WtpError, match="non-canonical Ed25519 scalar"):
        verify_envelope(m_malleable, lookup, now=NOW)

    for weak_hex in (
        "00" * 32,
        "01" + "00" * 31,
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ):
        with pytest.raises(WtpError, match="ERR_KEY_UNBOUND"):
            validate_public_key_hex(weak_hex)


def test_cross_encoding_cbor_to_json_gateway_verification():
    cbor_bytes = sign_cbor_envelope(
        sample(),
        SEED,
        signer_id=U(1),
        key_id="local-key-01",
        issued_at="2026-10-18T10:00:00Z",
        nonce="XGW" * 8,
        include_encoding=True,
    )
    transcoded_json_dict = dcbor_loads(cbor_bytes)
    assert transcoded_json_dict["proof"]["encoding"] == "dcbor"
    VALIDATOR.validate(transcoded_json_dict)
    assert verify_envelope(transcoded_json_dict, lookup, now=NOW)

    jcs_signed = sign_envelope(
        sample(),
        SEED,
        signer_id=U(1),
        key_id="local-key-01",
        issued_at="2026-10-18T10:00:00Z",
        nonce="JGW" * 8,
        include_encoding=True,
    )
    transcoded_cbor = dcbor_dumps(jcs_signed)
    assert verify_cbor_envelope(transcoded_cbor, lookup, now=NOW)["id"] == jcs_signed["id"]


def test_multi_member_space_epoch_wrapping_and_post_removal_secrecy():
    space_id = U(200)
    admin_id = U(1)
    alice_id = U(2)
    bob_id = U(3)

    alice_x_seed = bytes([0xA1] * 32)
    alice_x_pub = (
        X25519PrivateKey.from_private_bytes(alice_x_seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    bob_x_seed = bytes([0xB2] * 32)
    bob_x_pub = (
        X25519PrivateKey.from_private_bytes(bob_x_seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )

    reg = KeyRegistry()
    reg.register_trust_root(admin_id, "admin-ed-01", PUB_HEX, binding_id=U(8101))
    reg.register_trust_root(alice_id, "alice-ed-01", PUB2_HEX, binding_id=U(8102))
    reg.register_trust_root(bob_id, "bob-ed-01", PUB3_HEX, binding_id=U(8103))

    alice_kb = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.key_binding",
            "id": U(8104),
            "occurred_at": "2026-10-18T00:00:00Z",
            "payload": {
                "binding_id": U(8105),
                "principal_id": alice_id,
                "key_id": "alice-x25519-01",
                "alg": "X25519",
                "public_key": alice_x_pub,
                "purposes": ["encryption"],
                "valid_from": "2026-10-18T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            },
        },
        seed=SEED2,
        signer_id=alice_id,
        key_id="alice-ed-01",
        issued_at="2026-10-18T00:00:00Z",
        nonce="AKB" * 8,
    )
    bob_kb = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.key_binding",
            "id": U(8106),
            "occurred_at": "2026-10-18T00:00:00Z",
            "payload": {
                "binding_id": U(8107),
                "principal_id": bob_id,
                "key_id": "bob-x25519-01",
                "alg": "X25519",
                "public_key": bob_x_pub,
                "purposes": ["encryption"],
                "valid_from": "2026-10-18T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            },
        },
        seed=SEED3,
        signer_id=bob_id,
        key_id="bob-ed-01",
        issued_at="2026-10-18T00:00:00Z",
        nonce="BKB" * 8,
    )
    VALIDATOR.validate(alice_kb)
    VALIDATOR.validate(bob_kb)
    reg.register_signed_key_binding(alice_kb)
    reg.register_signed_key_binding(bob_kb)

    admin_keyring = SpaceEpochKeyring(space_id)
    admin_keyring.advance_epoch(
        epoch_secret=bytes([0x11] * 32),
        x25519_seed=bytes([0x22] * 32),
        key_id="epoch-0001",
    )
    ep1_env = create_space_epoch_envelope(
        admin_keyring,
        envelope_id=U(8201),
        epoch_id=U(8202),
        occurred_at="2026-10-18T10:00:00Z",
        issuer_id=admin_id,
        issuer_key_id="admin-ed-01",
        issuer_seed=SEED,
        members=[(alice_id, "alice-x25519-01"), (bob_id, "bob-x25519-01")],
        registry=reg,
        outer_nonce="EP1" * 8,
    )
    VALIDATOR.validate(ep1_env)
    assert validate_semantics(ep1_env)

    alice_keyring = SpaceEpochKeyring(space_id)
    bob_keyring = SpaceEpochKeyring(space_id)
    unwrap_space_epoch_for_member(
        ep1_env,
        member_id=alice_id,
        member_key_id="alice-x25519-01",
        member_x25519_seed=alice_x_seed,
        target_keyring=alice_keyring,
        lookup_public_key=reg.lookup_key,
        now=NOW,
    )
    unwrap_space_epoch_for_member(
        ep1_env,
        member_id=bob_id,
        member_key_id="bob-x25519-01",
        member_x25519_seed=bob_x_seed,
        target_keyring=bob_keyring,
        lookup_public_key=reg.lookup_key,
        now=NOW,
    )

    admin_keyring.advance_epoch(
        epoch_secret=bytes([0x33] * 32),
        x25519_seed=bytes([0x44] * 32),
        key_id="epoch-0002",
    )
    ep2_env = create_space_epoch_envelope(
        admin_keyring,
        envelope_id=U(8203),
        epoch_id=U(8204),
        occurred_at="2026-10-18T10:00:00Z",
        issuer_id=admin_id,
        issuer_key_id="admin-ed-01",
        issuer_seed=SEED,
        members=[(alice_id, "alice-x25519-01")],
        registry=reg,
        outer_nonce="EP2" * 8,
    )
    unwrap_space_epoch_for_member(
        ep2_env,
        member_id=alice_id,
        member_key_id="alice-x25519-01",
        member_x25519_seed=alice_x_seed,
        target_keyring=alice_keyring,
        lookup_public_key=reg.lookup_key,
        now=NOW,
    )
    with pytest.raises(DecryptionError, match="not authorized in space_epoch"):
        unwrap_space_epoch_for_member(
            ep2_env,
            member_id=bob_id,
            member_key_id="bob-x25519-01",
            member_x25519_seed=bob_x_seed,
            target_keyring=bob_keyring,
            lookup_public_key=reg.lookup_key,
            now=NOW,
        )


def test_source_first_minimal_patches_and_w3c_prov_o():
    base_doc = "# 梧桐计划\r\n原始段落 A。\r\n原始段落 B。\r\n".encode("utf-8")
    target_sub = "原始段落 A。".encode("utf-8")
    start_idx = base_doc.index(target_sub)
    end_idx = start_idx + len(target_sub)
    replacement_str = "经 Agent 最小补丁修订的段落 A。"
    expected_after = (
        base_doc[:start_idx]
        + replacement_str.encode("utf-8")
        + base_doc[end_idx:]
    )

    prop = json.loads((P / "examples/proposal.json").read_text())
    prop["payload"]["intent"] = "patch"
    prop["payload"]["base_digest"] = "sha256:" + hashlib.sha256(base_doc).hexdigest()
    prop["payload"]["proposed_digest"] = (
        "sha256:" + hashlib.sha256(expected_after).hexdigest()
    )
    prop["payload"]["patches"] = [
        {
            "start_byte": start_idx,
            "end_byte": end_idx,
            "expected_slice_digest": "sha256:" + hashlib.sha256(target_sub).hexdigest(),
            "replacement": replacement_str,
        }
    ]
    prop["payload"]["provenance"] = {
        "was_generated_by": "wutong.agent.patch-proposer/1.0",
        "was_associated_with": U(2),
        "was_derived_from": [U(101)],
        "used": ["urn:wutong:tool:minimal-diff"],
        "tool_id": "minimal-diff-v1",
        "reviewer_id": U(1),
    }
    VALIDATOR.validate(prop)
    assert validate_semantics(prop, body=base_doc)

    bad_prov = copy.deepcopy(prop["payload"]["provenance"])
    bad_prov["reviewer_id"] = U(2)
    with pytest.raises(WtpError, match="self-review forbidden"):
        validate_provenance(bad_prov)

    leak_prov = copy.deepcopy(prop["payload"]["provenance"])
    leak_prov["tool_id"] = "Bearer secret_token_123456"
    with pytest.raises(WtpError, match="credential leak"):
        validate_provenance(leak_prov)


def test_critical_extensions_negotiation():
    m = sample()
    m["extensions"] = {"org.wutong.experimental_guard": {"level": 2}}
    m["critical"] = ["org.wutong.experimental_guard"]
    signed = sign(m)
    VALIDATOR.validate(signed)

    with pytest.raises(WtpError, match="ERR_VERSION"):
        verify_envelope(signed, lookup, now=NOW)

    assert verify_envelope(
        signed,
        lookup,
        now=NOW,
        supported_extensions=("org.wutong.experimental_guard",),
    )

    bad = sample()
    bad["extensions"] = {"org.wutong.other": 1}
    bad["critical"] = ["org.wutong.missing"]
    signed_bad = sign(bad)
    with pytest.raises(WtpError, match="ERR_SCHEMA"):
        verify_envelope(
            signed_bad,
            lookup,
            now=NOW,
            supported_extensions=("org.wutong.missing",),
        )


def test_rfc8949_dcbor_and_cross_language_node_verify():
    obj = {"aa": 1, "b": 2, "a": 0, "neg": -500, "arr": [True, False, None, "梧桐"]}
    raw_cbor = dcbor_dumps(obj)
    node_hex = subprocess.check_output(
        ["node", str(P / "tools/dcbor_node.cjs")],
        input=json.dumps(obj, ensure_ascii=False).encode("utf-8"),
    ).decode("ascii")
    assert raw_cbor.hex() == node_hex
    assert dcbor_loads(raw_cbor) == obj

    cbor_signed = sign_cbor_envelope(
        sample(),
        SEED,
        signer_id=U(1),
        key_id="local-key-01",
        issued_at="2026-10-18T10:00:00Z",
        nonce="CBOR" * 6,
    )
    decoded_msg = verify_cbor_envelope(cbor_signed, lookup, now=NOW)
    assert decoded_msg["kind"] == "wutong.object"
    node_verify = subprocess.check_output(
        ["node", str(P / "tools/dcbor_node.cjs"), "--verify-seed0"],
        input=json.dumps(decoded_msg, ensure_ascii=False).encode("utf-8"),
    )
    assert node_verify == b"OK"

    for bad_cbor in (
        bytes.fromhex("1801"),
        bytes.fromhex("1900ff"),
        bytes.fromhex("9fff"),
        bytes.fromhex("4100"),
        bytes.fromhex("a2616201616102"),
        bytes.fromhex("a2616101616102"),
        raw_cbor + b"\x00",
    ):
        with pytest.raises(WtpError, match="ERR_SCHEMA"):
            dcbor_loads(bad_cbor)


def test_space_e2ee_epoch_rotation_and_verify_then_decrypt():
    space_id = U(200)
    keyring = SpaceEpochKeyring(space_id)
    keyring.advance_epoch(
        epoch_secret=bytes([0x11] * 32),
        x25519_seed=bytes([0x22] * 32),
        key_id="epoch-0001",
    )

    inner_signed = sign(sample(), nonce="INNER" * 5)
    sealed_ep1 = seal_encrypted_envelope(
        inner_signed,
        envelope_id=U(9901),
        occurred_at="2026-10-18T10:00:00Z",
        keyring=keyring,
        signer_seed=SEED,
        signer_id=U(1),
        signer_key_id="local-key-01",
        issued_at="2026-10-18T10:00:00Z",
        outer_nonce="OUTER1" * 4,
    )
    VALIDATOR.validate(sealed_ep1)
    assert validate_semantics(sealed_ep1)

    opened = open_encrypted_envelope(
        sealed_ep1, keyring=keyring, lookup_public_key=lookup, now=NOW
    )
    assert opened == inner_signed

    tampered_outer = copy.deepcopy(sealed_ep1)
    tampered_outer["occurred_at"] = "2026-10-18T10:00:09Z"
    with pytest.raises(WtpError, match="ERR_SIGNATURE"):
        open_encrypted_envelope(
            tampered_outer, keyring=keyring, lookup_public_key=lookup, now=NOW
        )

    removed_member_keyring = SpaceEpochKeyring(space_id)
    removed_member_keyring.epochs[1] = keyring.epochs[1]
    removed_member_keyring.current_epoch = 1

    keyring.advance_epoch(
        epoch_secret=bytes([0x33] * 32),
        x25519_seed=bytes([0x44] * 32),
        key_id="epoch-0002",
    )
    sealed_ep2 = seal_encrypted_envelope(
        inner_signed,
        envelope_id=U(9902),
        occurred_at="2026-10-18T10:00:00Z",
        keyring=keyring,
        signer_seed=SEED,
        signer_id=U(1),
        signer_key_id="local-key-01",
        issued_at="2026-10-18T10:00:00Z",
        outer_nonce="OUTER2" * 4,
    )
    VALIDATOR.validate(sealed_ep2)
    assert (
        open_encrypted_envelope(
            sealed_ep2, keyring=keyring, lookup_public_key=lookup, now=NOW
        )
        == inner_signed
    )
    with pytest.raises(DecryptionError, match="ERR_DECRYPTION_FAILED"):
        open_encrypted_envelope(
            sealed_ep2,
            keyring=removed_member_keyring,
            lookup_public_key=lookup,
            now=NOW,
        )


def test_wtp_sync_causal_closure_and_compaction_fallback():
    space_id = U(300)
    object_id = U(301)
    session_id = U(302)
    peer_a = SyncReplica(
        principal_id=U(1),
        key_id="local-key-01",
        private_seed=SEED,
        space_id=space_id,
        object_id=object_id,
        supported_codecs=("automerge/1", "snapshot/1"),
    )
    peer_b = SyncReplica(
        principal_id=U(2),
        key_id="local-key-02",
        private_seed=SEED2,
        space_id=space_id,
        object_id=object_id,
        supported_codecs=("yrs/1", "automerge/1", "snapshot/1"),
        compacted_watermark_seq=10,
    )
    c1 = peer_a.put_local_chunk(b"rev-1-root")
    c2 = peer_a.put_local_chunk(b"rev-2-middle", parents=[c1])
    c3 = peer_a.put_local_chunk(b"rev-3-head", parents=[c2])
    d_b = peer_b.put_local_chunk(b"peer-B-branch")

    result = synchronize_replicas(
        peer_a,
        peer_b,
        session_id=session_id,
        lookup_public_key=lookup,
        peer_a_known_seq=2,
        now=NOW,
    )
    assert result["selected_codec"] == "snapshot/1"
    assert result["snapshot_fallback"] is True
    assert result["converged"] is True
    assert set(peer_b.chunks.keys()) == {c1, c2, c3, d_b}
    assert set(result["heads"]) == {c3, d_b}
    for frame in result["frames"]:
        VALIDATOR.validate(frame)
        assert validate_semantics(frame)

    with pytest.raises(WtpError, match="ERR_UNSUPPORTED"):
        negotiate_sync_codec(["automerge/1"], ["yrs/1"])


def test_federation_ssrf_pagination_rate_limit_and_http_digest(tmp_path):
    raw_body = b'{"protocol":"wutong/0.1"}'
    hdr = compute_http_content_digest(raw_body)
    assert verify_http_content_digest(raw_body, hdr)
    with pytest.raises(WtpError, match="Content-Digest"):
        verify_http_content_digest(raw_body + b"!", hdr)

    for bad_url, bad_ips in [
        ("http://federation.wutong.space", ()),
        ("https://user:pass@federation.wutong.space", ()),
        ("https://localhost/_wutong/v0.1/meta", ()),
        ("https://node.internal/_wutong/v0.1/meta", ()),
        ("https://127.0.0.1/_wutong/v0.1/meta", ()),
        ("https://169.254.169.254/latest/meta-data/", ()),
        ("https://federation.wutong.space", ("10.0.0.1",)),
        ("https://federation.wutong.space", ("100.64.0.1",)),
        ("https://federation.wutong.space", ("::1",)),
        ("https://federation.wutong.space", ("fe80::1",)),
    ]:
        with pytest.raises(WtpError, match="ERR_SSRF_BLOCKED"):
            validate_federation_endpoint(bad_url, resolved_ips=bad_ips)

    reg = KeyRegistry()
    reg.register_trust_root(U(1), "local-key-01", PUB_HEX, binding_id=U(6001))
    reg.register_trust_root(U(2), "local-key-02", PUB2_HEX, binding_id=U(6002))
    ledger = DurableReplayLedger(tmp_path / "fed.sqlite")

    node = FederationNode(
        node_id=U(500),
        operator_id=U(1),
        base_url="https://node-a.wutong.space",
        key_id="local-key-01",
        private_seed=SEED,
        registry=reg,
        replay_ledger=ledger,
        max_requests_per_principal=3,
    )
    meta = node.get_node_meta(envelope_id=U(501))
    VALIDATOR.validate(meta)
    assert validate_semantics(meta)

    sub_raw = json.loads((P / "examples/subscription.json").read_text())
    sub_raw["payload"]["subscriber_id"] = U(2)
    sub_env = sign(
        sub_raw,
        nonce="SUB2" * 6,
        seed=SEED2,
        signer_id=U(2),
        key_id="local-key-02",
    )
    node.register_subscription(sub_env, now=NOW)

    obj1 = sample()
    obj1["id"] = U(6101)
    obj1["payload"]["object_id"] = U(6201)
    node.ingest_public_envelope(sign(obj1, nonce="OBJ1" * 6), now=NOW)

    obj2 = sample()
    obj2["id"] = U(6102)
    obj2["payload"]["object_id"] = U(6202)
    node.ingest_public_envelope(sign(obj2, nonce="OBJ2" * 6), now=NOW)

    page1 = node.poll_subscription(
        sub_env["payload"]["subscription_id"], cursor="0", limit=1
    )
    assert len(page1["events"]) == 1 and page1["has_more"] is True
    page2 = node.poll_subscription(
        sub_env["payload"]["subscription_id"],
        cursor=page1["next_cursor"],
        limit=1,
    )
    assert len(page2["events"]) == 1 and page2["has_more"] is False

    obj3 = sample()
    obj3["id"] = U(6103)
    obj3["payload"]["object_id"] = U(6203)
    node.ingest_public_envelope(sign(obj3, nonce="OBJ3" * 6), now=NOW)

    obj4 = sample()
    obj4["id"] = U(6104)
    obj4["payload"]["object_id"] = U(6204)
    with pytest.raises(WtpError, match="ERR_RATE_LIMIT"):
        node.ingest_public_envelope(sign(obj4, nonce="OBJ4" * 6), now=NOW)
    ledger.close()


def test_revision_dag_annotation_reanchoring_and_interop_loop():
    dag = RevisionDAG()
    r1, r2, r3 = U(101), U(102), U(103)
    base_rev = json.loads((P / "examples/revision.json").read_text())

    def make_rev(rid, parents):
        m = copy.deepcopy(base_rev)
        m["payload"]["revision_id"] = rid
        m["payload"]["parents"] = list(parents)
        return m

    dag.add_revision(make_rev(r1, []))
    dag.add_revision(make_rev(r2, [r1]))
    dag.add_revision(make_rev(r3, [r1, r2]))
    assert dag.is_fully_resolved(r3)
    order = dag.topological_order()
    assert order.index(r1) < order.index(r2) < order.index(r3)

    r_orphan_parent = U(999)
    r4 = U(104)
    dag.add_revision(make_rev(r4, [r_orphan_parent]))
    assert not dag.is_fully_resolved(r4)
    assert dag.unresolved_parents(r4) == [r_orphan_parent]

    with pytest.raises(WtpError, match="ERR_CONFLICT"):
        dag.add_revision(make_rev(r1, [r3]))

    doc_v1 = "# 梧桐计划\n原生源文件永远是一等公民。\n"
    sel_quote = {
        "type": "TextQuote",
        "prefix": "# 梧桐计划\n",
        "exact": "原生源文件",
        "suffix": "永远是一等公民",
    }
    assert reanchor_annotation(sel_quote, doc_v1)["status"] == "resolved"

    doc_v2 = "# 梧桐计划 v1.3\n新增导言段落。\n原生源文件永远是一等公民。\n"
    assert reanchor_annotation(sel_quote, doc_v2)["status"] == "stale"

    doc_v3 = "# 完全重写后的文档\n不包含原句。\n"
    assert reanchor_annotation(sel_quote, doc_v3)["status"] == "orphan"
    assert (
        reanchor_annotation({"type": "BytePosition", "start": 2, "end": 4}, "梧桐")[
            "status"
        ]
        == "orphan"
    )

    tracker = InteropProjectionTracker()
    rep = tracker.record_export(
        object_id=U(4),
        adapter_id="org.wutong.wordpress",
        remote_ref="https://blog.example/posts/42",
        content_digest="sha256:" + "a" * 64,
        dropped_features=("typst-math-macro",),
    )
    assert rep["lossy"] is True
    with pytest.raises(WtpError, match="ERR_CONFLICT"):
        tracker.verify_inbound_not_loop(
            object_id=U(4),
            adapter_id="org.wutong.wordpress",
            remote_ref="https://blog.example/posts/42",
            inbound_digest="sha256:" + "a" * 64,
        )


def test_canonical_cross_runtime_and_rfc8785_utf16_order():
    tricky = [
        {"z": "中文", "a": ["\u2028", "\n", "𝌆", 1, True, None]},
        {"p": {"z": "e\u0301", "a": "é"}, "a": 0},
        {"p": "\t\b\u0000", "q": "hello/世界"},
    ]
    for o in tricky:
        js = subprocess.check_output(
            ["node", str(P / "tools/jcs_node.cjs")],
            input=json.dumps(o, ensure_ascii=False).encode(),
        )
        assert canonical_bytes(o) == js

    astral = {"\uE000": 1, "𐍈": 2}
    py_astral = canonical_bytes(astral, allow_unicode_keys=True)
    js_astral = subprocess.check_output(
        ["node", str(P / "tools/jcs_node.cjs"), "--unicode-keys"],
        input=json.dumps(astral, ensure_ascii=False).encode(),
    )
    assert py_astral == js_astral == '{"𐍈":2,"\ue000":1}'.encode("utf-8")


def test_ed25519_rfc8032_known_seed():
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4" + "4449c5697b326919703bac031cae7f60"
    )
    assert Ed25519PrivateKey.from_private_bytes(seed).sign(b"").hex() == (
        "e5564300c360ac729086e2cc806e828a"
        + "84877f1eb8e5d974d873e06522490155"
        + "5fb8821590a33bacc61e39701cf9b46b"
        + "d25bf5f0595bbe24655141438e7a100b"
    )


def test_sign_verify_and_tamper():
    m = sign(sample())
    VALIDATOR.validate(m)
    cache = ReplayCache()
    assert verify_envelope(m, lookup, now=NOW, replay=cache)
    with pytest.raises(ReplayError, match="replayed"):
        verify_envelope(m, lookup, now=NOW, replay=cache)
    for path, value in [
        ("kind", "wutong.relation"),
        ("occurred_at", "2026-10-18T10:00:01Z"),
    ]:
        bad = copy.deepcopy(m)
        bad[path] = value
        with pytest.raises(WtpError, match="signature mismatch"):
            verify_envelope(bad, lookup, now=NOW)
    bad = copy.deepcopy(m)
    bad["payload"]["title"] = "altered"
    with pytest.raises(WtpError, match="signature mismatch"):
        verify_envelope(bad, lookup, now=NOW)


def test_unknown_key_bad_nonce_and_clock_skew():
    signed = sign(sample())
    with pytest.raises(WtpError, match="unknown authenticated"):
        verify_envelope(signed, lambda a, b: None, now=NOW)
    with pytest.raises(WtpError, match="replay window"):
        verify_envelope(signed, lookup, now=NOW + dt.timedelta(hours=1), mode="live")
    assert verify_envelope(
        signed, lookup, now=NOW + dt.timedelta(days=90), mode="archive"
    )
    with pytest.raises(WtpError, match="bad nonce"):
        sign(sample(), nonce="short")


def test_sign_cross_language_node_verify():
    m = sign(sample())
    script = """const crypto=require('node:crypto');let fs=require('node:fs');let x=JSON.parse(fs.readFileSync(0,'utf8'));let sig=Buffer.from(x.proof.sig,'base64url');delete x.proof;function j(o){if(o===null||typeof o!=='object')return JSON.stringify(o);if(Array.isArray(o))return '['+o.map(j).join(',')+']';return '{'+Object.keys(o).sort().map(k=>JSON.stringify(k)+':'+j(o[k])).join(',')+'}'}let seed=Buffer.from([...Array(32).keys()]);let key=crypto.createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});let verified=crypto.verify(null,Buffer.concat([Buffer.from('WUTONG-SIG-V0.1\\0'),Buffer.from(j(x))]),crypto.createPublicKey(key),sig);process.stdout.write(verified?'OK':'FAIL');"""
    assert (
        subprocess.check_output(["node", "-e", script], input=json.dumps(m).encode())
        == b"OK"
    )


def test_durable_replay_and_equivocation_ledger(tmp_path):
    db_file = tmp_path / "replay.sqlite"
    m1 = sign(sample(), nonce="N" * 24)
    ledger = DurableReplayLedger(db_file)
    assert verify_envelope(m1, lookup, now=NOW, replay=ledger)
    ledger.close()

    ledger2 = DurableReplayLedger(db_file)
    with pytest.raises(ReplayError, match="replayed"):
        verify_envelope(m1, lookup, now=NOW, replay=ledger2)

    res = ledger2.consume(
        U(1),
        "N" * 24,
        m1["id"],
        canonical_digest=canonical_sha256(
            {k: v for k, v in m1.items() if k != "proof"}
        ),
        allow_idempotent_retry=True,
    )
    assert res["idempotent_replay"] is True

    fork_msg = sample()
    fork_msg["payload"]["title"] = "Forked content with identical message ID"
    m_fork = sign(fork_msg, nonce="M" * 24)
    with pytest.raises(EquivocationError, match="ERR_EQUIVOCATION"):
        verify_envelope(m_fork, lookup, now=NOW, replay=ledger2)
    assert ledger2.equivocation_count() == 1
    ledger2.close()


def test_key_registry_rotation_and_revocation():
    root = U(1)
    reg = KeyRegistry()
    reg.register_trust_root(
        root,
        "key-v1",
        PUB_HEX,
        binding_id=U(9001),
        valid_from="2026-10-01T00:00:00Z",
        valid_until="2026-11-01T00:00:00Z",
    )

    rot_env = {
        "protocol": "wutong/0.1",
        "kind": "wutong.key_binding",
        "id": U(9002),
        "occurred_at": "2026-10-15T00:00:00Z",
        "payload": {
            "binding_id": U(9003),
            "principal_id": root,
            "key_id": "key-v2",
            "alg": "Ed25519",
            "public_key": PUB2_HEX,
            "purposes": ["signing", "delegation"],
            "valid_from": "2026-10-15T00:00:00Z",
            "valid_until": "2026-12-01T00:00:00Z",
            "previous_key_id": "key-v1",
        },
    }
    signed_rot = sign(
        rot_env,
        seed=SEED,
        signer_id=root,
        key_id="key-v1",
        issued_at="2026-10-15T00:00:00Z",
        nonce="R" * 24,
    )
    VALIDATOR.validate(signed_rot)
    assert reg.register_signed_key_binding(signed_rot)

    msg_v2 = sign(
        sample(),
        seed=SEED2,
        signer_id=root,
        key_id="key-v2",
        issued_at="2026-10-18T10:00:00Z",
        nonce="V" * 24,
    )
    assert verify_envelope(msg_v2, reg.lookup_key, now=NOW)

    rev_env = {
        "protocol": "wutong/0.1",
        "kind": "wutong.revocation",
        "id": U(9004),
        "occurred_at": "2026-10-16T00:00:00Z",
        "payload": {
            "revocation_id": U(9005),
            "issuer_id": root,
            "target_kind": "key_binding",
            "target_id": U(9001),
            "revoked_at": "2026-10-16T00:00:00Z",
            "effective_from": "2026-10-16T00:00:00Z",
            "reason": "superseded",
        },
    }
    signed_rev = sign(
        rev_env,
        seed=SEED2,
        signer_id=root,
        key_id="key-v2",
        issued_at="2026-10-16T00:00:00Z",
        nonce="X" * 24,
    )
    VALIDATOR.validate(signed_rev)
    assert reg.register_signed_revocation(signed_rev)

    old_proof = sign(
        sample(),
        seed=SEED,
        signer_id=root,
        key_id="key-v1",
        issued_at="2026-10-10T00:00:00Z",
        nonce="O" * 24,
    )
    assert verify_envelope(old_proof, reg.lookup_key, mode="archive")

    revoked_attempt = sign(
        sample(),
        seed=SEED,
        signer_id=root,
        key_id="key-v1",
        issued_at="2026-10-18T10:00:00Z",
        nonce="Z" * 24,
    )
    with pytest.raises(WtpError, match="ERR_KEY_REVOKED"):
        verify_envelope(revoked_attempt, reg.lookup_key, now=NOW)


def test_cryptographic_signed_capability_chain():
    root = U(1)
    agent = U(2)
    sub = U(3)
    obj = U(4)
    reg = KeyRegistry()
    reg.register_trust_root(root, "root-k1", PUB_HEX, binding_id=U(8001))
    reg.register_trust_root(agent, "agent-k1", PUB2_HEX, binding_id=U(8002))
    reg.register_trust_root(sub, "sub-k1", PUB3_HEX, binding_id=U(8003))

    c1_id = U(7001)
    c2_id = U(7002)
    c1 = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.capability",
            "id": U(7101),
            "occurred_at": "2026-10-18T00:00:00Z",
            "payload": {
                "capability_id": c1_id,
                "issuer_id": root,
                "audience_id": agent,
                "resource_ref": obj,
                "actions": ["document.propose", "document.read"],
                "not_before": "2026-10-18T00:00:00Z",
                "expires_at": "2026-10-19T00:00:00Z",
                "delegable": True,
            },
        },
        seed=SEED,
        signer_id=root,
        key_id="root-k1",
        issued_at="2026-10-18T00:00:00Z",
        nonce="C1" * 12,
    )
    c2 = sign(
        {
            "protocol": "wutong/0.1",
            "kind": "wutong.capability",
            "id": U(7102),
            "occurred_at": "2026-10-18T01:00:00Z",
            "payload": {
                "capability_id": c2_id,
                "issuer_id": agent,
                "audience_id": sub,
                "resource_ref": obj,
                "actions": ["document.propose"],
                "not_before": "2026-10-18T01:00:00Z",
                "expires_at": "2026-10-18T20:00:00Z",
                "delegable": False,
                "parent_id": c1_id,
            },
        },
        seed=SEED2,
        signer_id=agent,
        key_id="agent-k1",
        issued_at="2026-10-18T01:00:00Z",
        nonce="C2" * 12,
    )

    assert authorize_signed_capability_chain(
        [c1, c2],
        registry=reg,
        root_owner=root,
        actor=sub,
        resource=obj,
        action="document.propose",
        at="2026-10-18T10:00:00Z",
        revocation_freshness_at="2026-10-18T09:50:00Z",
    )


def test_capability_chain():
    root = U(1)
    agent = U(2)
    sub = U(3)
    obj = U(4)
    g1 = {
        "id": "c1",
        "issuer": root,
        "audience": agent,
        "resource": obj,
        "actions": ["document.propose", "document.read"],
        "nbf": "2026-10-18T00:00:00Z",
        "exp": "2026-10-19T00:00:00Z",
        "delegable": True,
    }
    g2 = {
        "id": "c2",
        "issuer": agent,
        "audience": sub,
        "resource": obj,
        "actions": ["document.propose"],
        "nbf": "2026-10-18T01:00:00Z",
        "exp": "2026-10-18T20:00:00Z",
        "delegable": False,
        "parent": "c1",
    }
    test = lambda gs, rev=(): authorize_chain(
        gs,
        root_owner=root,
        actor=sub,
        resource=obj,
        action="document.propose",
        at="2026-10-18T10:00:00Z",
        revoked=rev,
    )
    assert test([g1, g2])
    assert not test([g1, g2], ["c1"])


def test_task_transitions_exhaustive():
    for current, allowed in TRANSITIONS.items():
        for other in TRANSITIONS:
            if other in allowed:
                assert check_transition(current, other)
            else:
                with pytest.raises(WtpError):
                    check_transition(current, other)


def test_filecoordinator_recovery_and_permissions(tmp_path):
    for stage in ("prepared", "replaced", "committed"):
        path = tmp_path / f"{stage}.md"
        path.write_bytes(b"A\r\n")
        os.chmod(path, 0o640)
        db = tmp_path / f"{stage}.sqlite"
        c = FileCoordinator(db, workspace_root=tmp_path)
        c.import_file("obj-" + stage, path)
        orphan = tmp_path / f".wutong-orphan-{stage}.pending"
        orphan.write_bytes(b"stale-orphan")
        with pytest.raises(SimulatedCrash):
            c.replace(
                "obj-" + stage,
                "intent-" + stage,
                sha(b"A\r\n"),
                b"B\r\n",
                crash_at=stage,
            )
        c.db.close()
        r = FileCoordinator(db, workspace_root=tmp_path)
        output = r.recover()
        if stage == "committed":
            assert output == []
        else:
            assert output[0][1] in ("rolled-forward", "finalized")
        assert path.read_bytes() == b"B\r\n"
        assert (path.stat().st_mode & 0o777) == 0o640
        assert not orphan.exists()
        r.db.close()


def test_filecoordinator_symlink_and_dir_escape_blocked(tmp_path):
    ws = tmp_path / "workspace"
    ws.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"secret")
    c = FileCoordinator(tmp_path / "db.sqlite", workspace_root=ws)

    with pytest.raises(FileConflict, match="ERR_SYMLINK_OR_TRAVERSAL"):
        c.import_file("o1", outside)

    leaf_link = ws / "link.md"
    leaf_link.symlink_to(outside)
    with pytest.raises(FileConflict, match="ERR_SYMLINK_OR_TRAVERSAL"):
        c.import_file("o2", leaf_link)

    sub_real = tmp_path / "real_dir"
    sub_real.mkdir()
    real_doc = sub_real / "doc.md"
    real_doc.write_bytes(b"data")
    dir_link = ws / "subdir"
    dir_link.symlink_to(sub_real)
    with pytest.raises(FileConflict, match="ERR_SYMLINK_OR_TRAVERSAL"):
        c.import_file("o3", dir_link / "doc.md")


@pytest.mark.parametrize("path", FILES, ids=lambda x: x.stem)
def test_semantics_valid_examples(path):
    msg = json.loads(path.read_text())
    body = None
    if path.stem in ("object", "artifact"):
        body = f"wutong {path.stem}".encode("utf-8")
    if path.stem == "sync_frame":
        msg["payload"]["supported_codecs"] = ["automerge/1"]
    assert validate_semantics(msg, body=body)


@pytest.mark.parametrize(
    "path",
    [
        "../escape.md",
        "a/../../secret",
        "/etc/passwd",
        "C:/Windows/system.ini",
        "dir\\file.md",
        "./notes.md",
        "a//b.md",
        "a/CON",
        "file.",
        "a/trailing ",
    ],
)
def test_relative_path_attacks_rejected(path):
    with pytest.raises(WtpError):
        validate_relative_path(path)


if __name__ == "__main__":
    from wtp import testshim

    sys.exit(testshim.run_module(sys.modules[__name__]))
