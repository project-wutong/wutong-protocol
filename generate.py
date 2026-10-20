# SPDX-License-Identifier: AGPL-3.0-only
"""Normative Schema, Registry, OpenAPI 3.1.0, and Canonical Fixture Generator for Wutong Protocol v0.1.2 (Formal Release).

Refinements over v0.1.1:
1. Extends canonical message registry from 22 to **24 normative message kinds** by adding:
   - `wutong.service_invocation` (WTP-Service / WTP-Federation signed action & RPC invocation envelope)
   - `wutong.receipt` (Cryptographically signed execution receipt, notarization checkpoint, or structured error envelope)
2. Upgrades `wutong.sync_frame` with optional `presence_state` (`online`, `typing`, `viewing`, `idle`)
   and `ttl_seconds` (`1..60`) for ephemeral `PRESENCE` frames.
3. Updates Schema `$id` to `urn:wutong:schema:core:0.1.2` and synchronizes OpenAPI 3.1.0 components.
"""
import hashlib
import json
import pathlib

P = pathlib.Path(__file__).resolve().parent
U = lambda n: f"urn:uuid:019a1111-1111-7111-8111-{n:012x}"
D = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()

uid = {
    "type": "string",
    "pattern": r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
}
digest = {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"}
pubkey_hex = {"type": "string", "pattern": r"^[0-9a-f]{64}$"}
b64u_str = {
    "type": "string",
    "pattern": r"^[A-Za-z0-9_-]+$",
    "minLength": 1,
    "maxLength": 1048576,
}
nonce12_b64u = {"type": "string", "pattern": r"^[A-Za-z0-9_-]{16}$"}
ext_ns = {
    "type": "string",
    "pattern": r"^[a-z0-9]+(\.[a-z0-9_-]+)+$",
    "minLength": 3,
    "maxLength": 128,
}
ref = {"type": "string", "minLength": 1, "maxLength": 4096}
stamp = {"type": "string", "pattern": r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"}
small = {"type": "string", "minLength": 1, "maxLength": 256}
strlist = lambda item: {
    "type": "array",
    "items": item,
    "uniqueItems": True,
    "maxItems": 256,
}
extra = {
    "type": "object",
    "propertyNames": {"pattern": r"^[a-z0-9]+(\.[a-z0-9_-]+)+$"},
    "additionalProperties": True,
}

error_codes = [
    "ERR_SCHEMA",
    "ERR_VERSION",
    "ERR_SIGNATURE",
    "ERR_KEY_UNBOUND",
    "ERR_KEY_REVOKED",
    "ERR_REVOCATION_STALE",
    "ERR_PERMISSION",
    "ERR_REPLAY",
    "ERR_EQUIVOCATION",
    "ERR_DECRYPTION_FAILED",
    "ERR_CONFLICT",
    "ERR_SYMLINK_OR_TRAVERSAL",
    "ERR_SSRF_BLOCKED",
    "ERR_UNRESOLVED",
    "ERR_RATE_LIMIT",
    "ERR_UNSUPPORTED",
]

prov_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "was_generated_by": small,
        "was_associated_with": uid,
        "was_derived_from": strlist(ref),
        "used": strlist(ref),
        "tool_id": small,
        "reviewer_id": uid,
    },
    "required": ["was_generated_by", "was_associated_with"],
}

patch_item_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "start_byte": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
        "end_byte": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
        "expected_slice_digest": digest,
        "replacement": {"type": "string"},
    },
    "required": ["start_byte", "end_byte", "expected_slice_digest", "replacement"],
}

member_wrap_schema = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "member_id": uid,
        "member_key_id": small,
        "nonce_b64u": nonce12_b64u,
        "wrapped_key_b64u": b64u_str,
    },
    "required": ["member_id", "member_key_id", "nonce_b64u", "wrapped_key_b64u"],
}

codec_enum = {"enum": ["automerge/1", "yrs/1", "snapshot/1"]}
profile_enum = {
    "enum": [
        "core",
        "document",
        "agent",
        "security",
        "sync",
        "federation",
        "service",
        "interop",
    ]
}

kinds = {
    "principal": (
        {
            "principal_id": uid,
            "principal_type": {
                "enum": ["human", "organization", "agent", "service", "device"]
            },
            "display_name": small,
        },
        ["principal_id", "principal_type"],
    ),
    "key_binding": (
        {
            "binding_id": uid,
            "principal_id": uid,
            "key_id": small,
            "alg": {"enum": ["Ed25519", "X25519"]},
            "public_key": pubkey_hex,
            "purposes": {
                "type": "array",
                "items": {
                    "enum": [
                        "signing",
                        "delegation",
                        "authentication",
                        "assertion",
                        "encryption",
                    ]
                },
                "uniqueItems": True,
                "minItems": 1,
                "maxItems": 4,
            },
            "valid_from": stamp,
            "valid_until": stamp,
            "previous_key_id": small,
            "authority_id": uid,
        },
        [
            "binding_id",
            "principal_id",
            "key_id",
            "alg",
            "public_key",
            "purposes",
            "valid_from",
            "valid_until",
        ],
    ),
    "revocation": (
        {
            "revocation_id": uid,
            "issuer_id": uid,
            "target_kind": {
                "enum": ["key_binding", "capability", "publication", "artifact"]
            },
            "target_id": uid,
            "revoked_at": stamp,
            "effective_from": stamp,
            "reason": {
                "enum": [
                    "compromised",
                    "superseded",
                    "affiliation_change",
                    "policy_violation",
                    "withdrawn",
                ]
            },
        },
        [
            "revocation_id",
            "issuer_id",
            "target_kind",
            "target_id",
            "revoked_at",
            "effective_from",
            "reason",
        ],
    ),
    "space": (
        {
            "space_id": uid,
            "owner_id": uid,
            "name": small,
            "visibility": {"enum": ["local", "private", "shared", "public"]},
        },
        ["space_id", "owner_id", "name", "visibility"],
    ),
    "space_epoch": (
        {
            "epoch_id": uid,
            "space_id": uid,
            "epoch": {"type": "integer", "minimum": 1, "maximum": 9007199254740991},
            "key_id": small,
            "issuer_id": uid,
            "sender_ephemeral_pub": pubkey_hex,
            "space_x25519_pub": pubkey_hex,
            "previous_epoch_digest": digest,
            "member_wraps": {
                "type": "array",
                "items": member_wrap_schema,
                "minItems": 1,
                "maxItems": 1024,
            },
        },
        [
            "epoch_id",
            "space_id",
            "epoch",
            "key_id",
            "issuer_id",
            "sender_ephemeral_pub",
            "space_x25519_pub",
            "member_wraps",
        ],
    ),
    "object": (
        {
            "object_id": uid,
            "space_id": uid,
            "owner_id": uid,
            "object_type": small,
            "media_type": small,
            "byte_length": {
                "type": "integer",
                "minimum": 0,
                "maximum": 9007199254740991,
            },
            "content_digest": digest,
            "title": small,
            "binding": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "kind": {"enum": ["file", "blob", "external"]},
                    "relative_path": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 2048,
                    },
                    "external_uri": ref,
                },
                "required": ["kind"],
                "allOf": [
                    {
                        "if": {"properties": {"kind": {"const": "file"}}},
                        "then": {"required": ["relative_path"]},
                    },
                    {
                        "if": {"properties": {"kind": {"const": "external"}}},
                        "then": {"required": ["external_uri"]},
                    },
                ],
            },
        },
        [
            "object_id",
            "space_id",
            "owner_id",
            "object_type",
            "content_digest",
            "media_type",
            "byte_length",
        ],
    ),
    "revision": (
        {
            "revision_id": uid,
            "object_id": uid,
            "content_digest": digest,
            "parents": strlist(uid),
            "author_id": uid,
            "change_id": uid,
            "provenance": prov_schema,
        },
        ["revision_id", "object_id", "content_digest", "parents", "author_id"],
    ),
    "relation": (
        {
            "relation_id": uid,
            "source_id": uid,
            "target_ref": ref,
            "predicate": small,
            "author_id": uid,
            "visibility": {"enum": ["private", "shared", "public"]},
        },
        ["relation_id", "source_id", "target_ref", "predicate", "author_id"],
    ),
    "annotation": (
        {
            "annotation_id": uid,
            "target_ref": ref,
            "target_revision": digest,
            "author_id": uid,
            "body_ref": ref,
            "selector": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "type": {
                        "enum": [
                            "TextQuote",
                            "TextPosition",
                            "BytePosition",
                            "Node",
                        ]
                    },
                    "exact": {"type": "string"},
                    "prefix": {"type": "string"},
                    "suffix": {"type": "string"},
                    "start": {"type": "integer", "minimum": 0},
                    "end": {"type": "integer", "minimum": 0},
                    "node_id": small,
                },
                "required": ["type"],
            },
            "visibility": {"enum": ["private", "shared", "public"]},
        },
        ["annotation_id", "target_ref", "author_id", "selector"],
    ),
    "proposal": (
        {
            "proposal_id": uid,
            "object_id": uid,
            "proposer_id": uid,
            "base_digest": digest,
            "proposed_digest": digest,
            "intent": {"enum": ["replace", "patch", "metadata", "relation"]},
            "status": {
                "enum": ["pending", "accepted", "rejected", "applied", "stale"]
            },
            "task_id": uid,
            "patches": {
                "type": "array",
                "items": patch_item_schema,
                "minItems": 1,
                "maxItems": 256,
            },
            "provenance": prov_schema,
        },
        [
            "proposal_id",
            "object_id",
            "proposer_id",
            "base_digest",
            "proposed_digest",
            "intent",
            "status",
        ],
    ),
    "task": (
        {
            "task_id": uid,
            "requester_id": uid,
            "assignee_id": uid,
            "target_ref": ref,
            "state": {
                "enum": [
                    "created",
                    "assigned",
                    "accepted",
                    "running",
                    "awaiting_approval",
                    "completed",
                    "failed",
                    "cancelled",
                ]
            },
            "artifacts": strlist(ref),
            "idempotency_key": small,
        },
        ["task_id", "requester_id", "state"],
    ),
    "capability": (
        {
            "capability_id": uid,
            "issuer_id": uid,
            "audience_id": uid,
            "resource_ref": ref,
            "actions": {
                "type": "array",
                "items": small,
                "uniqueItems": True,
                "minItems": 1,
                "maxItems": 64,
            },
            "not_before": stamp,
            "expires_at": stamp,
            "delegable": {"type": "boolean"},
            "parent_id": uid,
            "revocation_ref": ref,
        },
        [
            "capability_id",
            "issuer_id",
            "audience_id",
            "resource_ref",
            "actions",
            "not_before",
            "expires_at",
            "delegable",
        ],
    ),
    "event": (
        {
            "event_id": uid,
            "actor_id": uid,
            "action": small,
            "subject_ref": ref,
            "result": {
                "enum": ["accepted", "rejected", "pending", "completed", "failed"]
            },
            "causes": strlist(uid),
            "idempotency_key": small,
        },
        ["event_id", "actor_id", "action", "subject_ref", "result"],
    ),
    "service": (
        {
            "service_id": uid,
            "space_id": uid,
            "owner_id": uid,
            "service_type": {
                "enum": [
                    "blog",
                    "wiki",
                    "forum",
                    "qa",
                    "media",
                    "im",
                    "agent",
                    "api",
                    "custom",
                ]
            },
            "source_refs": strlist(ref),
            "spec_digest": digest,
            "visibility": {"enum": ["local", "private", "shared", "public"]},
        },
        [
            "service_id",
            "space_id",
            "owner_id",
            "service_type",
            "source_refs",
            "spec_digest",
            "visibility",
        ],
    ),
    "service_invocation": (
        {
            "invocation_id": uid,
            "service_id": uid,
            "caller_id": uid,
            "action": small,
            "target_ref": ref,
            "capability_ids": strlist(uid),
            "idempotency_key": small,
            "arguments": {
                "type": "object",
                "propertyNames": {"pattern": r"^[\x21-\x7e]+$"},
                "additionalProperties": True,
            },
        },
        [
            "invocation_id",
            "service_id",
            "caller_id",
            "action",
            "target_ref",
            "idempotency_key",
        ],
    ),
    "receipt": (
        {
            "receipt_id": uid,
            "request_id": uid,
            "request_digest": digest,
            "responder_id": uid,
            "status": {"enum": ["accepted", "completed", "rejected", "notarized"]},
            "error_code": {"enum": error_codes},
            "result_digest": digest,
            "applied_revision_id": uid,
            "retry_after_seconds": {"type": "integer", "minimum": 0, "maximum": 86400},
        },
        [
            "receipt_id",
            "request_id",
            "request_digest",
            "responder_id",
            "status",
        ],
    ),
    "publication": (
        {
            "publication_id": uid,
            "object_id": uid,
            "revision_id": uid,
            "publisher_id": uid,
            "visibility": {"enum": ["unlisted", "public"]},
            "representation_digest": digest,
            "published_at": stamp,
        },
        [
            "publication_id",
            "object_id",
            "revision_id",
            "publisher_id",
            "visibility",
            "representation_digest",
            "published_at",
        ],
    ),
    "external_binding": (
        {
            "binding_id": uid,
            "object_id": uid,
            "adapter_id": small,
            "account_ref": ref,
            "remote_ref": ref,
            "direction": {
                "enum": ["export", "import", "bidirectional", "interaction-only"]
            },
            "last_source_revision": uid,
            "origin_digest": digest,
        },
        [
            "binding_id",
            "object_id",
            "adapter_id",
            "account_ref",
            "remote_ref",
            "direction",
        ],
    ),
    "agent_manifest": (
        {
            "agent_id": uid,
            "display_name": small,
            "skills": strlist(small),
            "input_types": strlist(small),
            "output_types": strlist(small),
            "execution": {"enum": ["local", "remote", "hybrid"]},
            "endpoint": ref,
        },
        [
            "agent_id",
            "display_name",
            "skills",
            "input_types",
            "output_types",
            "execution",
        ],
    ),
    "artifact": (
        {
            "artifact_id": uid,
            "task_id": uid,
            "creator_id": uid,
            "content_digest": digest,
            "media_type": small,
            "byte_length": {"type": "integer", "minimum": 0},
            "provenance": prov_schema,
        },
        [
            "artifact_id",
            "task_id",
            "creator_id",
            "content_digest",
            "media_type",
            "byte_length",
        ],
    ),
    "sync_frame": (
        {
            "session_id": uid,
            "space_id": uid,
            "object_id": uid,
            "step": {
                "enum": [
                    "HELLO",
                    "AUTH",
                    "SYNC_OFFER",
                    "SYNC_REQUEST",
                    "SYNC_CHUNK",
                    "SYNC_ACK",
                    "PRESENCE",
                ]
            },
            "seq": {"type": "integer", "minimum": 0, "maximum": 9007199254740991},
            "supported_codecs": {
                "type": "array",
                "items": codec_enum,
                "uniqueItems": True,
                "minItems": 1,
                "maxItems": 8,
            },
            "selected_codec": codec_enum,
            "heads": strlist(digest),
            "want": strlist(digest),
            "compacted_WaterMark_seq": {"type": "integer", "minimum": 0},
            "chunk_digest": digest,
            "chunk_b64u": b64u_str,
            "chunk_parents": strlist(digest),
            "presence_state": {"enum": ["online", "typing", "viewing", "idle"]},
            "ttl_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
        },
        ["session_id", "space_id", "step", "seq"],
    ),
    "encrypted_envelope": (
        {
            "space_id": uid,
            "epoch": {"type": "integer", "minimum": 1, "maximum": 9007199254740991},
            "key_id": small,
            "sender_ephemeral_pub": pubkey_hex,
            "aead_alg": {"const": "ChaCha20-Poly1305"},
            "kdf_alg": {"const": "HKDF-SHA256"},
            "nonce_b64u": nonce12_b64u,
            "inner_kind": small,
            "aad_digest": digest,
            "ciphertext_b64u": b64u_str,
        },
        [
            "space_id",
            "epoch",
            "key_id",
            "sender_ephemeral_pub",
            "aead_alg",
            "kdf_alg",
            "nonce_b64u",
            "inner_kind",
            "aad_digest",
            "ciphertext_b64u",
        ],
    ),
    "node_meta": (
        {
            "node_id": uid,
            "operator_id": uid,
            "implementation": small,
            "supported_profiles": {
                "type": "array",
                "items": profile_enum,
                "uniqueItems": True,
                "minItems": 1,
                "maxItems": 16,
            },
            "supported_encodings": {
                "type": "array",
                "items": {"enum": ["application/wtp+json", "application/wtp+cbor"]},
                "uniqueItems": True,
                "minItems": 1,
                "maxItems": 4,
            },
            "max_envelope_bytes": {
                "type": "integer",
                "minimum": 4096,
                "maximum": 67108864,
            },
            "endpoints": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "base_url": ref,
                    "meta_path": small,
                    "objects_path": small,
                    "revisions_path": small,
                    "resolve_path": small,
                    "subscriptions_path": small,
                    "invocations_path": small,
                    "sync_path": small,
                },
                "required": [
                    "base_url",
                    "meta_path",
                    "objects_path",
                    "revisions_path",
                    "resolve_path",
                    "subscriptions_path",
                    "invocations_path",
                ],
            },
        },
        [
            "node_id",
            "operator_id",
            "implementation",
            "supported_profiles",
            "supported_encodings",
            "max_envelope_bytes",
            "endpoints",
        ],
    ),
    "subscription": (
        {
            "subscription_id": uid,
            "subscriber_id": uid,
            "target_ref": ref,
            "filter_kinds": strlist(small),
            "cursor": small,
            "delivery_mode": {"enum": ["poll", "sse", "websocket", "webhook"]},
            "status": {"enum": ["active", "paused", "cancelled", "expired"]},
            "expires_at": stamp,
        },
        [
            "subscription_id",
            "subscriber_id",
            "target_ref",
            "filter_kinds",
            "delivery_mode",
            "status",
            "expires_at",
        ],
    ),
}

base_env = {
    "protocol": {"const": "wutong/0.1"},
    "kind": {"type": "string"},
    "id": uid,
    "occurred_at": stamp,
    "payload": {"type": "object"},
    "extensions": extra,
    "critical": {
        "type": "array",
        "items": ext_ns,
        "uniqueItems": True,
        "minItems": 1,
        "maxItems": 32,
    },
    "auth": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "signer_id": uid,
            "key_id": ref,
            "issued_at": stamp,
            "nonce": {"type": "string", "pattern": "^[A-Za-z0-9_-]{16,128}$"},
        },
        "required": ["signer_id", "key_id", "issued_at", "nonce"],
    },
    "proof": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "alg": {"const": "Ed25519"},
            "sig": {"type": "string", "pattern": "^[A-Za-z0-9_-]{86}$"},
            "encoding": {"enum": ["jcs", "dcbor"]},
        },
        "required": ["alg", "sig"],
    },
}

variants = []
for name, (properties, required) in kinds.items():
    props = dict(properties)
    props["x"] = extra
    payload_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": props,
        "required": required,
    }
    if name == "key_binding":
        payload_schema["allOf"] = [
            {
                "if": {"properties": {"alg": {"const": "X25519"}}},
                "then": {
                    "properties": {
                        "purposes": {
                            "type": "array",
                            "items": {"const": "encryption"},
                            "minItems": 1,
                            "maxItems": 1,
                        }
                    }
                },
            },
            {
                "if": {"properties": {"alg": {"const": "Ed25519"}}},
                "then": {
                    "properties": {
                        "purposes": {
                            "type": "array",
                            "items": {
                                "enum": [
                                    "signing",
                                    "delegation",
                                    "authentication",
                                    "assertion",
                                ]
                            },
                            "minItems": 1,
                        }
                    }
                },
            },
        ]
    if name == "receipt":
        payload_schema["allOf"] = [
            {
                "if": {"properties": {"status": {"const": "rejected"}}},
                "then": {"required": ["error_code"]},
            }
        ]
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            **base_env,
            "kind": {"const": f"wutong.{name}"},
            "payload": payload_schema,
        },
        "required": ["protocol", "kind", "id", "occurred_at", "payload"],
        "dependentRequired": {
            "auth": ["proof"],
            "proof": ["auth"],
            "critical": ["extensions"],
        },
    }
    variants.append(schema)

root = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:wutong:schema:core:0.1.2",
    "$comment": "Server-independent URN schema identifier for Wutong Protocol v0.1.2 Formal Release.",
    "title": "Wutong Protocol v0.1.2 Normative Wire Schema (24 Message Kinds)",
    "description": "Syntactic contract for all 24 Wutong Protocol v0.1.2 message kinds across Core, Document, Agent, Security, Sync, Federation, Service, and Interop profiles.",
    "oneOf": variants,
}

(P / "schemas" / "core.schema.json").write_text(
    json.dumps(root, ensure_ascii=False, indent=2) + "\n"
)

(P / "schemas" / "registry.json").write_text(
    json.dumps(
        {
            "protocol": "wutong/0.1",
            "version": "0.1.2",
            "schema_id": "urn:wutong:schema:core:0.1.2",
            "status": "formal-release",
            "kinds": list(kinds),
            "profiles": [
                "core",
                "document",
                "agent",
                "security",
                "sync",
                "federation",
                "service",
                "interop",
            ],
            "wire_encodings": [
                {
                    "media_type": "application/wtp+json",
                    "canonicalization": "RFC 8785 (JCS)",
                    "signature_prefix": "WUTONG-SIG-V0.1\\x00",
                    "proof_encoding": "jcs",
                },
                {
                    "media_type": "application/wtp+cbor",
                    "canonicalization": "RFC 8949 Section 4.2.1 (dCBOR)",
                    "signature_prefix": "WUTONG-CBOR-SIG-V0.1\\x00",
                    "proof_encoding": "dcbor",
                },
            ],
            "sync_codecs": ["automerge/1", "yrs/1", "snapshot/1"],
            "e2ee_suites": [
                {
                    "kem": "X25519 (RFC 7748)",
                    "kdf": "HKDF-SHA256 (RFC 5869)",
                    "aead": "ChaCha20-Poly1305 (RFC 8439)",
                    "epoch_distribution": "wutong.space_epoch",
                }
            ],
            "errors": error_codes,
        },
        indent=2,
    )
    + "\n"
)

openapi_path = P / "openapi" / "wutong-federation-v0.1.openapi.json"
if openapi_path.exists():
    oa = json.loads(openapi_path.read_text())
    oa["info"]["version"] = "0.1.2"
    oa["components"]["schemas"]["WutongEnvelope"]["$ref"] = "urn:wutong:schema:core:0.1.2"
    openapi_path.write_text(json.dumps(oa, ensure_ascii=False, indent=2) + "\n")

for i, (name, (props, req)) in enumerate(kinds.items(), 1):
    payload = {}
    sample_bytes = f"wutong {name}".encode("utf-8")
    for field in req:
        if field.endswith("_id") and field not in (
            "key_id",
            "adapter_id",
            "node_id",
            "session_id",
            "epoch_id",
            "invocation_id",
            "receipt_id",
            "request_id",
            "responder_id",
            "caller_id",
        ):
            payload[field] = U(i * 100 + len(payload) + 1)
        elif field in (
            "node_id",
            "session_id",
            "epoch_id",
            "invocation_id",
            "receipt_id",
            "request_id",
            "responder_id",
            "caller_id",
        ):
            payload[field] = U(i * 100 + len(payload) + 1)
        elif field in (
            "content_digest",
            "base_digest",
            "proposed_digest",
            "spec_digest",
            "representation_digest",
            "aad_digest",
            "request_digest",
        ):
            payload[field] = D(sample_bytes)
        elif field in (
            "parents",
            "source_refs",
            "artifacts",
            "skills",
            "input_types",
            "output_types",
        ):
            payload[field] = []
        elif field == "filter_kinds":
            payload[field] = ["wutong.object", "wutong.revision"]
        elif field == "actions":
            payload[field] = ["document.propose"]
        elif field == "purposes":
            payload[field] = ["signing", "delegation"]
        elif field == "alg":
            payload[field] = "Ed25519"
        elif field == "aead_alg":
            payload[field] = "ChaCha20-Poly1305"
        elif field == "kdf_alg":
            payload[field] = "HKDF-SHA256"
        elif field in ("public_key", "sender_ephemeral_pub", "space_x25519_pub"):
            payload[field] = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
        elif field == "key_id":
            payload[field] = "local-key-01"
        elif field == "idempotency_key":
            payload[field] = "idem-key-0001"
        elif field == "member_wraps":
            payload[field] = [
                {
                    "member_id": U(1),
                    "member_key_id": "x25519-key-01",
                    "nonce_b64u": "AAAAAAAAAAAAAAAA",
                    "wrapped_key_b64u": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo",
                }
            ]
        elif field in ("not_before", "valid_from", "revoked_at", "effective_from"):
            payload[field] = "2026-10-18T00:00:00Z"
        elif field in ("expires_at", "valid_until"):
            payload[field] = "2026-10-19T00:00:00Z"
        elif field == "published_at":
            payload[field] = "2026-10-18T10:00:00Z"
        elif field == "delegable":
            payload[field] = False
        elif field == "byte_length":
            payload[field] = len(sample_bytes)
        elif field == "seq":
            payload[field] = 0
        elif field == "epoch":
            payload[field] = 1
        elif field == "step":
            payload[field] = "HELLO"
        elif field == "nonce_b64u":
            payload[field] = "AAAAAAAAAAAAAAAA"
        elif field == "inner_kind":
            payload[field] = "wutong.object"
        elif field == "ciphertext_b64u":
            payload[field] = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"
        elif field == "implementation":
            payload[field] = "wutong-reference/0.1.2"
        elif field == "supported_profiles":
            payload[field] = [
                "core",
                "document",
                "agent",
                "security",
                "sync",
                "federation",
                "service",
                "interop",
            ]
        elif field == "supported_encodings":
            payload[field] = ["application/wtp+json", "application/wtp+cbor"]
        elif field == "max_envelope_bytes":
            payload[field] = 1048576
        elif field == "endpoints":
            payload[field] = {
                "base_url": "https://node.wutong.space",
                "meta_path": "/_wutong/v0.1/meta",
                "objects_path": "/_wutong/v0.1/objects",
                "revisions_path": "/_wutong/v0.1/revisions",
                "resolve_path": "/_wutong/v0.1/resolve",
                "subscriptions_path": "/_wutong/v0.1/subscriptions",
                "invocations_path": "/_wutong/v0.1/invocations",
                "sync_path": "/_wutong/v0.1/sync",
            }
        elif field == "delivery_mode":
            payload[field] = "poll"
        elif field == "selector":
            payload[field] = {"type": "TextQuote", "exact": "test"}
        elif field == "name":
            payload[field] = "Wutong Research"
        elif field == "display_name":
            payload[field] = "Example Agent"
        elif field == "principal_type":
            payload[field] = "agent"
        elif field == "target_kind":
            payload[field] = "capability"
        elif field == "reason":
            payload[field] = "superseded"
        elif field == "visibility":
            payload[field] = "local" if name in ("space", "service") else "public"
        elif field == "service_type":
            payload[field] = "blog"
        elif field == "execution":
            payload[field] = "local"
        elif field == "state":
            payload[field] = "created"
        elif field == "status":
            if name == "subscription":
                payload[field] = "active"
            elif name == "receipt":
                payload[field] = "accepted"
            else:
                payload[field] = "pending"
        elif field == "intent":
            payload[field] = "replace"
        elif field == "result":
            payload[field] = "pending"
        elif field == "direction":
            payload[field] = "export"
        elif field == "object_type":
            payload[field] = "document"
        elif field == "media_type":
            payload[field] = "text/markdown"
        elif field in ("target_ref", "resource_ref", "account_ref", "remote_ref"):
            payload[field] = "urn:uuid:019a1111-1111-7111-8111-000000009999"
        elif field == "adapter_id":
            payload[field] = "org.wutong.wordpress"
        elif field == "predicate":
            payload[field] = "references"
        elif field == "action":
            payload[field] = "document.propose"
        else:
            payload[field] = "Example"
    msg = {
        "protocol": "wutong/0.1",
        "kind": "wutong." + name,
        "id": U(10000 + i),
        "occurred_at": "2026-10-18T10:00:00Z",
        "payload": payload,
    }
    (P / "examples" / f"{name}.json").write_text(
        json.dumps(msg, ensure_ascii=False, indent=2) + "\n"
    )

print("Generated", len(kinds), "kinds, examples, and OpenAPI 3.1.0 spec")
