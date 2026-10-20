# SPDX-License-Identifier: AGPL-3.0-only
"""Wutong Protocol v0.1.1 Formal Release Reference Implementation Package."""
from .wire import (
    ED25519_L,
    EquivocationError,
    ReplayCache,
    ReplayError,
    WtpError,
    canonical_bytes,
    canonical_sha256,
    check_critical_extensions,
    check_ed25519_signature_canonical,
    sign_envelope,
    strict_loads,
    validate_public_key_hex,
    verify_envelope,
)
from .cbor_wire import (
    dcbor_dumps,
    dcbor_loads,
    sign_cbor_envelope,
    verify_cbor_envelope,
)
from .document_patch import apply_source_patches, validate_provenance
from .e2ee import (
    DecryptionError,
    SpaceEpochKeyring,
    create_space_epoch_envelope,
    open_encrypted_envelope,
    seal_encrypted_envelope,
    unwrap_space_epoch_for_member,
)
from .sync import (
    SYNC_STEP_ORDER,
    SyncReplica,
    negotiate_sync_codec,
    synchronize_replicas,
)
from .federation import (
    FederationNode,
    InteropProjectionTracker,
    RevisionDAG,
    compute_http_content_digest,
    reanchor_annotation,
    validate_federation_endpoint,
    verify_http_content_digest,
)
from .replay import DurableReplayLedger
from .policy import (
    KeyRegistry,
    authorize_chain,
    authorize_signed_capability_chain,
    check_transition,
)
from .filecoord import FileConflict, FileCoordinator, SimulatedCrash
from .semantic import validate_relative_path, validate_semantics

__all__ = [
    "DecryptionError",
    "DurableReplayLedger",
    "ED25519_L",
    "EquivocationError",
    "FederationNode",
    "FileConflict",
    "FileCoordinator",
    "InteropProjectionTracker",
    "KeyRegistry",
    "ReplayCache",
    "ReplayError",
    "RevisionDAG",
    "SYNC_STEP_ORDER",
    "SimulatedCrash",
    "SpaceEpochKeyring",
    "SyncReplica",
    "WtpError",
    "apply_source_patches",
    "authorize_chain",
    "authorize_signed_capability_chain",
    "canonical_bytes",
    "canonical_sha256",
    "check_critical_extensions",
    "check_ed25519_signature_canonical",
    "check_transition",
    "compute_http_content_digest",
    "create_space_epoch_envelope",
    "dcbor_dumps",
    "dcbor_loads",
    "negotiate_sync_codec",
    "open_encrypted_envelope",
    "reanchor_annotation",
    "seal_encrypted_envelope",
    "sign_cbor_envelope",
    "sign_envelope",
    "strict_loads",
    "synchronize_replicas",
    "unwrap_space_epoch_for_member",
    "validate_federation_endpoint",
    "validate_provenance",
    "validate_public_key_hex",
    "validate_relative_path",
    "validate_semantics",
    "verify_cbor_envelope",
    "verify_envelope",
    "verify_http_content_digest",
]
