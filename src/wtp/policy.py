# SPDX-License-Identifier: AGPL-3.0-only
"""Cryptographic KeyBinding Registry (Ed25519 + X25519), Key Compromise vs Supersession Revocation, and Temporal Capability Verification (v0.1.2).

Refinements in v0.1.2:
1. Distinguishes `reason == "compromised"` from `reason == "superseded"` / `"affiliation_change"`:
   - When a key is revoked with `reason == "compromised"`, unnotarized historical signatures
     are rejected across ALL timestamps (preventing an attacker holding a stolen key from
     forging backdated `auth.issued_at` timestamps prior to `effective_from`!).
   - If the historical signature is accompanied by an independent verified `notarized_before_revocation=True`
     receipt/checkpoint created prior to `effective_from`, historical archive verification succeeds.
2. Enforces temporal delegation monotonicity in `authorize_signed_capability_chain`:
   - Every child capability `c_child` delegated from `c_parent` MUST satisfy
     `c_parent.auth.issued_at <= c_child.auth.issued_at` and
     `c_parent.not_before <= c_child.auth.issued_at < c_parent.expires_at`.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from .wire import WtpError, parse_time, validate_public_key_hex, verify_envelope

TRANSITIONS = {
    "created": {"assigned", "cancelled"},
    "assigned": {"accepted", "cancelled"},
    "accepted": {"running", "cancelled"},
    "running": {"awaiting_approval", "completed", "failed", "cancelled"},
    "awaiting_approval": {"running", "completed", "failed", "cancelled"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
}


def check_transition(old, new):
    if old not in TRANSITIONS or new not in TRANSITIONS[old]:
        raise WtpError("ERR_PERMISSION: illegal task transition")
    return True


class KeyRegistry:
    """Manages Principal-to-Key bindings (Ed25519 and X25519), key rotation chains, and signed revocations."""

    def __init__(self):
        self.bindings = {}
        self.binding_by_id = {}
        self.revocations = {}

    def register_trust_root(
        self,
        principal_id: str,
        key_id: str,
        public_key_hex: str,
        *,
        alg: str = "Ed25519",
        binding_id: str = "urn:uuid:019a1111-1111-7111-8111-000000000000",
        purposes=("signing", "delegation", "authentication", "assertion"),
        valid_from="2020-01-01T00:00:00Z",
        valid_until="2035-01-01T00:00:00Z",
    ):
        pub_bytes = validate_public_key_hex(public_key_hex)
        if alg == "Ed25519":
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        elif alg == "X25519":
            pub = X25519PublicKey.from_public_bytes(pub_bytes)
        else:
            raise WtpError(f"ERR_SCHEMA: unsupported key_binding alg {alg!r}")
        rec = {
            "binding_id": binding_id,
            "principal_id": principal_id,
            "key_id": key_id,
            "alg": alg,
            "pub": pub,
            "public_key_hex": public_key_hex,
            "purposes": set(purposes),
            "valid_from": parse_time(valid_from),
            "valid_until": parse_time(valid_until),
        }
        self.bindings[(principal_id, key_id)] = rec
        self.binding_by_id[binding_id] = (principal_id, key_id)

    def register_signed_key_binding(self, envelope: dict):
        if envelope.get("kind") != "wutong.key_binding":
            raise WtpError("ERR_SCHEMA: expected wutong.key_binding")
        p = envelope["payload"]
        auth = envelope.get("auth", {})
        vf = parse_time(p["valid_from"])
        vu = parse_time(p["valid_until"])
        if not (vf < vu):
            raise WtpError("ERR_SCHEMA: invalid key_binding validity window")
        pub_bytes = validate_public_key_hex(p["public_key"])
        alg = p["alg"]
        if alg == "Ed25519":
            if "encryption" in p["purposes"]:
                raise WtpError("ERR_SCHEMA: Ed25519 key cannot have encryption purpose")
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
        elif alg == "X25519":
            if set(p["purposes"]) != {"encryption"}:
                raise WtpError("ERR_SCHEMA: X25519 key_binding must have purposes=['encryption']")
            pub = X25519PublicKey.from_public_bytes(pub_bytes)
        else:
            raise WtpError(f"ERR_SCHEMA: unsupported alg {alg!r}")

        signer_id = auth.get("signer_id")
        signer_key_id = auth.get("key_id")

        if "previous_key_id" in p:
            if signer_id != p["principal_id"] or signer_key_id != p["previous_key_id"]:
                raise WtpError(
                    "ERR_SIGNATURE: key rotation must be signed by previous_key_id of same principal"
                )
            verify_envelope(envelope, self.lookup_key, mode="archive", purpose="signing")
        elif "authority_id" in p:
            if signer_id != p["authority_id"]:
                raise WtpError(
                    "ERR_SIGNATURE: authority-bound key must be signed by authority_id"
                )
            verify_envelope(envelope, self.lookup_key, mode="archive", purpose="signing")
        else:
            if signer_id != p["principal_id"]:
                raise WtpError("ERR_SIGNATURE: key_binding signer mismatch")
            if (signer_id, signer_key_id) in self.bindings:
                verify_envelope(
                    envelope, self.lookup_key, mode="archive", purpose="signing"
                )
            elif alg == "Ed25519" and signer_key_id == p["key_id"]:
                verify_envelope(
                    envelope,
                    lambda s, k: pub if (s == p["principal_id"] and k == p["key_id"]) else None,
                    mode="archive",
                )
            else:
                raise WtpError("ERR_KEY_UNBOUND: untrusted signer for key_binding")

        rec = {
            "binding_id": p["binding_id"],
            "principal_id": p["principal_id"],
            "key_id": p["key_id"],
            "alg": alg,
            "pub": pub,
            "public_key_hex": p["public_key"],
            "purposes": set(p["purposes"]),
            "valid_from": vf,
            "valid_until": vu,
        }
        self.bindings[(p["principal_id"], p["key_id"])] = rec
        self.binding_by_id[p["binding_id"]] = (p["principal_id"], p["key_id"])
        return True

    def register_signed_revocation(self, envelope: dict):
        if envelope.get("kind") != "wutong.revocation":
            raise WtpError("ERR_SCHEMA: expected wutong.revocation")
        p = envelope["payload"]
        auth = envelope.get("auth", {})
        if auth.get("signer_id") != p["issuer_id"]:
            raise WtpError("ERR_SIGNATURE: revocation signer must match issuer_id")
        verify_envelope(envelope, self.lookup_key, mode="archive", purpose="signing")
        eff = parse_time(p["effective_from"])
        self.revocations.setdefault(p["target_id"], []).append(
            {
                "issuer_id": p["issuer_id"],
                "effective_from": eff,
                "target_kind": p["target_kind"],
                "reason": p["reason"],
            }
        )
        return True

    def is_revoked(
        self,
        target_id: str,
        *,
        at_time: str,
        expected_issuer: str = None,
        notarized_before_revocation: bool = False,
    ) -> bool:
        at_dt = parse_time(at_time) if isinstance(at_time, str) else at_time
        for rev in self.revocations.get(target_id, ()):
            if expected_issuer is not None and rev["issuer_id"] != expected_issuer:
                continue
            # If the key/capability was compromised, self-asserted timestamps prior to
            # effective_from cannot be trusted without an independent notarization receipt!
            if rev["reason"] == "compromised" and not notarized_before_revocation:
                return True
            if rev["effective_from"] <= at_dt:
                return True
        return False

    def lookup_key(
        self,
        principal_id: str,
        key_id: str,
        *,
        at_time: str = None,
        purpose: str = "signing",
        notarized_before_revocation: bool = False,
    ):
        rec = self.bindings.get((principal_id, key_id))
        if rec is None:
            return None
        if purpose and purpose not in rec["purposes"]:
            return None
        if at_time is not None:
            at_dt = parse_time(at_time) if isinstance(at_time, str) else at_time
            if not (rec["valid_from"] <= at_dt < rec["valid_until"]):
                return None
            if self.is_revoked(
                rec["binding_id"],
                at_time=at_dt,
                expected_issuer=principal_id,
                notarized_before_revocation=notarized_before_revocation,
            ):
                raise WtpError("ERR_KEY_REVOKED: signer key binding was revoked or compromised")
        return rec["pub"]


def authorize_signed_capability_chain(
    signed_envelopes,
    *,
    registry: KeyRegistry,
    root_owner: str,
    actor: str,
    resource: str,
    action: str,
    at: str,
    revocation_freshness_at: str = None,
    max_revocation_staleness_seconds: int = 3600,
    depth_limit: int = 8,
) -> bool:
    at_dt = parse_time(at)
    if revocation_freshness_at is None:
        raise WtpError("ERR_REVOCATION_STALE: fail-closed when revocation state is unknown")
    fresh_dt = parse_time(revocation_freshness_at)
    if abs((at_dt - fresh_dt).total_seconds()) > max_revocation_staleness_seconds:
        raise WtpError("ERR_REVOCATION_STALE: revocation snapshot exceeds freshness budget")

    verified_grants = {}
    for env in signed_envelopes:
        if env.get("kind") != "wutong.capability":
            continue
        p = env["payload"]
        auth = env.get("auth", {})
        if auth.get("signer_id") != p["issuer_id"]:
            continue
        try:
            verify_envelope(
                env, registry.lookup_key, mode="archive", purpose="delegation"
            )
            registry.lookup_key(
                auth["signer_id"], auth["key_id"], at_time=at, purpose="delegation"
            )
        except WtpError:
            continue
        if registry.is_revoked(
            p["capability_id"], at_time=at_dt, expected_issuer=p["issuer_id"]
        ):
            continue
        verified_grants[p["capability_id"]] = {
            "id": p["capability_id"],
            "issuer": p["issuer_id"],
            "audience": p["audience_id"],
            "resource": p["resource_ref"],
            "actions": p["actions"],
            "nbf": p["not_before"],
            "exp": p["expires_at"],
            "issued_at": auth["issued_at"],
            "delegable": p["delegable"],
            "parent": p.get("parent_id"),
        }

    return authorize_chain(
        verified_grants.values(),
        root_owner=root_owner,
        actor=actor,
        resource=resource,
        action=action,
        at=at,
        revoked=(),
        depth_limit=depth_limit,
    )


def authorize_chain(
    grants,
    *,
    root_owner,
    actor,
    resource,
    action,
    at,
    revoked=(),
    depth_limit=8,
):
    grants = {g["id"]: g for g in grants}
    revoked = set(revoked)
    at = parse_time(at)
    for leaf in grants.values():
        if (
            leaf["audience"] != actor
            or leaf["resource"] != resource
            or action not in leaf["actions"]
        ):
            continue
        current = leaf
        seen = set()
        steps = 0
        while True:
            steps += 1
            if (
                steps > depth_limit
                or current["id"] in seen
                or current["id"] in revoked
            ):
                break
            seen.add(current["id"])
            if current["resource"] != resource or action not in current["actions"]:
                break
            if not (parse_time(current["nbf"]) <= at < parse_time(current["exp"])):
                break
            parent_id = current.get("parent")
            if parent_id is None:
                if current["issuer"] == root_owner:
                    return True
                break
            if parent_id not in grants:
                break
            parent = grants[parent_id]
            if parent["audience"] != current["issuer"] or not parent["delegable"]:
                break
            if not set(current["actions"]).issubset(set(parent["actions"])):
                break
            if parse_time(current["nbf"]) < parse_time(parent["nbf"]) or parse_time(
                current["exp"]
            ) > parse_time(parent["exp"]):
                break
            # Temporal issuance monotonicity check when `issued_at` is present
            if "issued_at" in current and "issued_at" in parent:
                c_iat = parse_time(current["issued_at"])
                p_iat = parse_time(parent["issued_at"])
                if c_iat < p_iat or not (
                    parse_time(parent["nbf"]) <= c_iat < parse_time(parent["exp"])
                ):
                    break
            current = parent
    return False
