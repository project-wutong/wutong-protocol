# SPDX-License-Identifier: AGPL-3.0-only
"""WTP-Federation Two-Node Exchange, Signed Receipt Generation, SSRF Defense, Rate Limiting, Bounded Pagination, RFC 9530 Content-Digest, Revision DAG, Annotation Re-anchoring, and Interop Loop Prevention (v0.1.2).

Refinements in v0.1.2:
- `FederationNode.invoke_protected_action` now accepts `wutong.service_invocation` envelopes
  (as well as general signed invocation envelopes) and returns a cryptographically signed
  `wutong.receipt` envelope (`status="accepted"` or `"completed"`, `request_id`, `request_digest`,
  `responder_id`), closing the request/response wire loop!
"""
import base64
import hashlib
import ipaddress
import urllib.parse
from .policy import KeyRegistry, authorize_signed_capability_chain
from .replay import DurableReplayLedger
from .wire import WtpError, canonical_sha256, sign_envelope, verify_envelope


def compute_http_content_digest(body: bytes) -> str:
    b64 = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
    return f"sha-256=:{b64}:"


def verify_http_content_digest(body: bytes, header_value: str) -> bool:
    if not isinstance(header_value, str) or header_value != compute_http_content_digest(body):
        raise WtpError("ERR_SIGNATURE: HTTP Content-Digest header mismatch")
    return True


def validate_federation_endpoint(url: str, *, resolved_ips=()) -> str:
    if not isinstance(url, str) or not url:
        raise WtpError("ERR_SSRF_BLOCKED: empty federation endpoint")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise WtpError("ERR_SSRF_BLOCKED: federation endpoints MUST use https")
    if parsed.username or parsed.password:
        raise WtpError("ERR_SSRF_BLOCKED: credentials forbidden in federation endpoint URL")
    host = parsed.hostname
    if (
        not host
        or host in ("localhost", "localhost.localdomain")
        or host.endswith(".local")
        or host.endswith(".internal")
    ):
        raise WtpError("ERR_SSRF_BLOCKED: local hostname forbidden")

    candidates = list(resolved_ips)
    try:
        candidates.append(str(ipaddress.ip_address(host)))
    except ValueError:
        pass

    cgnat_net = ipaddress.ip_network("100.64.0.0/10")
    for ip_str in candidates:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
            or (isinstance(ip, ipaddress.IPv4Address) and ip in cgnat_net)
        ):
            raise WtpError(f"ERR_SSRF_BLOCKED: disallowed IP address {ip_str}")
    return url


class FederationNode:
    """Normative WTP-Federation v0.1.2 reference node with signed `wutong.receipt` responses."""

    def __init__(
        self,
        *,
        node_id: str,
        operator_id: str,
        base_url: str,
        key_id: str,
        private_seed: bytes,
        registry: KeyRegistry,
        replay_ledger: DurableReplayLedger,
        max_requests_per_principal: int = 100,
    ):
        validate_federation_endpoint(base_url)
        self.node_id = node_id
        self.operator_id = operator_id
        self.base_url = base_url.rstrip("/")
        self.key_id = key_id
        self.private_seed = private_seed
        self.registry = registry
        self.replay_ledger = replay_ledger
        self.max_requests_per_principal = max_requests_per_principal
        self.request_counts = {}
        self.objects = {}
        self.revisions = {}
        self.publications = {}
        self.withdrawn_publications = set()
        self.subscriptions = {}
        self.event_log = []
        self._receipt_seq = 0

    def _check_rate_limit(self, principal_id: str) -> None:
        used = self.request_counts.get(principal_id, 0)
        if used >= self.max_requests_per_principal:
            raise WtpError(
                f"ERR_RATE_LIMIT: principal {principal_id} exceeded rate quota ({self.max_requests_per_principal})"
            )
        self.request_counts[principal_id] = used + 1

    def get_node_meta(self, *, envelope_id: str, occurred_at: str = "2026-10-18T10:00:00Z") -> dict:
        unsigned = {
            "protocol": "wutong/0.1",
            "kind": "wutong.node_meta",
            "id": envelope_id,
            "occurred_at": occurred_at,
            "payload": {
                "node_id": self.node_id,
                "operator_id": self.operator_id,
                "implementation": "wutong-reference/0.1.2",
                "supported_profiles": [
                    "core",
                    "document",
                    "agent",
                    "security",
                    "sync",
                    "federation",
                    "service",
                    "interop",
                ],
                "supported_encodings": [
                    "application/wtp+json",
                    "application/wtp+cbor",
                ],
                "max_envelope_bytes": 1048576,
                "endpoints": {
                    "base_url": self.base_url,
                    "meta_path": "/_wutong/v0.1/meta",
                    "objects_path": "/_wutong/v0.1/objects",
                    "revisions_path": "/_wutong/v0.1/revisions",
                    "resolve_path": "/_wutong/v0.1/resolve",
                    "subscriptions_path": "/_wutong/v0.1/subscriptions",
                    "invocations_path": "/_wutong/v0.1/invocations",
                    "sync_path": "/_wutong/v0.1/sync",
                },
            },
        }
        return sign_envelope(
            unsigned,
            self.private_seed,
            signer_id=self.operator_id,
            key_id=self.key_id,
            issued_at=occurred_at,
            nonce="META-" + envelope_id[-19:],
        )

    def ingest_public_envelope(self, signed_envelope: dict, *, now=None):
        signer = signed_envelope.get("auth", {}).get("signer_id", "")
        self._check_rate_limit(signer)
        verify_envelope(
            signed_envelope,
            self.registry.lookup_key,
            now=now,
            replay=self.replay_ledger,
            mode="live",
        )
        kind = signed_envelope["kind"]
        p = signed_envelope["payload"]
        if kind == "wutong.object":
            self.objects[p["object_id"]] = signed_envelope
        elif kind == "wutong.revision":
            self.revisions[p["revision_id"]] = signed_envelope
        elif kind == "wutong.publication":
            self.publications[p["publication_id"]] = signed_envelope
        elif kind == "wutong.revocation" and p["target_kind"] == "publication":
            self.withdrawn_publications.add(p["target_id"])
        self.event_log.append(signed_envelope)
        return True

    def resolve(self, resource_ref: str) -> dict:
        if resource_ref in self.withdrawn_publications:
            raise WtpError("ERR_UNRESOLVED: publication withdrawn")
        if resource_ref in self.publications:
            pub = self.publications[resource_ref]
            if pub["payload"]["publication_id"] in self.withdrawn_publications:
                raise WtpError("ERR_UNRESOLVED: publication withdrawn")
            return pub
        if resource_ref in self.objects:
            return self.objects[resource_ref]
        if resource_ref in self.revisions:
            return self.revisions[resource_ref]
        raise WtpError(f"ERR_UNRESOLVED: unknown resource {resource_ref}")

    def register_subscription(self, signed_sub: dict, *, now=None) -> dict:
        if signed_sub.get("kind") != "wutong.subscription":
            raise WtpError("ERR_SCHEMA: expected wutong.subscription")
        signer = signed_sub.get("auth", {}).get("signer_id", "")
        self._check_rate_limit(signer)
        verify_envelope(
            signed_sub,
            self.registry.lookup_key,
            now=now,
            replay=self.replay_ledger,
            mode="live",
        )
        p = signed_sub["payload"]
        if signed_sub["auth"]["signer_id"] != p["subscriber_id"]:
            raise WtpError("ERR_PERMISSION: subscription signer must match subscriber_id")
        self.subscriptions[p["subscription_id"]] = signed_sub
        return signed_sub

    def poll_subscription(
        self,
        subscription_id: str,
        *,
        cursor: str = "0",
        limit: int = 50,
    ) -> dict:
        if subscription_id not in self.subscriptions:
            raise WtpError("ERR_UNRESOLVED: unknown subscription")
        if not isinstance(limit, int) or limit < 1 or limit > 256:
            raise WtpError("ERR_SCHEMA: poll limit must be in 1..256")
        try:
            start_idx = int(cursor)
            if start_idx < 0:
                raise ValueError
        except ValueError as e:
            raise WtpError("ERR_SCHEMA: invalid subscription cursor") from e

        sub = self.subscriptions[subscription_id]["payload"]
        allowed_kinds = set(sub["filter_kinds"])
        events = []
        idx = start_idx
        while idx < len(self.event_log) and len(events) < limit:
            ev = self.event_log[idx]
            idx += 1
            if not allowed_kinds or ev["kind"] in allowed_kinds:
                events.append(ev)

        has_more = any(
            (not allowed_kinds or e["kind"] in allowed_kinds)
            for e in self.event_log[idx:]
        )
        return {
            "subscription_id": subscription_id,
            "next_cursor": str(idx),
            "has_more": has_more,
            "events": events,
        }

    def invoke_protected_action(
        self,
        signed_invocation: dict,
        *,
        signed_capabilities: list,
        root_owner: str,
        resource_ref: str = None,
        action: str = None,
        at: str = "2026-10-18T10:00:00Z",
        revocation_freshness_at: str = "2026-10-18T09:55:00Z",
        now=None,
    ) -> dict:
        """Verifies a signed invocation (e.g. `wutong.service_invocation`) and returns a signed `wutong.receipt`."""
        signer = signed_invocation.get("auth", {}).get("signer_id", "")
        self._check_rate_limit(signer)
        verify_envelope(
            signed_invocation,
            self.registry.lookup_key,
            now=now,
            replay=self.replay_ledger,
            mode="live",
        )
        p = signed_invocation["payload"]
        if signed_invocation["kind"] == "wutong.service_invocation":
            if p["caller_id"] != signer:
                raise WtpError("ERR_PERMISSION: service_invocation caller_id must match signer_id")
            resource_ref = resource_ref or p["target_ref"]
            action = action or p["action"]
        if not authorize_signed_capability_chain(
            signed_capabilities,
            registry=self.registry,
            root_owner=root_owner,
            actor=signer,
            resource=resource_ref,
            action=action,
            at=at,
            revocation_freshness_at=revocation_freshness_at,
        ):
            raise WtpError("ERR_PERMISSION: capability chain denied invocation")
        self.event_log.append(signed_invocation)
        self._receipt_seq += 1
        req_digest = canonical_sha256(
            {k: v for k, v in signed_invocation.items() if k != "proof"}
        )
        receipt_unsigned = {
            "protocol": "wutong/0.1",
            "kind": "wutong.receipt",
            "id": f"urn:uuid:019a1111-1111-7111-8111-00000088{self._receipt_seq:04x}",
            "occurred_at": at,
            "payload": {
                "receipt_id": f"urn:uuid:019a1111-1111-7111-8111-00000089{self._receipt_seq:04x}",
                "request_id": signed_invocation["id"],
                "request_digest": req_digest,
                "responder_id": self.operator_id,
                "status": "accepted",
            },
        }
        return sign_envelope(
            receipt_unsigned,
            self.private_seed,
            signer_id=self.operator_id,
            key_id=self.key_id,
            issued_at=at,
            nonce=f"RCPT-{self._receipt_seq:019d}",
        )


class RevisionDAG:
    """Verifies Revision DAG acyclicity, causal order, and unresolved parent quarantine."""

    def __init__(self):
        self.nodes = {}
        self.parents = {}

    def add_revision(self, revision_envelope: dict):
        if revision_envelope.get("kind") != "wutong.revision":
            raise WtpError("ERR_SCHEMA: expected wutong.revision")
        p = revision_envelope["payload"]
        rid = p["revision_id"]
        plist = list(p.get("parents", ()))
        if rid in plist:
            raise WtpError("ERR_SCHEMA: self parent revision")
        for parent in plist:
            if self._is_reachable(parent, rid):
                raise WtpError("ERR_CONFLICT: cycle detected in Revision DAG")
        self.nodes[rid] = revision_envelope
        self.parents[rid] = plist

    def _is_reachable(self, start: str, target: str) -> bool:
        stack = [start]
        visited = set()
        while stack:
            cur = stack.pop()
            if cur == target:
                return True
            if cur in visited:
                continue
            visited.add(cur)
            for nxt in self.parents.get(cur, ()):
                stack.append(nxt)
        return False

    def unresolved_parents(self, revision_id: str) -> list:
        if revision_id not in self.parents:
            raise WtpError("ERR_UNRESOLVED: revision not in DAG")
        return [p for p in self.parents[revision_id] if p not in self.nodes]

    def is_fully_resolved(self, revision_id: str) -> bool:
        stack = [revision_id]
        visited = set()
        while stack:
            cur = stack.pop()
            if cur not in self.nodes:
                return False
            if cur in visited:
                continue
            visited.add(cur)
            stack.extend(self.parents.get(cur, ()))
        return True

    def topological_order(self) -> list:
        visited = {}
        order = []

        def dfs(u):
            state = visited.get(u, 0)
            if state == 1:
                raise WtpError("ERR_CONFLICT: cycle in Revision DAG")
            if state == 2 or u not in self.nodes:
                return
            visited[u] = 1
            for parent in self.parents.get(u, ()):
                dfs(parent)
            visited[u] = 2
            order.append(u)

        for nid in sorted(self.nodes):
            dfs(nid)
        return order


def reanchor_annotation(selector: dict, document_text: str) -> dict:
    stype = selector.get("type")
    if stype == "TextPosition":
        start, end = selector.get("start", 0), selector.get("end", 0)
        if 0 <= start <= end <= len(document_text):
            extracted = document_text[start:end]
            exact = selector.get("exact")
            if exact is None or extracted == exact:
                return {"status": "resolved", "start": start, "end": end, "exact": extracted}
            idx = document_text.find(exact)
            if idx != -1:
                return {
                    "status": "stale",
                    "start": idx,
                    "end": idx + len(exact),
                    "exact": exact,
                }
        return {"status": "orphan", "start": None, "end": None, "exact": None}

    if stype == "BytePosition":
        raw = document_text.encode("utf-8") if isinstance(document_text, str) else bytes(document_text)
        start, end = selector.get("start", 0), selector.get("end", 0)
        if 0 <= start <= end <= len(raw):
            try:
                extracted = raw[start:end].decode("utf-8", "strict")
                return {"status": "resolved", "start": start, "end": end, "exact": extracted}
            except UnicodeDecodeError:
                return {"status": "orphan", "start": None, "end": None, "exact": None}
        return {"status": "orphan", "start": None, "end": None, "exact": None}

    if stype == "TextQuote":
        exact = selector.get("exact", "")
        prefix = selector.get("prefix", "")
        suffix = selector.get("suffix", "")
        if not exact:
            return {"status": "orphan", "start": None, "end": None, "exact": None}
        full_pattern = prefix + exact + suffix
        if (prefix or suffix) and full_pattern in document_text:
            idx = document_text.index(full_pattern) + len(prefix)
            return {
                "status": "resolved",
                "start": idx,
                "end": idx + len(exact),
                "exact": exact,
            }
        idx = document_text.find(exact)
        if idx != -1:
            status = "resolved" if not (prefix or suffix) else "stale"
            return {
                "status": status,
                "start": idx,
                "end": idx + len(exact),
                "exact": exact,
            }
        return {"status": "orphan", "start": None, "end": None, "exact": None}

    raise WtpError(f"ERR_UNSUPPORTED: selector type {stype!r}")


class InteropProjectionTracker:
    """Prevents external sync loops (`WTP -> Adapter -> RSS/Webhook -> WTP`) and tracks fidelity loss."""

    def __init__(self):
        self.exported_digests = {}
        self.loss_reports = []

    def record_export(
        self,
        *,
        object_id: str,
        adapter_id: str,
        remote_ref: str,
        content_digest: str,
        dropped_features=(),
    ) -> dict:
        key = (object_id, adapter_id, remote_ref)
        self.exported_digests.setdefault(key, set()).add(content_digest)
        report = {
            "object_id": object_id,
            "adapter_id": adapter_id,
            "remote_ref": remote_ref,
            "content_digest": content_digest,
            "lossy": bool(dropped_features),
            "dropped_features": list(dropped_features),
        }
        self.loss_reports.append(report)
        return report

    def verify_inbound_not_loop(
        self,
        *,
        object_id: str,
        adapter_id: str,
        remote_ref: str,
        inbound_digest: str,
        hop_trail=(),
    ) -> bool:
        if adapter_id in hop_trail:
            raise WtpError("ERR_CONFLICT: interop adapter hop loop detected")
        key = (object_id, adapter_id, remote_ref)
        if inbound_digest in self.exported_digests.get(key, set()):
            raise WtpError("ERR_CONFLICT: inbound external content matches previously exported digest (echo loop)")
        return True
