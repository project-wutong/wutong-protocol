# SPDX-License-Identifier: AGPL-3.0-only
"""WTP-Sync Deterministic Handshake, Ephemeral Presence, Multi-Hop Causal Ancestor Closure & Compaction Fallback (`wutong.sync_frame`).

Refinements in v0.1.2:
1. Adds `send_presence` and `ingest_presence` for `step == "PRESENCE"` frames, enforcing
   ephemeral TTL (`1 <= ttl_seconds <= 60`) and isolating Presence state from the durable
   revision/chunk DAG.
2. Enforces `max_chunk_bytes` limit on `SYNC_CHUNK` frames before decoding or storing.
"""
import hashlib
from .wire import WtpError, b64u, deb64u, sign_envelope, verify_envelope

SYNC_STEP_ORDER = {
    "HELLO": {"AUTH"},
    "AUTH": {"SYNC_OFFER"},
    "SYNC_OFFER": {"SYNC_REQUEST", "SYNC_ACK"},
    "SYNC_REQUEST": {"SYNC_CHUNK"},
    "SYNC_CHUNK": {"SYNC_CHUNK", "SYNC_ACK"},
    "SYNC_ACK": {"SYNC_OFFER", "PRESENCE"},
    "PRESENCE": {"PRESENCE", "SYNC_OFFER"},
}


def negotiate_sync_codec(client_codecs, server_codecs, *, require_snapshot: bool = False) -> str:
    server_set = set(server_codecs)
    if require_snapshot:
        if "snapshot/1" in client_codecs and "snapshot/1" in server_set:
            return "snapshot/1"
        raise WtpError("ERR_UNSUPPORTED: peer frontier predates compaction and snapshot/1 is unavailable")
    for c in client_codecs:
        if c in server_set:
            return c
    raise WtpError("ERR_UNSUPPORTED: no mutually supported WTP-Sync codec")


class SyncReplica:
    """Represents a peer node's local revision/chunk store and ephemeral presence table."""

    def __init__(
        self,
        *,
        principal_id: str,
        key_id: str,
        private_seed: bytes,
        space_id: str,
        object_id: str,
        supported_codecs=("automerge/1", "yrs/1", "snapshot/1"),
        compacted_watermark_seq: int = 0,
        max_chunk_bytes: int = 524288,
    ):
        self.principal_id = principal_id
        self.key_id = key_id
        self.private_seed = private_seed
        self.space_id = space_id
        self.object_id = object_id
        self.supported_codecs = list(supported_codecs)
        self.compacted_watermark_seq = compacted_watermark_seq
        self.max_chunk_bytes = max_chunk_bytes
        self.chunks = {}
        self.parents = {}
        self.heads = set()
        # Ephemeral presence state (never persisted in chunks/heads!)
        self.ephemeral_presence = {}
        self._seq = 0

    def put_local_chunk(self, raw_bytes: bytes, *, parents=()) -> str:
        if len(raw_bytes) > self.max_chunk_bytes:
            raise WtpError("ERR_SCHEMA: sync chunk exceeds max_chunk_bytes")
        d = "sha256:" + hashlib.sha256(raw_bytes).hexdigest()
        self.chunks[d] = bytes(raw_bytes)
        parent_list = list(parents)
        self.parents[d] = parent_list
        for p in parent_list:
            self.heads.discard(p)
        if not any(d in plist for plist in self.parents.values()):
            self.heads.add(d)
        return d

    def build_presence_frame(
        self,
        *,
        session_id: str,
        frame_id: str,
        presence_state: str = "viewing",
        ttl_seconds: int = 30,
        occurred_at: str = "2026-10-18T10:00:00Z",
    ) -> dict:
        if presence_state not in ("online", "typing", "viewing", "idle"):
            raise WtpError("ERR_SCHEMA: invalid presence_state")
        if not isinstance(ttl_seconds, int) or not (1 <= ttl_seconds <= 60):
            raise WtpError("ERR_SCHEMA: presence ttl_seconds must be in 1..60")
        return self.build_signed_frame(
            session_id=session_id,
            frame_id=frame_id,
            step="PRESENCE",
            occurred_at=occurred_at,
            extra_payload={
                "presence_state": presence_state,
                "ttl_seconds": ttl_seconds,
            },
        )

    def ingest_presence_frame(self, signed_frame: dict, *, lookup_public_key, now=None) -> dict:
        if signed_frame.get("kind") != "wutong.sync_frame" or signed_frame.get("payload", {}).get("step") != "PRESENCE":
            raise WtpError("ERR_SCHEMA: expected PRESENCE sync_frame")
        verify_envelope(signed_frame, lookup_public_key, now=now)
        p = signed_frame["payload"]
        ttl = p.get("ttl_seconds", 30)
        if not isinstance(ttl, int) or not (1 <= ttl <= 60):
            raise WtpError("ERR_SCHEMA: invalid PRESENCE ttl_seconds")
        signer = signed_frame["auth"]["signer_id"]
        rec = {
            "principal_id": signer,
            "state": p.get("presence_state", "online"),
            "ttl_seconds": ttl,
            "occurred_at": signed_frame["occurred_at"],
        }
        self.ephemeral_presence[signer] = rec
        return rec

    def transitive_closure(self, head_digests) -> list:
        visited = set()
        order = []

        def dfs(d):
            if d in visited or d not in self.chunks:
                return
            visited.add(d)
            for p in self.parents.get(d, ()):
                dfs(p)
            order.append(d)

        for hd in sorted(head_digests):
            dfs(hd)
        return order

    def build_signed_frame(
        self,
        *,
        session_id: str,
        frame_id: str,
        step: str,
        occurred_at: str = "2026-10-18T10:00:00Z",
        nonce: str = None,
        extra_payload: dict = None,
    ) -> dict:
        self._seq += 1
        payload = {
            "session_id": session_id,
            "space_id": self.space_id,
            "object_id": self.object_id,
            "step": step,
            "seq": self._seq - 1,
        }
        if extra_payload:
            payload.update(extra_payload)
        env = {
            "protocol": "wutong/0.1",
            "kind": "wutong.sync_frame",
            "id": frame_id,
            "occurred_at": occurred_at,
            "payload": payload,
        }
        use_nonce = nonce or f"SYNC-{self._seq:019d}"
        return sign_envelope(
            env,
            self.private_seed,
            signer_id=self.principal_id,
            key_id=self.key_id,
            issued_at=occurred_at,
            nonce=use_nonce,
        )


def synchronize_replicas(
    peer_a: SyncReplica,
    peer_b: SyncReplica,
    *,
    session_id: str,
    lookup_public_key,
    peer_a_known_seq: int = 0,
    now=None,
) -> dict:
    transcript = []
    uid_base = "urn:uuid:019a1111-1111-7111-8111-00000009"
    fid = [0]

    def next_id():
        fid[0] += 1
        return f"{uid_base}{fid[0]:04x}"

    hello = peer_a.build_signed_frame(
        session_id=session_id,
        frame_id=next_id(),
        step="HELLO",
        extra_payload={"supported_codecs": peer_a.supported_codecs},
    )
    verify_envelope(hello, lookup_public_key, now=now)
    transcript.append(hello)

    need_snapshot = peer_a_known_seq < peer_b.compacted_watermark_seq
    selected = negotiate_sync_codec(
        hello["payload"]["supported_codecs"],
        peer_b.supported_codecs,
        require_snapshot=need_snapshot,
    )
    auth = peer_b.build_signed_frame(
        session_id=session_id,
        frame_id=next_id(),
        step="AUTH",
        extra_payload={
            "supported_codecs": peer_b.supported_codecs,
            "selected_codec": selected,
            "compacted_WaterMark_seq": peer_b.compacted_watermark_seq,
        },
    )
    verify_envelope(auth, lookup_public_key, now=now)
    transcript.append(auth)

    for sender, receiver in ((peer_a, peer_b), (peer_b, peer_a)):
        all_sender_order = sender.transitive_closure(sender.heads)
        offer = sender.build_signed_frame(
            session_id=session_id,
            frame_id=next_id(),
            step="SYNC_OFFER",
            extra_payload={
                "selected_codec": selected,
                "heads": all_sender_order,
            },
        )
        verify_envelope(offer, lookup_public_key, now=now)
        transcript.append(offer)

        missing = [
            d for d in offer["payload"]["heads"] if d not in receiver.chunks
        ]
        if missing:
            req = receiver.build_signed_frame(
                session_id=session_id,
                frame_id=next_id(),
                step="SYNC_REQUEST",
                extra_payload={"want": missing},
            )
            verify_envelope(req, lookup_public_key, now=now)
            transcript.append(req)

            for d in req["payload"]["want"]:
                raw = sender.chunks[d]
                plist = sender.parents.get(d, [])
                chunk_frame = sender.build_signed_frame(
                    session_id=session_id,
                    frame_id=next_id(),
                    step="SYNC_CHUNK",
                    extra_payload={
                        "selected_codec": selected,
                        "chunk_digest": d,
                        "chunk_b64u": b64u(raw),
                        "chunk_parents": plist,
                    },
                )
                verify_envelope(chunk_frame, lookup_public_key, now=now)
                decoded = deb64u(chunk_frame["payload"]["chunk_b64u"])
                if len(decoded) > receiver.max_chunk_bytes:
                    raise WtpError("ERR_SCHEMA: received sync chunk exceeds max_chunk_bytes")
                actual_digest = "sha256:" + hashlib.sha256(decoded).hexdigest()
                if actual_digest != chunk_frame["payload"]["chunk_digest"]:
                    raise WtpError("ERR_CONFLICT: sync chunk digest mismatch")
                receiver.put_local_chunk(
                    decoded, parents=chunk_frame["payload"].get("chunk_parents", ())
                )
                transcript.append(chunk_frame)

        ack = receiver.build_signed_frame(
            session_id=session_id,
            frame_id=next_id(),
            step="SYNC_ACK",
            extra_payload={"heads": sorted(receiver.heads)},
        )
        verify_envelope(ack, lookup_public_key, now=now)
        transcript.append(ack)

    return {
        "selected_codec": selected,
        "snapshot_fallback": need_snapshot,
        "converged": peer_a.heads == peer_b.heads and set(peer_a.chunks) == set(peer_b.chunks),
        "heads": sorted(peer_a.heads),
        "frames": transcript,
    }
