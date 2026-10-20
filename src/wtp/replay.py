# SPDX-License-Identifier: AGPL-3.0-only
"""Durable SQLite-backed Replay, Idempotency, and Equivocation Ledger (Gate G05).

Solves RC1 Finding 5:
- Persists consumed `(signer_id, nonce)` pairs across process restarts using
  SQLite WAL with `PRAGMA synchronous=FULL`.
- Detects cryptographic equivocation when the same `message_id` is signed with
  different canonical bytes, recording forensic evidence in `equivocations`.
- Supports idempotent response caching when the exact same signed request is
  retried within an idempotency policy.
"""
import datetime as dt
import pathlib
import sqlite3
from .wire import EquivocationError, ReplayError


class DurableReplayLedger:
    def __init__(self, db_path):
        self.db_path = pathlib.Path(db_path)
        self.db = sqlite3.connect(str(self.db_path), isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=4000")
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS replay_nonces(
                signer_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                message_id TEXT NOT NULL,
                canonical_digest TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                response_json TEXT,
                PRIMARY KEY(signer_id, nonce)
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS message_digests(
                message_id TEXT PRIMARY KEY,
                signer_id TEXT NOT NULL,
                canonical_digest TEXT NOT NULL,
                issued_at TEXT NOT NULL
            )"""
        )
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS equivocations(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                signer_id TEXT NOT NULL,
                first_digest TEXT NOT NULL,
                second_digest TEXT NOT NULL,
                detected_at TEXT NOT NULL
            )"""
        )

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def check_equivocation(self, principal, message_id, *, canonical_digest):
        row = self.db.execute(
            "SELECT signer_id, canonical_digest FROM message_digests WHERE message_id=?",
            (message_id,),
        ).fetchone()
        if row is not None:
            prev_signer, prev_digest = row
            if prev_digest != canonical_digest or prev_signer != principal:
                now_s = dt.datetime.now(dt.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    self.db.execute(
                        "INSERT INTO equivocations(message_id, signer_id, first_digest, second_digest, detected_at) VALUES (?,?,?,?,?)",
                        (
                            message_id,
                            principal,
                            prev_digest,
                            canonical_digest,
                            now_s,
                        ),
                    )
                    self.db.execute("COMMIT")
                except Exception:
                    self.db.execute("ROLLBACK")
                    raise
                raise EquivocationError(
                    f"ERR_EQUIVOCATION: message_id {message_id} already recorded with different canonical digest"
                )

    def consume(
        self,
        principal,
        nonce,
        message_id,
        *,
        canonical_digest,
        issued_at="2026-10-18T10:00:00Z",
        allow_idempotent_retry=False,
        response_json=None,
    ):
        self.check_equivocation(
            principal, message_id, canonical_digest=canonical_digest
        )
        row = self.db.execute(
            "SELECT message_id, canonical_digest, response_json FROM replay_nonces WHERE signer_id=? AND nonce=?",
            (principal, nonce),
        ).fetchone()
        if row is not None:
            prev_mid, prev_digest, cached_resp = row
            if prev_mid != message_id or prev_digest != canonical_digest:
                now_s = dt.datetime.now(dt.timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
                self.db.execute("BEGIN IMMEDIATE")
                try:
                    self.db.execute(
                        "INSERT INTO equivocations(message_id, signer_id, first_digest, second_digest, detected_at) VALUES (?,?,?,?,?)",
                        (
                            message_id,
                            principal,
                            prev_digest,
                            canonical_digest,
                            now_s,
                        ),
                    )
                    self.db.execute("COMMIT")
                except Exception:
                    self.db.execute("ROLLBACK")
                    raise
                raise EquivocationError(
                    "ERR_EQUIVOCATION: nonce reused with different message payload"
                )
            if allow_idempotent_retry:
                return {"idempotent_replay": True, "response": cached_resp}
            raise ReplayError("ERR_REPLAY: replayed nonce")

        self.db.execute("BEGIN IMMEDIATE")
        try:
            self.db.execute(
                "INSERT INTO replay_nonces VALUES (?,?,?,?,?,?)",
                (
                    principal,
                    nonce,
                    message_id,
                    canonical_digest,
                    issued_at,
                    response_json,
                ),
            )
            self.db.execute(
                "INSERT OR IGNORE INTO message_digests VALUES (?,?,?,?)",
                (message_id, principal, canonical_digest, issued_at),
            )
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return {"idempotent_replay": False, "response": response_json}

    def equivocation_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM equivocations").fetchone()[0]
