"""Local append-only hash-chained log (SQLite). Source of truth for ordering; survives ledger outages."""
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field

from eth_utils import keccak

GENESIS = b"\x00" * 32


def compute_entry_hash(seq: int, alert_hash: bytes, bundle_sha256: bytes, prev_hash: bytes, ts_ms: int) -> bytes:
    return keccak(seq.to_bytes(8, "big") + alert_hash + bundle_sha256 + prev_hash + ts_ms.to_bytes(8, "big"))


@dataclass
class Entry:
    seq: int
    alert_id: str
    alert_hash: bytes
    bundle_sha256: bytes
    prev_hash: bytes
    entry_hash: bytes
    ts_ms: int
    batch_id: int | None = None
    tx_hash: str | None = None
    block: int | None = None
    proof: list[bytes] = field(default_factory=list)


class WriteAheadLog:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS entries(
                seq INTEGER PRIMARY KEY, alert_id TEXT UNIQUE NOT NULL,
                alert_hash BLOB NOT NULL, bundle_sha256 BLOB NOT NULL,
                prev_hash BLOB NOT NULL, entry_hash BLOB NOT NULL, ts_ms INTEGER NOT NULL,
                batch_id INTEGER, tx_hash TEXT, block INTEGER, proof TEXT)"""
        )
        self._db.commit()

    @staticmethod
    def _row(r) -> Entry:
        proof = [bytes.fromhex(x) for x in json.loads(r[10])] if r[10] else []
        return Entry(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], proof)

    def append(self, alert_id: str, alert_hash: bytes, bundle_sha256: bytes, ts_ms: int | None = None) -> Entry:
        with self._lock:
            existing = self.get(alert_id)
            if existing:  # idempotent on alert_id
                return existing
            last = self._db.execute("SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (last[0] + 1, last[1]) if last else (0, GENESIS)
            ts_ms = ts_ms if ts_ms is not None else int(time.time() * 1000)
            eh = compute_entry_hash(seq, alert_hash, bundle_sha256, prev, ts_ms)
            self._db.execute(
                "INSERT INTO entries(seq, alert_id, alert_hash, bundle_sha256, prev_hash, entry_hash, ts_ms) VALUES (?,?,?,?,?,?,?)",
                (seq, alert_id, alert_hash, bundle_sha256, prev, eh, ts_ms),
            )
            self._db.commit()
            return Entry(seq, alert_id, alert_hash, bundle_sha256, prev, eh, ts_ms)

    def get(self, alert_id: str) -> Entry | None:
        r = self._db.execute("SELECT * FROM entries WHERE alert_id=?", (alert_id,)).fetchone()
        return self._row(r) if r else None

    def get_seq(self, seq: int) -> Entry | None:
        r = self._db.execute("SELECT * FROM entries WHERE seq=?", (seq,)).fetchone()
        return self._row(r) if r else None

    def unanchored(self, limit: int = 1000) -> list[Entry]:
        rows = self._db.execute("SELECT * FROM entries WHERE batch_id IS NULL ORDER BY seq LIMIT ?", (limit,)).fetchall()
        return [self._row(r) for r in rows]

    def range(self, first: int, last: int) -> list[Entry]:
        rows = self._db.execute("SELECT * FROM entries WHERE seq BETWEEN ? AND ? ORDER BY seq", (first, last)).fetchall()
        return [self._row(r) for r in rows]

    def mark_anchored(self, entries: list[Entry], proofs: list[list[bytes]], batch_id: int, tx_hash: str, block: int):
        with self._lock:
            for e, p in zip(entries, proofs):
                self._db.execute(
                    "UPDATE entries SET batch_id=?, tx_hash=?, block=?, proof=? WHERE seq=?",
                    (batch_id, tx_hash, block, json.dumps([x.hex() for x in p]), e.seq),
                )
            self._db.commit()

    def batch_ids(self) -> list[int]:
        return [r[0] for r in self._db.execute("SELECT DISTINCT batch_id FROM entries WHERE batch_id IS NOT NULL ORDER BY batch_id")]

    def batch_range(self, batch_id: int) -> tuple[int, int]:
        r = self._db.execute("SELECT MIN(seq), MAX(seq) FROM entries WHERE batch_id=?", (batch_id,)).fetchone()
        return r[0], r[1]

    def count(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    def pending_count(self) -> int:
        return self._db.execute("SELECT COUNT(*) FROM entries WHERE batch_id IS NULL").fetchone()[0]

    def oldest_pending_age_s(self) -> float | None:
        r = self._db.execute("SELECT MIN(ts_ms) FROM entries WHERE batch_id IS NULL").fetchone()[0]
        return None if r is None else max(0.0, time.time() - r / 1000)

    def verify_chain(self) -> tuple[bool, str]:
        """Recompute every entry hash and link; detect edits, deletions and reordering."""
        prev, expected_seq = GENESIS, 0
        for r in self._db.execute("SELECT * FROM entries ORDER BY seq"):
            e = self._row(r)
            if e.seq != expected_seq:
                return False, f"sequence gap: expected {expected_seq}, found {e.seq}"
            if e.prev_hash != prev:
                return False, f"broken link at seq {e.seq}"
            if compute_entry_hash(e.seq, e.alert_hash, e.bundle_sha256, e.prev_hash, e.ts_ms) != e.entry_hash:
                return False, f"entry hash mismatch at seq {e.seq}"
            prev, expected_seq = e.entry_hash, expected_seq + 1
        return True, "ok"
