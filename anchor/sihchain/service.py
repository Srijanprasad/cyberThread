"""Anchor service: alert -> evidence store -> hash-chained log -> Merkle batch -> ledger.
Detection never waits on this service; ledger outages only delay anchoring."""
import json
import logging
import time

from eth_utils import keccak

from .canonical import alert_hash, canonical_bytes, sha256
from .chain import ChainClient, ChainUnavailable, ZERO32
from .evidence import EvidenceStore
from .merkle import build_tree, merkle_proof, root_of
from .wal import Entry, WriteAheadLog

log = logging.getLogger("sihchain.service")


class IntegrityError(Exception):
    pass


class AnchorService:
    def __init__(self, wal: WriteAheadLog, store: EvidenceStore, chain: ChainClient,
                 batch_size: int = 100, batch_interval_s: float = 10.0, clock=time.monotonic):
        self.wal, self.store, self.chain = wal, store, chain
        self.batch_size, self.batch_interval_s, self._clock = batch_size, batch_interval_s, clock
        self._last_flush = clock()
        self.metrics = {"ingested": 0, "batches": 0, "anchored": 0, "anchor_failures": 0, "recovered_batches": 0}

    # ---- ingest -------------------------------------------------------
    def ingest(self, alert: dict, evidence: dict | None = None) -> Entry:
        """Persist evidence and append to the local log. Fast, never touches the ledger."""
        if "alert_id" not in alert:
            raise ValueError("alert must carry an alert_id")
        bundle = {"alert": alert, "evidence": evidence if evidence is not None else alert.get("evidence")}
        digest, _uri = self.store.put(bundle)
        entry = self.wal.append(alert["alert_id"], alert_hash(alert), digest)
        self.metrics["ingested"] += 1
        return entry

    # ---- anchoring ----------------------------------------------------
    def due(self) -> bool:
        pending = self.wal.pending_count()
        return pending >= self.batch_size or (pending > 0 and self._clock() - self._last_flush >= self.batch_interval_s)

    def flush(self, force: bool = False) -> int:
        """Anchor one batch of pending entries. Returns the number anchored (0 on outage). Never raises on outage."""
        if not force and not self.due():
            return 0
        entries = self.wal.unanchored(self.batch_size)
        if not entries:
            return 0
        first, last = entries[0].seq, entries[-1].seq
        if last - first + 1 != len(entries):
            raise IntegrityError("pending entries are not contiguous")

        try:
            chain_next = self.chain.next_seq()
        except ChainUnavailable as exc:
            return self._failed(exc)
        if chain_next > first:
            return self._recover(entries, chain_next)
        if chain_next < first:
            raise IntegrityError(f"ledger expects seq {chain_next} but log starts at {first}")

        layers = build_tree([keccak(e.entry_hash) for e in entries])
        root = root_of(layers)
        uri = f"wal://{first}-{last}"
        try:
            batch_id, tx_hash, block = self.chain.anchor_batch(root, first, last, uri)
        except ChainUnavailable as exc:
            return self._failed(exc)
        proofs = [merkle_proof(layers, i) for i in range(len(entries))]
        self.wal.mark_anchored(entries, proofs, batch_id, tx_hash, block)
        self._last_flush = self._clock()
        self.metrics["batches"] += 1
        self.metrics["anchored"] += len(entries)
        return len(entries)

    def drain(self, max_batches: int = 1000) -> int:
        total = 0
        for _ in range(max_batches):
            n = self.flush(force=True)
            if n == 0:
                break
            total += n
        return total

    def _failed(self, exc) -> int:
        self.metrics["anchor_failures"] += 1
        log.warning("ledger unavailable, %d entries stay pending: %s", self.wal.pending_count(), exc)
        return 0

    def _recover(self, entries: list[Entry], chain_next: int) -> int:
        """The ledger already holds a batch the log has not marked (crash after tx, before mark)."""
        first = entries[0].seq
        for batch_id in range(self.chain.batch_count() - 1, -1, -1):
            b = self.chain.batch(batch_id)
            if b["sensor"] == self.chain.sender and b["first_seq"] == first:
                batch_entries = self.wal.range(b["first_seq"], b["last_seq"])
                layers = build_tree([keccak(e.entry_hash) for e in batch_entries])
                if root_of(layers) != b["root"]:
                    raise IntegrityError(f"on-chain root for seq {first}-{b['last_seq']} does not match the local log")
                proofs = [merkle_proof(layers, i) for i in range(len(batch_entries))]
                self.wal.mark_anchored(batch_entries, proofs, batch_id, "recovered", 0)
                self.metrics["recovered_batches"] += 1
                return len(batch_entries)
        raise IntegrityError(f"ledger is ahead (next seq {chain_next}) but no matching batch for seq {first}")

    # ---- loop ---------------------------------------------------------
    def run(self, source):
        """Consume an iterable of (alert, evidence|None); flush on size or interval."""
        for item in source:
            alert, evidence = item if isinstance(item, tuple) else (item, None)
            self.ingest(alert, evidence)
            self.flush()
        self.drain()

    def run_jsonl(self, path: str, follow: bool = False, poll_s: float = 0.5, stop=lambda: False) -> None:
        """Ingest alerts from a JSON-lines file. Each line is an alert object, or
        {"alert": {...}, "evidence": {...}}. With follow=True, keep tailing until stop() is true.
        A partially written last line is left alone until it is complete."""
        with open(path, "r", encoding="utf-8") as f:
            while True:
                pos = f.tell()
                line = f.readline()
                if line and line.endswith("\n"):
                    if line.strip():
                        rec = json.loads(line)
                        alert = rec["alert"] if "alert" in rec and "alert_id" not in rec else rec
                        self.ingest(alert, rec.get("evidence") if alert is not rec else None)
                        self.flush()
                    continue
                if line:  # incomplete line: rewind and wait for the writer to finish it
                    f.seek(pos)
                self.flush()
                if not follow or stop():
                    break
                time.sleep(poll_s)
        self.drain()
