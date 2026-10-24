"""Independent verification of one alert against the ledger. Does not trust the stored entry hash or proof blindly."""
from dataclasses import dataclass, field

from eth_utils import keccak

from .canonical import alert_hash, canonical_bytes, sha256
from .chain import ChainClient, ZERO32
from .evidence import EvidenceStore
from .merkle import verify_proof
from .wal import WriteAheadLog, compute_entry_hash

import json


@dataclass
class Step:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    alert_id: str
    steps: list[Step] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.steps) and all(s.ok for s in self.steps)

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.steps.append(Step(name, ok, detail))
        return ok

    def to_dict(self) -> dict:
        return {"alert_id": self.alert_id, "ok": self.ok,
                "steps": [{"name": s.name, "ok": s.ok, "detail": s.detail} for s in self.steps]}


def verify_alert(alert_id: str, wal: WriteAheadLog, store: EvidenceStore, chain: ChainClient) -> Report:
    r = Report(alert_id)
    entry = wal.get(alert_id)
    if not r.add("log_entry_found", entry is not None, "" if entry else "no log entry for this alert"):
        return r

    # 1. evidence bundle is present and matches the logged digest
    data = store.get(entry.bundle_sha256)
    if not r.add("evidence_present", data is not None):
        return r
    r.add("evidence_hash", sha256(data) == entry.bundle_sha256, "stored bytes must hash to the logged digest")

    # 2. the alert inside the bundle matches the logged alert hash
    try:
        bundle = json.loads(data)
        r.add("alert_hash", alert_hash(bundle["alert"]) == entry.alert_hash and bundle["alert"].get("alert_id") == alert_id)
    except Exception as exc:
        r.add("alert_hash", False, f"bundle unreadable: {exc}")

    # 3. local hash chain intact (detects edits, deletions, reordering)
    ok, msg = wal.verify_chain()
    r.add("log_chain_intact", ok, msg)

    # 4. anchored?
    if not r.add("anchored", entry.batch_id is not None, "pending: not yet on the ledger" if entry.batch_id is None else f"batch {entry.batch_id}"):
        return r

    # 5. Merkle proof against the on-chain root (leaf rebuilt from fields, not from the stored hash)
    recomputed = compute_entry_hash(entry.seq, entry.alert_hash, entry.bundle_sha256, entry.prev_hash, entry.ts_ms)
    leaf = keccak(recomputed)
    b = chain.batch(entry.batch_id)
    r.add("merkle_proof_local", verify_proof(leaf, entry.proof, b["root"]))
    r.add("merkle_proof_onchain", chain.verify_onchain(entry.batch_id, leaf, entry.proof))
    r.add("seq_in_batch_range", b["first_seq"] <= entry.seq <= b["last_seq"], f"{b['first_seq']}..{b['last_seq']}")
    r.add("sensor_matches", b["sensor"] == chain.sender)

    # 6. batch chain: prev_root links and no gaps between this sensor's batches
    ids = wal.batch_ids()
    pos = ids.index(entry.batch_id)
    if pos == 0:
        r.add("batch_link", b["prev_root"] == ZERO32 and b["first_seq"] == 0, "first batch of this sensor")
    else:
        prev = chain.batch(ids[pos - 1])
        r.add("batch_link", b["prev_root"] == prev["root"] and prev["last_seq"] + 1 == b["first_seq"])
    return r
