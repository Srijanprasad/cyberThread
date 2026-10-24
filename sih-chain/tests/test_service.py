import json
import os

import pytest
from eth_utils import keccak

from conftest import make_alert
from sihchain.chain import ChainUnavailable
from sihchain.merkle import build_tree, root_of
from sihchain.service import AnchorService, IntegrityError
from sihchain.verify import verify_alert


def failed_steps(report):
    return {s.name for s in report.steps if not s.ok}


def test_end_to_end_batches_and_verification(service, wal, store, chain):
    service.run(make_alert(i) for i in range(25))
    assert wal.pending_count() == 0
    assert chain.batch_count() == 3  # 10 + 10 + 5
    assert [chain.batch(i)["first_seq"] for i in range(3)] == [0, 10, 20]
    for i in range(25):
        report = verify_alert(f"alert-{i:04d}", wal, store, chain)
        assert report.ok, report.to_dict()


def test_ingest_is_idempotent_and_requires_id(service):
    a = make_alert(1)
    e1, e2 = service.ingest(a), service.ingest(a)
    assert e1.seq == e2.seq
    with pytest.raises(ValueError):
        service.ingest({"threat": "x"})


def test_pending_alerts_report_not_anchored(service, wal, store, chain):
    service.ingest(make_alert(0))
    report = verify_alert("alert-0000", wal, store, chain)
    assert not report.ok and failed_steps(report) == {"anchored"}


def test_tampered_evidence_bundle_detected(service, wal, store, chain):
    service.run(make_alert(i) for i in range(12))
    entry = wal.get("alert-0003")
    path = store._path(entry.bundle_sha256)
    with open(path, "rb") as fh:
        forged = json.loads(fh.read())
    forged["alert"]["severity"] = "low"
    with open(path, "wb") as fh:
        fh.write(json.dumps(forged).encode())
    report = verify_alert("alert-0003", wal, store, chain)
    assert not report.ok
    assert "evidence_hash" in failed_steps(report)
    assert verify_alert("alert-0004", wal, store, chain).ok  # neighbours unaffected


def test_missing_evidence_detected(service, wal, store, chain):
    service.run(make_alert(i) for i in range(3))
    os.remove(store._path(wal.get("alert-0001").bundle_sha256))
    assert failed_steps(verify_alert("alert-0001", wal, store, chain)) == {"evidence_present"}


def test_tampered_log_row_detected(service, wal, store, chain):
    service.run(make_alert(i) for i in range(12))
    wal._db.execute("UPDATE entries SET alert_hash=? WHERE alert_id='alert-0005'", (keccak(b"forged"),))
    report = verify_alert("alert-0005", wal, store, chain)
    assert not report.ok
    assert {"log_chain_intact", "merkle_proof_local"} <= failed_steps(report)


def test_deleted_log_entry_detected(service, wal, store, chain):
    service.run(make_alert(i) for i in range(12))
    wal._db.execute("DELETE FROM entries WHERE alert_id='alert-0002'")
    assert "log_chain_intact" in failed_steps(verify_alert("alert-0004", wal, store, chain))


def test_ledger_outage_keeps_entries_and_drains_after(service, wal, store, chain, monkeypatch):
    for i in range(5):
        service.ingest(make_alert(i))
    real = chain.next_seq

    def down(*a, **k):
        raise ChainUnavailable("connection refused")

    monkeypatch.setattr(chain, "next_seq", down)
    assert service.flush(force=True) == 0  # does not raise
    assert wal.pending_count() == 5 and service.metrics["anchor_failures"] == 1
    for i in range(5, 8):  # ingest keeps working during the outage
        service.ingest(make_alert(i))
    monkeypatch.setattr(chain, "next_seq", real)
    assert service.drain() == 8
    assert all(verify_alert(f"alert-{i:04d}", wal, store, chain).ok for i in range(8))


def test_failed_submission_is_retried(service, wal, chain, monkeypatch):
    for i in range(3):
        service.ingest(make_alert(i))
    real = chain.anchor_batch
    monkeypatch.setattr(chain, "anchor_batch", lambda *a, **k: (_ for _ in ()).throw(ChainUnavailable("timeout")))
    assert service.flush(force=True) == 0 and wal.pending_count() == 3
    monkeypatch.setattr(chain, "anchor_batch", real)
    assert service.flush(force=True) == 3


def test_recovery_after_crash_between_tx_and_mark(service, wal, store, chain):
    entries = [service.ingest(make_alert(i)) for i in range(4)]
    root = root_of(build_tree([keccak(e.entry_hash) for e in entries]))
    chain.anchor_batch(root, 0, 3, "crashed-before-mark")  # ledger has it, log does not know
    assert wal.pending_count() == 4
    assert service.flush(force=True) == 4
    assert service.metrics["recovered_batches"] == 1 and chain.batch_count() == 1
    assert all(verify_alert(f"alert-{i:04d}", wal, store, chain).ok for i in range(4))


def test_ledger_root_mismatch_raises_integrity_error(service, chain):
    for i in range(4):
        service.ingest(make_alert(i))
    chain.anchor_batch(keccak(b"not the real root"), 0, 3, "bogus")
    with pytest.raises(IntegrityError):
        service.flush(force=True)


def test_due_logic_with_fake_clock(wal, store, chain):
    t = [0.0]
    svc = AnchorService(wal, store, chain, batch_size=100, batch_interval_s=10.0, clock=lambda: t[0])
    svc.ingest(make_alert(0))
    assert not svc.due()
    t[0] = 11.0
    assert svc.due() and svc.flush() == 1


def test_batch_size_triggers_without_waiting(wal, store, chain):
    svc = AnchorService(wal, store, chain, batch_size=3, batch_interval_s=3600)
    for i in range(3):
        svc.ingest(make_alert(i))
    assert svc.due() and svc.flush() == 3


def test_run_jsonl_ingests_and_anchors(tmp_path, service, wal, store, chain):
    path = tmp_path / "alerts.jsonl"
    lines = [json.dumps(make_alert(i)) for i in range(4)]
    lines.append(json.dumps({"alert": make_alert(4), "evidence": {"note": "wrapped"}}))
    path.write_text("\n".join(lines) + "\n")
    service.run_jsonl(str(path))
    assert wal.count() == 5 and wal.pending_count() == 0
    assert all(verify_alert(f"alert-{i:04d}", wal, store, chain).ok for i in range(5))


def test_run_jsonl_waits_for_partial_last_line(tmp_path, service, wal):
    path = tmp_path / "alerts.jsonl"
    full = [json.dumps(make_alert(i)) for i in range(3)]
    path.write_text("\n".join(full) + "\n" + json.dumps(make_alert(3))[:20])  # writer mid-line
    service.run_jsonl(str(path), follow=True, poll_s=0, stop=lambda: True)
    assert wal.count() == 3 and wal.pending_count() == 0
