import pytest
from eth_utils import keccak
from fastapi.testclient import TestClient

from conftest import make_alert
from sihchain.api import create_app
from sihchain.modelgate import ModelNotApproved, file_digest, require_approved


def test_model_gate(chain, accts, tmp_path):
    good = tmp_path / "syn.model"
    good.write_bytes(b"trained weights v1")
    digest = file_digest(str(good))
    reg = chain.registry.functions
    reg.register(digest, keccak(b"dataset"), "syn-flood", "1.0.0").transact({"from": accts["publisher"]})
    with pytest.raises(ModelNotApproved):  # registered but not approved
        require_approved(str(good), chain)
    for a in accts["approvers"][:2]:
        reg.approve(digest).transact({"from": a})
    assert require_approved(str(good), chain) == digest

    swapped = tmp_path / "swapped.model"
    swapped.write_bytes(b"trained weights v1 + backdoor")
    with pytest.raises(ModelNotApproved):
        require_approved(str(swapped), chain)

    reg.revoke(digest).transact({"from": accts["admin"]})
    with pytest.raises(ModelNotApproved):
        require_approved(str(good), chain)


def test_api(service, wal, store, chain):
    service.run(make_alert(i) for i in range(12))
    c = TestClient(create_app(wal, store, chain))

    s = c.get("/integrity/status").json()
    assert s["log_entries"] == 12 and s["pending_entries"] == 0 and s["log_chain_ok"] and not s["log_truncated"]

    p = c.get("/alerts/alert-0001/proof").json()
    assert p["anchored"] and p["batch_id"] == 0 and len(p["proof"]) >= 1

    assert c.get("/alerts/alert-0001/verify").json()["ok"] is True
    assert c.get("/alerts/nope/verify").status_code == 404
    assert c.get("/alerts/nope/proof").status_code == 404

    wal._db.execute("UPDATE entries SET alert_hash=? WHERE alert_id='alert-0001'", (keccak(b"x"),))
    v = c.get("/alerts/alert-0001/verify").json()
    assert v["ok"] is False
    assert c.get("/integrity/status").json()["log_chain_ok"] is False


def test_api_detects_tail_truncation(service, wal, store, chain):
    service.run(make_alert(i) for i in range(12))
    wal._db.execute("DELETE FROM entries WHERE seq >= 8")  # attacker trims the tail of the log
    c = TestClient(create_app(wal, store, chain))
    assert c.get("/integrity/status").json()["log_truncated"] is True
