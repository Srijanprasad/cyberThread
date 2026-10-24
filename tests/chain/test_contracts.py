import pytest
from eth_utils import keccak

ROOT_A, ROOT_B, ROOT_C = keccak(b"a"), keccak(b"b"), keccak(b"c")
ZERO = b"\x00" * 32


def test_only_sensor_can_anchor(chain, accts):
    with pytest.raises(Exception):
        chain.anchor.functions.anchorBatch(ROOT_A, 0, 4, "x").transact({"from": accts["other"]})
    with pytest.raises(Exception):
        chain.anchor.functions.anchorBatch(ROOT_A, 0, 4, "x").transact({"from": accts["admin"]})
    assert chain.batch_count() == 0


def test_sequence_gap_rejected_and_contiguous_accepted(chain, accts):
    chain.anchor_batch(ROOT_A, 0, 4, "b0")
    with pytest.raises(Exception):  # skipped 5
        chain.anchor.functions.anchorBatch(ROOT_B, 6, 9, "b1").transact({"from": accts["sensor"]})
    with pytest.raises(Exception):  # replay of the same range
        chain.anchor.functions.anchorBatch(ROOT_B, 0, 4, "b1").transact({"from": accts["sensor"]})
    with pytest.raises(Exception):  # bad range
        chain.anchor.functions.anchorBatch(ROOT_B, 5, 4, "b1").transact({"from": accts["sensor"]})
    chain.anchor_batch(ROOT_B, 5, 9, "b1")
    assert chain.next_seq() == 10
    assert chain.batch_count() == 2


def test_prev_root_links(chain):
    chain.anchor_batch(ROOT_A, 0, 1, "b0")
    chain.anchor_batch(ROOT_B, 2, 3, "b1")
    chain.anchor_batch(ROOT_C, 4, 4, "b2")
    assert chain.batch(0)["prev_root"] == ZERO
    assert chain.batch(1)["prev_root"] == ROOT_A
    assert chain.batch(2)["prev_root"] == ROOT_B
    assert chain.batch(2)["root"] == ROOT_C


def test_roles_are_separate(chain, accts):
    # a sensor must not be able to publish models, and an approver must not anchor
    with pytest.raises(Exception):
        chain.registry.functions.register(ROOT_A, ROOT_B, "syn", "1").transact({"from": accts["sensor"]})
    with pytest.raises(Exception):
        chain.anchor.functions.anchorBatch(ROOT_A, 0, 0, "x").transact({"from": accts["approvers"][0]})


def test_model_registry_threshold_flow(chain, accts):
    pub, (a1, a2, a3) = accts["publisher"], accts["approvers"]
    reg = chain.registry.functions
    h = keccak(b"model-v1")
    assert not chain.is_model_approved(h)  # unknown
    reg.register(h, keccak(b"dataset"), "syn-flood", "1.0.0").transact({"from": pub})
    assert not chain.is_model_approved(h)  # registered, 0 approvals
    with pytest.raises(Exception):  # duplicate registration
        reg.register(h, keccak(b"dataset"), "syn-flood", "1.0.0").transact({"from": pub})
    with pytest.raises(Exception):  # not an approver
        reg.approve(h).transact({"from": accts["other"]})
    reg.approve(h).transact({"from": a1})
    assert not chain.is_model_approved(h)  # 1 of 2
    with pytest.raises(Exception):  # same approver twice
        reg.approve(h).transact({"from": a1})
    reg.approve(h).transact({"from": a2})
    assert chain.is_model_approved(h)  # 2 of 2
    reg.revoke(h).transact({"from": accts["admin"]})
    assert not chain.is_model_approved(h)
    with pytest.raises(Exception):  # cannot approve a revoked model
        reg.approve(h).transact({"from": a3})


def test_only_admin_can_revoke(chain, accts):
    h = keccak(b"m")
    chain.registry.functions.register(h, ZERO, "d", "1").transact({"from": accts["publisher"]})
    with pytest.raises(Exception):
        chain.registry.functions.revoke(h).transact({"from": accts["approvers"][0]})
