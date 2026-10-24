import random

import pytest
from eth_utils import keccak

from sihchain.merkle import build_tree, merkle_proof, root_of, verify_proof


def leaves(n, seed=1):
    rnd = random.Random(seed)
    return [keccak(rnd.randbytes(16)) for _ in range(n)]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 100, 1000])
def test_python_and_onchain_agree(n, chain):
    ls = leaves(n)
    layers = build_tree(ls)
    root = root_of(layers)
    batch_id, _tx, _block = chain.anchor_batch(root, 0, n - 1, "test")
    idxs = range(n) if n <= 100 else random.Random(2).sample(range(n), 30)
    for i in idxs:
        proof = merkle_proof(layers, i)
        assert verify_proof(ls[i], proof, root)
        assert chain.verify_onchain(batch_id, ls[i], proof)


def test_wrong_leaf_and_wrong_proof_fail(chain):
    ls = leaves(7)
    layers = build_tree(ls)
    root = root_of(layers)
    batch_id, *_ = chain.anchor_batch(root, 0, 6, "t")
    proof = merkle_proof(layers, 3)
    assert not verify_proof(ls[4], proof, root)
    assert not chain.verify_onchain(batch_id, ls[4], proof)
    assert not chain.verify_onchain(batch_id, ls[3], merkle_proof(layers, 5))


def test_empty_tree_rejected():
    with pytest.raises(ValueError):
        build_tree([])
