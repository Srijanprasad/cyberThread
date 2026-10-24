"""Merkle tree compatible with OpenZeppelin MerkleProof (sorted-pair keccak256, odd node promoted)."""
from eth_utils import keccak


def parent(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a <= b else keccak(b + a)


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        raise ValueError("cannot build a tree with no leaves")
    layers = [list(leaves)]
    while len(layers[-1]) > 1:
        cur, nxt = layers[-1], []
        for i in range(0, len(cur), 2):
            nxt.append(parent(cur[i], cur[i + 1]) if i + 1 < len(cur) else cur[i])
        layers.append(nxt)
    return layers  # layers[-1][0] is the root


def root_of(layers: list[list[bytes]]) -> bytes:
    return layers[-1][0]


def merkle_proof(layers: list[list[bytes]], index: int) -> list[bytes]:
    proof = []
    for layer in layers[:-1]:
        sibling = index ^ 1
        if sibling < len(layer):
            proof.append(layer[sibling])
        index //= 2
    return proof


def verify_proof(leaf: bytes, proof: list[bytes], root: bytes) -> bool:
    h = leaf
    for p in proof:
        h = parent(h, p)
    return h == root
