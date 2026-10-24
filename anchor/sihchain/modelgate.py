"""Refuse to load detector artifacts that are not approved on the registry."""
import hashlib

from .chain import ChainClient


class ModelNotApproved(Exception):
    pass


def file_digest(path: str) -> bytes:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def require_approved(path: str, chain: ChainClient) -> bytes:
    digest = file_digest(path)
    if not chain.is_model_approved(digest):
        raise ModelNotApproved(f"{path} (sha256 {digest.hex()}) is not approved on the model registry")
    return digest
