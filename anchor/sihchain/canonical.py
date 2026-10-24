"""Canonical hashing. Alerts are serialised with RFC 8785 (JCS) so equal content always hashes equally."""
import hashlib

import rfc8785
from eth_utils import keccak


def canonical_bytes(obj) -> bytes:
    return rfc8785.dumps(obj)


def alert_hash(alert: dict) -> bytes:
    """keccak256 of the canonical alert JSON (32 bytes)."""
    return keccak(canonical_bytes(alert))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
