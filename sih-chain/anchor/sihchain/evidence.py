"""Content-addressed evidence storage. Implement EvidenceStore for MinIO/S3 in deployments."""
import abc
import os

from .canonical import canonical_bytes, sha256


class EvidenceStore(abc.ABC):
    @abc.abstractmethod
    def put(self, bundle: dict) -> tuple[bytes, str]:
        """Store a bundle; return (sha256 digest of canonical bytes, uri)."""

    @abc.abstractmethod
    def get(self, digest: bytes) -> bytes | None:
        """Return stored bytes for a digest, or None."""


class FileEvidenceStore(EvidenceStore):
    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def _path(self, digest: bytes) -> str:
        h = digest.hex()
        return os.path.join(self.root, h[:2], h)

    def put(self, bundle: dict) -> tuple[bytes, str]:
        data = canonical_bytes(bundle)
        digest = sha256(data)
        path = self._path(digest)
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        return digest, f"evidence://sha256/{digest.hex()}"

    def get(self, digest: bytes) -> bytes | None:
        try:
            with open(self._path(digest), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None
