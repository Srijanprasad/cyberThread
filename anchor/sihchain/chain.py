"""Thin web3 wrapper around the two contracts."""
import json
import os

from web3 import Web3

BUILD_DIR = os.environ.get("SIHCHAIN_BUILD_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "chain", "build"))
ZERO32 = b"\x00" * 32


def load_artifact(name: str, build_dir: str | None = None) -> dict:
    with open(os.path.join(build_dir or BUILD_DIR, f"{name}.json")) as f:
        return json.load(f)


class ChainUnavailable(Exception):
    pass


class ChainClient:
    def __init__(self, w3: Web3, anchor_address: str, registry_address: str | None = None,
                 private_key: str | None = None, from_account: str | None = None,
                 gas_price: int | None = 0, build_dir: str | None = None):
        self.w3 = w3
        self.anchor = w3.eth.contract(address=anchor_address, abi=load_artifact("EvidenceAnchor", build_dir)["abi"])
        self.registry = (
            w3.eth.contract(address=registry_address, abi=load_artifact("ModelRegistry", build_dir)["abi"])
            if registry_address else None
        )
        self._key = private_key
        if private_key:
            self.sender = w3.eth.account.from_key(private_key).address
        else:
            self.sender = from_account or w3.eth.accounts[0]
        self.gas_price = gas_price  # 0 for the private QBFT chain; None = use node's price

    # ---- transactions -------------------------------------------------
    def _send(self, fn):
        try:
            if self._key:
                tx = fn.build_transaction({
                    "from": self.sender,
                    "nonce": self.w3.eth.get_transaction_count(self.sender),
                    "gasPrice": self.w3.eth.gas_price if self.gas_price is None else self.gas_price,
                })
                signed = self.w3.eth.account.sign_transaction(tx, self._key)
                tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            else:
                tx_hash = fn.transact({"from": self.sender})
            return self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
        except Exception as exc:  # network errors, reverts, timeouts
            raise ChainUnavailable(str(exc)) from exc

    def anchor_batch(self, root: bytes, first_seq: int, last_seq: int, uri: str) -> tuple[int, str, int]:
        receipt = self._send(self.anchor.functions.anchorBatch(root, first_seq, last_seq, uri))
        if receipt["status"] != 1:
            raise ChainUnavailable("anchorBatch reverted")
        events = self.anchor.events.BatchAnchored().process_receipt(receipt)
        return events[0]["args"]["id"], receipt["transactionHash"].hex(), receipt["blockNumber"]

    # ---- reads --------------------------------------------------------
    def next_seq(self, sensor: str | None = None) -> int:
        return self.anchor.functions.nextSeq(sensor or self.sender).call()

    def batch_count(self) -> int:
        return self.anchor.functions.batchCount().call()

    def batch(self, batch_id: int) -> dict:
        root, prev, sensor, first, last, ts, uri = self.anchor.functions.batches(batch_id).call()
        return {"root": bytes(root), "prev_root": bytes(prev), "sensor": sensor,
                "first_seq": first, "last_seq": last, "ts": ts, "uri": uri}

    def verify_onchain(self, batch_id: int, leaf: bytes, proof: list[bytes]) -> bool:
        return self.anchor.functions.verify(batch_id, leaf, proof).call()

    def height(self) -> int:
        return self.w3.eth.block_number

    def is_model_approved(self, digest: bytes) -> bool:
        if not self.registry:
            raise RuntimeError("model registry address not configured")
        return self.registry.functions.isApproved(digest).call()
