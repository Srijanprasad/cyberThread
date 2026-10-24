"""CLI: sihchain deploy | status | verify <alert_id>. Configuration via environment variables."""
import argparse
import json
import os
import sys

from web3 import Web3

from .chain import ChainClient
from .deploy import deploy_contracts, write_addresses
from .evidence import FileEvidenceStore
from .verify import verify_alert
from .wal import WriteAheadLog


def _w3() -> Web3:
    return Web3(Web3.HTTPProvider(os.environ.get("SIHCHAIN_RPC", "http://besu-1:8545")))


def _client(w3: Web3) -> ChainClient:
    with open(os.environ.get("SIHCHAIN_ADDRESSES", "addresses.json")) as f:
        a = json.load(f)
    return ChainClient(w3, a["EvidenceAnchor"], a.get("ModelRegistry"), private_key=os.environ["SIHCHAIN_SENSOR_KEY"])


def main(argv=None):
    p = argparse.ArgumentParser(prog="sihchain")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deploy", help="deploy contracts and grant roles (dev: keys from env)")
    d.add_argument("--threshold", type=int, default=2)
    sub.add_parser("status")
    r = sub.add_parser("run", help="anchor alerts from a JSON-lines file")
    r.add_argument("path")
    r.add_argument("--follow", action="store_true")
    r.add_argument("--batch-size", type=int, default=100)
    r.add_argument("--batch-interval", type=float, default=10.0)
    v = sub.add_parser("verify")
    v.add_argument("alert_id")
    args = p.parse_args(argv)

    w3 = _w3()
    if args.cmd == "deploy":
        admin_key = os.environ["SIHCHAIN_ADMIN_KEY"]
        sensor = w3.eth.account.from_key(os.environ["SIHCHAIN_SENSOR_KEY"]).address
        approvers = [w3.eth.account.from_key(k).address for k in os.environ.get("SIHCHAIN_APPROVER_KEYS", "").split(",") if k]
        publishers = [w3.eth.account.from_key(k).address for k in os.environ.get("SIHCHAIN_PUBLISHER_KEYS", "").split(",") if k]
        addrs = deploy_contracts(w3, [sensor], publishers, approvers, threshold=args.threshold, admin_key=admin_key)
        write_addresses(os.environ.get("SIHCHAIN_ADDRESSES", "addresses.json"), addrs)
        print(json.dumps(addrs, indent=2))
        return 0

    chain = _client(w3)
    wal = WriteAheadLog(os.environ.get("SIHCHAIN_WAL", "wal.sqlite"))
    store = FileEvidenceStore(os.environ.get("SIHCHAIN_EVIDENCE", "evidence"))
    if args.cmd == "run":
        from .service import AnchorService
        AnchorService(wal, store, chain, args.batch_size, args.batch_interval).run_jsonl(args.path, follow=args.follow)
        return 0
    if args.cmd == "status":
        ok, msg = wal.verify_chain()
        print(json.dumps({"height": chain.height(), "batches": chain.batch_count(), "entries": wal.count(),
                          "pending": wal.pending_count(), "log_chain_ok": ok, "detail": msg}, indent=2))
        return 0 if ok else 1
    report = verify_alert(args.alert_id, wal, store, chain)
    for s in report.steps:
        print(f"[{'PASS' if s.ok else 'FAIL'}] {s.name} {s.detail}")
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())
