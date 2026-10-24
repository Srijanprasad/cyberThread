"""Read-only integrity API for the dashboard."""
from fastapi import FastAPI, HTTPException

from .chain import ChainClient
from .evidence import EvidenceStore
from .verify import verify_alert
from .wal import WriteAheadLog


def create_app(wal: WriteAheadLog, store: EvidenceStore, chain: ChainClient) -> FastAPI:
    app = FastAPI(title="sihchain integrity API", version="0.1.0")

    @app.get("/integrity/status")
    def status():
        ok, msg = wal.verify_chain()
        ids = wal.batch_ids()
        ledger_next = chain.next_seq()
        return {
            "chain_height": chain.height(),
            "ledger_batches": chain.batch_count(),
            "log_entries": wal.count(),
            "pending_entries": wal.pending_count(),
            "anchor_lag_seconds": wal.oldest_pending_age_s(),
            "last_batch_id": ids[-1] if ids else None,
            "log_chain_ok": ok,
            "log_chain_detail": msg,
            "ledger_next_seq": ledger_next,
            # the ledger has anchored more entries than the local log still holds: tail truncation
            "log_truncated": ledger_next > wal.count(),
        }

    @app.get("/alerts/{alert_id}/proof")
    def proof(alert_id: str):
        e = wal.get(alert_id)
        if not e:
            raise HTTPException(404, "unknown alert")
        return {
            "alert_id": alert_id, "seq": e.seq, "alert_hash": e.alert_hash.hex(),
            "bundle_sha256": e.bundle_sha256.hex(), "entry_hash": e.entry_hash.hex(),
            "batch_id": e.batch_id, "tx_hash": e.tx_hash, "block": e.block,
            "proof": [p.hex() for p in e.proof], "anchored": e.batch_id is not None,
        }

    @app.get("/alerts/{alert_id}/verify")
    def verify(alert_id: str):
        report = verify_alert(alert_id, wal, store, chain)
        if report.steps and report.steps[0].name == "log_entry_found" and not report.steps[0].ok:
            raise HTTPException(404, "unknown alert")
        return report.to_dict()

    return app
