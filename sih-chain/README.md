# sihchain: blockchain layer for the SIH 2026 PS 26145 IDS

Tamper-evident anchoring of IDS alerts, evidence bundles and model provenance. It sits **after** alert fusion, on the analytics side of the enclave. It is never on the ingest path and never on the detection critical path: if the ledger is down, detection and logging continue and anchoring catches up later.

## What it does

| Piece | Purpose |
|---|---|
| `EvidenceAnchor.sol` | Append-only Merkle roots per sensor; per-sensor sequence numbers (a skipped or replayed batch is rejected); `prevRoot` links |
| `ModelRegistry.sol` | Detector artifacts usable only after N-of-M approvers sign off; revocation |
| `anchor/sihchain/` | Anchor service: canonical hashing (RFC 8785), content-addressed evidence store, SQLite hash-chained log, Merkle batching, ledger client, recovery after crashes |
| `verify.py`, `api.py`, `cli.py` | Independent per-alert verification, integrity status API for the dashboard, CLI |
| `modelgate.py` | Refuse to load a model file whose SHA-256 is not approved on the registry |
| `deploy/` | 4-validator Besu QBFT network, internal-only Docker networks, anchor service |

On-chain data is hashes and small metadata only. Never put IPs, domains or payloads on chain.

## Flow

alert -> canonical JSON -> `alert_hash` (keccak256) + evidence bundle stored by SHA-256 -> local hash-chained log entry -> every N alerts or T seconds: Merkle tree over entry hashes -> `anchorBatch(root, firstSeq, lastSeq, uri)` -> proofs saved per alert.

## Quickstart (no Docker needed)

```bash
make compile          # solc-js compiles the contracts into chain/build/
pip install -e ".[test]"
make test             # 40 tests against an in-process EVM (py-evm)
```

Anchor alerts from a JSON-lines file (each line an alert object with `alert_id`, or `{"alert": {...}, "evidence": {...}}`):

```bash
export SIHCHAIN_RPC=... SIHCHAIN_ADDRESSES=addresses.json SIHCHAIN_SENSOR_KEY=0x...
sihchain run alerts.jsonl --follow
sihchain verify alert-0001      # PASS/FAIL per step
sihchain status
```

Plug into the main pipeline by writing `alerts.final` records to that file, or by adding a consumer that calls `AnchorService.ingest()` then `flush()` (a Redpanda/Kafka adapter is not included).

## Private network (Docker)

```bash
make chain-gen        # generate validator keys + genesis with Besu
cp deploy/secrets/dev-keys.env.example deploy/secrets/dev-keys.env   # fill with throwaway keys
make chain-up && make chain-deploy
```

## What has and has not been tested

Tested (automated, in CI): contract roles, sequence-gap and replay rejection, `prevRoot` links, the model approval threshold and revocation; Python-built Merkle proofs verified by the on-chain verifier for 1, 2, 3, 4, 5, 7, 8, 100 and 1000 leaves; tamper detection for edited evidence, edited log rows, deleted entries, reordering and tail truncation; ledger outage with later drain; retry after failed submission; crash recovery; the integrity API; the model gate; JSON-lines ingest.

**Not tested:** the Docker Compose network, `gen-network.sh` and the Besu configuration (they need Docker and a Besu image, which the build environment did not have), the CLI against a live RPC, and any load or latency numbers. Treat those as a starting point and expect to adjust flags and image tags. Tests use py-evm, not Besu, so behaviour on QBFT (finality time, gas settings) still needs to be confirmed on the real network.

## Security notes and limitations

- The ledger proves records were not altered after anchoring. It does not prove an alert was correct, and a compromised sensor key can anchor false records until the role is revoked.
- Dev keys live in an env file. Use an HSM, TPM or hardware token in production, one key per sensor and per person.
- The contracts are first drafts: get them reviewed and run static analysis (for example Slither) before any real use.
- If the log's newest entries are deleted before they are anchored, nothing can detect it. Anchor frequently and monitor `log_truncated` and `anchor_lag_seconds`.
- Hashes of low-entropy values (IP addresses) can be brute-forced. Anchor whole bundles or use keyed hashes.
- Optional public anchoring needs an egress-only gateway and is not implemented here. Check with the organisers that outbound export from the enclave is acceptable.

Licence: Apache-2.0.
