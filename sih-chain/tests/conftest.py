import pytest
from web3 import EthereumTesterProvider, Web3

from sihchain.chain import ChainClient
from sihchain.deploy import deploy_contracts
from sihchain.evidence import FileEvidenceStore
from sihchain.service import AnchorService
from sihchain.wal import WriteAheadLog


@pytest.fixture
def w3():
    return Web3(EthereumTesterProvider())


@pytest.fixture
def accts(w3):
    a = w3.eth.accounts
    return {"admin": a[0], "sensor": a[1], "publisher": a[2], "approvers": [a[3], a[4], a[5]], "other": a[6]}


@pytest.fixture
def deployed(w3, accts):
    return deploy_contracts(w3, sensors=[accts["sensor"]], publishers=[accts["publisher"]],
                            approvers=accts["approvers"], threshold=2, admin=accts["admin"])


@pytest.fixture
def chain(w3, deployed, accts):
    return ChainClient(w3, deployed["EvidenceAnchor"], deployed["ModelRegistry"], from_account=accts["sensor"])


@pytest.fixture
def wal():
    return WriteAheadLog(":memory:")


@pytest.fixture
def store(tmp_path):
    return FileEvidenceStore(str(tmp_path / "evidence"))


@pytest.fixture
def service(wal, store, chain):
    return AnchorService(wal, store, chain, batch_size=10, batch_interval_s=10.0)


def make_alert(i: int) -> dict:
    return {
        "alert_id": f"alert-{i:04d}", "threat": "syn_flood", "confidence": 0.93 + i / 10000,
        "severity": "high", "ts_start": 1790000000 + i, "ts_end": 1790000001 + i,
        "entities": {"dst": "10.0.0.5", "dst_port": 443, "src_count": 4821},
        "evidence": {"top_features": [["syn_only_ratio", 0.98], ["src_entropy", 0.99]], "sample_flows": 5},
    }
