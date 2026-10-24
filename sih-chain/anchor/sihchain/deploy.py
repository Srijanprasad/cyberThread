"""Deploy both contracts and grant roles. Works with an unlocked dev account or a private key."""
import json

from web3 import Web3

from .chain import load_artifact


def _send(w3: Web3, fn, sender: str, key: str | None, gas_price: int | None):
    if key:
        tx = fn.build_transaction({
            "from": sender,
            "nonce": w3.eth.get_transaction_count(sender),
            "gasPrice": w3.eth.gas_price if gas_price is None else gas_price,
        })
        h = w3.eth.send_raw_transaction(w3.eth.account.sign_transaction(tx, key).raw_transaction)
    else:
        h = fn.transact({"from": sender})
    receipt = w3.eth.wait_for_transaction_receipt(h, timeout=120)
    if receipt["status"] != 1:
        raise RuntimeError("transaction reverted")
    return receipt


def deploy_contracts(w3: Web3, sensors: list[str], publishers: list[str], approvers: list[str],
                     threshold: int = 2, admin: str | None = None, admin_key: str | None = None,
                     gas_price: int | None = 0, build_dir: str | None = None) -> dict:
    if admin_key:
        admin = w3.eth.account.from_key(admin_key).address
    admin = admin or w3.eth.accounts[0]

    out = {"admin": admin, "threshold": threshold}
    for name, args in (("EvidenceAnchor", [admin]), ("ModelRegistry", [admin, threshold])):
        art = load_artifact(name, build_dir)
        c = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
        receipt = _send(w3, c.constructor(*args), admin, admin_key, gas_price)
        out[name] = receipt["contractAddress"]

    anchor = w3.eth.contract(address=out["EvidenceAnchor"], abi=load_artifact("EvidenceAnchor", build_dir)["abi"])
    registry = w3.eth.contract(address=out["ModelRegistry"], abi=load_artifact("ModelRegistry", build_dir)["abi"])
    for s in sensors:
        _send(w3, anchor.functions.grantRole(anchor.functions.SENSOR_ROLE().call(), s), admin, admin_key, gas_price)
    for p in publishers:
        _send(w3, registry.functions.grantRole(registry.functions.PUBLISHER_ROLE().call(), p), admin, admin_key, gas_price)
    for a in approvers:
        _send(w3, registry.functions.grantRole(registry.functions.APPROVER_ROLE().call(), a), admin, admin_key, gas_price)
    return out


def write_addresses(path: str, addresses: dict):
    with open(path, "w") as f:
        json.dump(addresses, f, indent=2)
