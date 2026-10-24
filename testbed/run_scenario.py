"""
Executes a scenario end-to-end:
1. Orchestrator generates forward-only PCAP and ground-truth log.
2. Extracts canonical FlowEvents and DnsEvents.
3. Labels events into Parquet.
"""

import sys
from pathlib import Path
from testbed.orchestrator import ScenarioOrchestrator
from testbed.extract.extract_flows import extract_flows_from_pcap
from testbed.extract.extract_dns import extract_dns_from_pcap
from testbed.label import label_dataset


def run_scenario(scenario_name: str, captures_dir: str = "captures"):
    sc_path = Path("testbed/scenarios") / f"{scenario_name}.yaml"
    if not sc_path.exists():
        print(f"Error: Scenario file {sc_path} not found.")
        sys.exit(1)

    print(f"[*] Running testbed scenario: {scenario_name}...")
    orch = ScenarioOrchestrator(str(sc_path), captures_dir)
    manifest = orch.run()

    pcap_path = manifest["pcap_file"]
    print(f"[*] Extracting canonical flows and DNS queries from {pcap_path}...")
    flows = extract_flows_from_pcap(pcap_path)
    dns = extract_dns_from_pcap(pcap_path)
    print(f"[*] Extracted {len(flows)} FlowEvents and {len(dns)} DnsEvents.")

    gt_path = str(Path(captures_dir) / f"{scenario_name}_ground_truth.json")
    parquet_path = str(Path(captures_dir) / f"{scenario_name}_labeled.parquet")
    df = label_dataset(flows, dns, gt_path, parquet_path)
    print(f"[+] Labeled dataset written to {parquet_path}:")
    print(df["label"].value_counts().to_string())
    return manifest


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "syn_basic"
    run_scenario(scenario)
