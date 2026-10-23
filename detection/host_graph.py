"""
Innovation 4: Temporal Host Relationship Graph Engine.
Constructs dynamic in-memory graph of network communications (hosts, IPs, domains).
Identifies multi-host campaigns, coordinated scanning, and shared C2 infrastructure
without initiating any active probes across the data diode.
"""

import time
from collections import defaultdict
import networkx as nx
from typing import Dict, List, Any, Optional
from ingestion.schema import FlowRecord, PacketRecord, NetworkGraphState, GraphNode, GraphEdge


class HostRelationshipGraph:
    """Maintains a sliding-window communication graph."""

    def __init__(self, time_window_sec: float = 600.0):
        self.time_window = time_window_sec
        self.graph = nx.DiGraph()
        self.node_meta: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"label": "", "type": "internal_host", "alerts": 0})

    def update_from_flow(self, flow: FlowRecord, is_suspicious: bool = False, risk_score: float = 0.0):
        """Adds or updates flow relationship in the graph."""
        src = flow.src_ip
        dst = flow.dst_ip
        now = flow.last_time

        # Update source node
        if not self.graph.has_node(src):
            self.graph.add_node(src, type="internal_host", first_seen=now, last_seen=now, risk_score=risk_score)
            self.node_meta[src] = {"label": src, "type": "internal_host", "alerts": 0}
        else:
            self.graph.nodes[src]["last_seen"] = now
            if risk_score > self.graph.nodes[src].get("risk_score", 0.0):
                self.graph.nodes[src]["risk_score"] = risk_score

        # Update destination node
        if not self.graph.has_node(dst):
            node_type = "external_ip" if not dst.startswith(("10.", "192.168.", "172.16.")) else "internal_server"
            self.graph.add_node(dst, type=node_type, first_seen=now, last_seen=now, risk_score=0.0)
            self.node_meta[dst] = {"label": dst, "type": node_type, "alerts": 0}
        else:
            self.graph.nodes[dst]["last_seen"] = now

        # Update edge
        if self.graph.has_edge(src, dst):
            edge = self.graph[src][dst]
            edge["flow_count"] += 1
            edge["byte_count"] += flow.byte_count
            edge["last_seen"] = now
            if is_suspicious:
                edge["is_suspicious"] = True
        else:
            self.graph.add_edge(
                src,
                dst,
                protocol=flow.protocol,
                flow_count=1,
                byte_count=flow.byte_count,
                last_seen=now,
                is_suspicious=is_suspicious,
            )

        if is_suspicious:
            self.node_meta[src]["alerts"] = self.node_meta[src].get("alerts", 0) + 1

    def update_dns_node(self, src_ip: str, domain: str, is_suspicious: bool = False):
        """Adds domain relationship edge for DNS queries."""
        now = time.time()
        if not self.graph.has_node(domain):
            self.graph.add_node(domain, type="domain", first_seen=now, last_seen=now, risk_score=80.0 if is_suspicious else 10.0)
            self.node_meta[domain] = {"label": domain, "type": "domain", "alerts": 1 if is_suspicious else 0}
        else:
            self.graph.nodes[domain]["last_seen"] = now

        if self.graph.has_edge(src_ip, domain):
            edge = self.graph[src_ip][domain]
            edge["flow_count"] += 1
            edge["last_seen"] = now
            if is_suspicious:
                edge["is_suspicious"] = True
        else:
            self.graph.add_edge(
                src_ip,
                domain,
                protocol="DNS",
                flow_count=1,
                byte_count=0,
                last_seen=now,
                is_suspicious=is_suspicious,
            )

    def prune_old_edges(self, current_time: float):
        """Removes edges older than the sliding time window."""
        cutoff = current_time - self.time_window
        edges_to_remove = []
        for u, v, data in self.graph.edges(data=True):
            if data.get("last_seen", 0) < cutoff:
                edges_to_remove.append((u, v))
        for u, v in edges_to_remove:
            self.graph.remove_edge(u, v)

    def find_coordinated_campaigns(self) -> List[Dict[str, Any]]:
        """
        Detects multiple internal hosts communicating with the same rare external destination.
        Indicates botnet or lateral campaign.
        """
        campaigns = []
        for node in self.graph.nodes():
            in_edges = list(self.graph.in_edges(node, data=True))
            if len(in_edges) >= 2 and not node.startswith(("8.8.8.8", "1.1.1.1")):
                sources = [u for u, _ in in_edges]
                campaigns.append({
                    "target_node": node,
                    "participating_hosts": sources,
                    "edge_count": len(in_edges),
                    "interpretation": f"Campaign correlation: {len(sources)} internal endpoints targeting {node}."
                })
        return campaigns

    def get_graph_state(self, max_nodes: int = 50) -> NetworkGraphState:
        """Serializes current graph state for frontend network visualization."""
        nodes = []
        for node, data in list(self.graph.nodes(data=True))[:max_nodes]:
            meta = self.node_meta.get(node, {})
            nodes.append(GraphNode(
                id=node,
                label=meta.get("label", node),
                type=data.get("type", "host"),
                risk_score=float(data.get("risk_score", 0.0)),
                alert_count=meta.get("alerts", 0),
            ))

        edges = []
        for u, v, data in list(self.graph.edges(data=True))[:max_nodes * 2]:
            edges.append(GraphEdge(
                source=u,
                target=v,
                protocol=data.get("protocol", "IP"),
                flow_count=data.get("flow_count", 1),
                byte_count=data.get("byte_count", 0),
                last_seen=data.get("last_seen", 0.0),
                is_suspicious=data.get("is_suspicious", False),
            ))

        return NetworkGraphState(nodes=nodes, edges=edges, timestamp=time.time())
