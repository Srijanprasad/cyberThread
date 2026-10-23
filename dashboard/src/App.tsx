import { useState, useEffect, useRef } from 'react';
import {
  Shield,
  AlertTriangle,
  Radio,
  Activity,
  Layers,
  Zap,
  Play,
  Eye,
  Terminal,
  CheckCircle,
} from 'lucide-react';
import { NetworkGraph, type GraphNode, type GraphEdge } from './components/NetworkGraph';
import { AlertDetailModal, type ThreatAlert } from './components/AlertDetailModal';

interface SystemStatus {
  status: string;
  diode_enclave_mode: string;
  active_flows_tracked: number;
  total_packets_processed: number;
  total_alerts_emitted: number;
  throughput_pps: number;
  average_latency_ms: number;
  visibility_coverage_pct: number;
  active_threat_level: string;
}

interface PacketLog {
  timestamp: number;
  src: string;
  dst: string;
  proto: string;
  len: number;
  flags: string[];
  dns?: string;
  info: string;
}

export function App() {
  const [status, setStatus] = useState<SystemStatus>({
    status: 'ONLINE',
    diode_enclave_mode: 'UNIDIRECTIONAL_PASSIVE_INGEST',
    active_flows_tracked: 0,
    total_packets_processed: 0,
    total_alerts_emitted: 0,
    throughput_pps: 0.0,
    average_latency_ms: 2.1,
    visibility_coverage_pct: 88.5,
    active_threat_level: 'NORMAL',
  });

  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [packetLogs, setPacketLogs] = useState<PacketLog[]>([]);
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simulationStatus, setSimulationStatus] = useState<string>('Ready for simulation');

  const wsRef = useRef<WebSocket | null>(null);

  // WebSocket connection for real-time telemetry
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname || 'localhost';
    const port = '8000';
    const wsUrl = `${protocol}//${host}:${port}/ws/telemetry`;

    let socket: WebSocket;
    let reconnectTimeout: any;

    const connect = () => {
      socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        console.log('[WS] Connected to CyberThread telemetry stream');
      };

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'TELEMETRY_UPDATE') {
            if (data.status) setStatus(data.status);
            if (data.alerts) setAlerts(data.alerts);
            if (data.recent_packets) setPacketLogs(data.recent_packets);
            if (data.graph) {
              setGraphNodes(data.graph.nodes || []);
              setGraphEdges(data.graph.edges || []);
            }
          } else if (data.type === 'NEW_ALERT' && data.alert) {
            setAlerts((prev) => [data.alert, ...prev.slice(0, 49)]);
          }
        } catch (e) {
          console.error('[WS] Parse error', e);
        }
      };

      socket.onerror = (e) => {
        console.warn('[WS] Error, using REST fallback', e);
      };

      socket.onclose = () => {
        reconnectTimeout = setTimeout(connect, 3000);
      };
    };

    connect();

    // Fallback polling in case WebSocket is blocked
    const pollInterval = setInterval(async () => {
      try {
        const [resStatus, resAlerts, resGraph] = await Promise.all([
          fetch('http://localhost:8000/api/status'),
          fetch('http://localhost:8000/api/alerts?limit=25'),
          fetch('http://localhost:8000/api/graph'),
        ]);
        if (resStatus.ok) setStatus(await resStatus.json());
        if (resAlerts.ok) setAlerts(await resAlerts.json());
        if (resGraph.ok) {
          const g = await resGraph.json();
          setGraphNodes(g.nodes || []);
          setGraphEdges(g.edges || []);
        }
      } catch (err) {
        // backend offline
      }
    }, 2500);

    return () => {
      if (socket) socket.close();
      clearTimeout(reconnectTimeout);
      clearInterval(pollInterval);
    };
  }, []);

  const triggerScenario = async (scenario: string) => {
    setIsSimulating(true);
    setSimulationStatus(`Injecting ${scenario.replace(/_/g, ' ')}...`);
    try {
      const res = await fetch(`http://localhost:8000/api/traffic/simulate?scenario=${scenario}&intensity=35`, {
        method: 'POST',
      });
      const data = await res.json();
      setSimulationStatus(data.message || 'Simulation running');
    } catch (err) {
      setSimulationStatus('Simulation request failed');
    } finally {
      setTimeout(() => setIsSimulating(false), 2000);
    }
  };

  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter === 'ALL') return true;
    return a.severity === severityFilter;
  });

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', padding: '16px 24px', gap: '16px' }}>
      {/* Top Banner / Classification */}
      <header className="glass-panel" style={{ padding: '14px 20px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ background: 'rgba(6, 182, 212, 0.15)', border: '1px solid rgba(6, 182, 212, 0.4)', padding: '8px', borderRadius: '8px' }}>
            <Radio size={22} color="#06b6d4" className="pulse-led" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '11px', fontWeight: 700, color: '#f59e0b', letterSpacing: '0.1em' }}>
                NTRO ENCLAVE // SIH-2026 PS-26145
              </span>
              <span style={{ fontSize: '10px', background: 'rgba(239, 68, 68, 0.2)', color: '#f87171', border: '1px solid rgba(239, 68, 68, 0.4)', padding: '1px 6px', borderRadius: '3px', fontWeight: 600 }}>
                ONE-WAY DATA DIODE ACTIVE
              </span>
            </div>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc', margin: '2px 0 0 0' }}>
              CyberThread AI — Unidirectional Threat Intelligence Platform
            </h1>
          </div>
        </div>

        {/* Telemetry Chips */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(51, 65, 85, 0.5)', borderRadius: '6px', padding: '6px 12px', textAlign: 'right' }}>
            <div style={{ fontSize: '10px', color: '#94a3b8' }}>THROUGHPUT</div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#38bdf8' }} className="font-mono">
              {status.throughput_pps} <span style={{ fontSize: '10px', color: '#64748b' }}>PPS</span>
            </div>
          </div>

          <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(51, 65, 85, 0.5)', borderRadius: '6px', padding: '6px 12px', textAlign: 'right' }}>
            <div style={{ fontSize: '10px', color: '#94a3b8' }}>INGEST LATENCY</div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#10b981' }} className="font-mono">
              {status.average_latency_ms.toFixed(1)} <span style={{ fontSize: '10px', color: '#64748b' }}>MS</span>
            </div>
          </div>

          <div style={{ background: 'rgba(15, 23, 42, 0.7)', border: '1px solid rgba(51, 65, 85, 0.5)', borderRadius: '6px', padding: '6px 12px', textAlign: 'right' }}>
            <div style={{ fontSize: '10px', color: '#94a3b8' }}>OBSERVABILITY</div>
            <div style={{ fontSize: '14px', fontWeight: 700, color: '#06b6d4' }} className="font-mono">
              {status.visibility_coverage_pct}%
            </div>
          </div>

          <div style={{
            background: status.active_threat_level === 'CRITICAL_ATTACK' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.1)',
            border: `1px solid ${status.active_threat_level === 'CRITICAL_ATTACK' ? '#ef4444' : '#10b981'}`,
            borderRadius: '6px',
            padding: '6px 14px',
            textAlign: 'center',
          }}>
            <div style={{ fontSize: '10px', color: '#cbd5e1' }}>THREAT LEVEL</div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: status.active_threat_level === 'CRITICAL_ATTACK' ? '#ef4444' : '#10b981' }}>
              {status.active_threat_level}
            </div>
          </div>
        </div>
      </header>

      {/* Interactive Scenario Trigger Bar (Judge Simulation Controls) */}
      <div className="glass-panel" style={{ padding: '12px 18px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Zap size={16} color="#f59e0b" />
          <span style={{ fontSize: '12px', fontWeight: 600, color: '#cbd5e1', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Attack Scenario Simulator:
          </span>
          <span style={{ fontSize: '11px', color: '#94a3b8', fontStyle: 'italic' }}>
            ({simulationStatus})
          </span>
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          <button className="btn-cyber btn-cyber-red" onClick={() => triggerScenario('port_scan')} disabled={isSimulating}>
            Port Scan
          </button>
          <button className="btn-cyber btn-cyber-red" onClick={() => triggerScenario('syn_flood')} disabled={isSimulating}>
            SYN Flood
          </button>
          <button className="btn-cyber btn-cyber-red" onClick={() => triggerScenario('udp_flood')} disabled={isSimulating}>
            UDP Flood
          </button>
          <button className="btn-cyber btn-cyber-red" onClick={() => triggerScenario('dns_tunneling')} disabled={isSimulating}>
            DNS Tunnel (iodine)
          </button>
          <button className="btn-cyber btn-cyber-red" onClick={() => triggerScenario('c2_beaconing')} disabled={isSimulating}>
            C2 Beacon
          </button>
          <button className="btn-cyber btn-cyber-red" onClick={() => triggerScenario('slowloris')} disabled={isSimulating}>
            Slowloris
          </button>
          <button className="btn-cyber" onClick={() => triggerScenario('benign')} disabled={isSimulating}>
            Benign Flow
          </button>
          <button className="btn-cyber" style={{ borderColor: '#8b5cf6', color: '#c084fc' }} onClick={() => triggerScenario('all')} disabled={isSimulating}>
            <Play size={13} /> Run All Suite
          </button>
        </div>
      </div>

      {/* 3-Column Core SOC Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.5fr 1.3fr', gap: '16px', flex: 1 }}>
        {/* Column 1: Live Threat Alerts Feed */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', padding: '16px', maxHeight: 'calc(100vh - 200px)', overflow: 'hidden' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', borderBottom: '1px solid rgba(51, 65, 85, 0.4)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <AlertTriangle size={18} color="#ef4444" />
              <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc' }}>
                Threat Detections ({alerts.length})
              </h2>
            </div>

            {/* Severity Filter */}
            <div style={{ display: 'flex', gap: '4px' }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  style={{
                    background: severityFilter === sev ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                    border: severityFilter === sev ? '1px solid #38bdf8' : '1px solid transparent',
                    color: severityFilter === sev ? '#38bdf8' : '#64748b',
                    fontSize: '10px',
                    fontWeight: 600,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                  }}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Alert List */}
          <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '10px', flex: 1, paddingRight: '4px' }}>
            {filteredAlerts.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px 0', color: '#64748b' }}>
                <CheckCircle size={32} color="#10b981" style={{ margin: '0 auto 10px', opacity: 0.6 }} />
                <p className="font-mono text-sm">No active threats detected in queue.</p>
                <p style={{ fontSize: '12px', marginTop: '4px' }}>Click an attack scenario button above to test live.</p>
              </div>
            ) : (
              filteredAlerts.map((alert) => {
                const sevColor = {
                  CRITICAL: '#ef4444',
                  HIGH: '#f97316',
                  MEDIUM: '#eab308',
                  LOW: '#3b82f6',
                  INFO: '#10b981',
                }[alert.severity] || '#3b82f6';

                return (
                  <div
                    key={alert.alert_id}
                    onClick={() => setSelectedAlert(alert)}
                    style={{
                      background: 'rgba(15, 23, 42, 0.65)',
                      borderLeft: `4px solid ${sevColor}`,
                      borderTop: '1px solid rgba(51, 65, 85, 0.4)',
                      borderRight: '1px solid rgba(51, 65, 85, 0.4)',
                      borderBottom: '1px solid rgba(51, 65, 85, 0.4)',
                      borderRadius: '6px',
                      padding: '12px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.background = 'rgba(30, 41, 59, 0.85)')}
                    onMouseLeave={(e) => (e.currentTarget.style.background = 'rgba(15, 23, 42, 0.65)')}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span className={`badge-${alert.severity.toLowerCase()}`} style={{ fontSize: '10px', padding: '1px 6px', borderRadius: '3px', fontWeight: 700 }}>
                        {alert.severity}
                      </span>
                      <span className="font-mono" style={{ fontSize: '11px', color: '#94a3b8' }}>
                        Risk: <strong style={{ color: sevColor }}>{alert.risk_score}</strong>/100
                      </span>
                    </div>

                    <div style={{ fontSize: '0.9rem', fontWeight: 600, color: '#f8fafc', marginTop: '6px' }}>
                      {alert.threat_type.replace(/_/g, ' ').toUpperCase()}
                    </div>

                    <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }} className="font-mono">
                      Src: <span style={{ color: '#38bdf8' }}>{alert.src_ip}</span> ➔ {alert.dst_ip || 'Internal'}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '8px', paddingTop: '6px', borderTop: '1px solid rgba(51, 65, 85, 0.3)' }}>
                      <span style={{ fontSize: '10px', color: '#06b6d4' }}>
                        {alert.detection_layer}
                      </span>
                      <span style={{ fontSize: '10px', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '3px' }}>
                        <Eye size={11} /> Investigate Evidence
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Column 2: Center - Attack Graph & Observability Matrix */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Innovation 4: Temporal Host Relationship Graph */}
          <div className="glass-panel" style={{ padding: '16px', display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={18} color="#06b6d4" />
                <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc' }}>
                  Temporal Host Relationship Graph
                </h2>
              </div>
              <span className="font-mono" style={{ fontSize: '11px', color: '#64748b' }}>
                {graphNodes.length} Nodes • {graphEdges.length} Active Edges
              </span>
            </div>

            <NetworkGraph nodes={graphNodes} edges={graphEdges} />

            <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', marginTop: '8px', fontSize: '11px', color: '#94a3b8' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#06b6d4' }}></span> Internal Host
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#8b5cf6' }}></span> External Server/Domain
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#f43f5e' }}></span> Malicious / High Risk
              </span>
            </div>
          </div>

          {/* Innovation 1: Observability Mask Matrix */}
          <div className="glass-panel" style={{ padding: '14px', flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Shield size={16} color="#38bdf8" />
              <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#38bdf8' }}>
                Innovation 1: Visibility-Aware Observability Matrix
              </h3>
            </div>
            <p style={{ fontSize: '11px', color: '#94a3b8', marginBottom: '10px' }}>
              Tracks physical tap constraints through the hardware data diode to prevent false assumptions on missing return packets.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', fontSize: '11px' }}>
              <div style={{ background: 'rgba(6, 182, 212, 0.08)', border: '1px solid rgba(6, 182, 212, 0.3)', padding: '8px', borderRadius: '6px' }}>
                <div style={{ color: '#06b6d4', fontWeight: 600 }}>✓ Client Egress Observables</div>
                <div style={{ color: '#94a3b8', fontSize: '10px', marginTop: '4px' }}>
                  SYN packets, PPS/BPS, IAT variance, payload entropy, DNS queries, HTTP method/URI.
                </div>
              </div>

              <div style={{ background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '8px', borderRadius: '6px' }}>
                <div style={{ color: '#f87171', fontWeight: 600 }}>✗ Unobserved Reverse Telemetry</div>
                <div style={{ color: '#94a3b8', fontSize: '10px', marginTop: '4px' }}>
                  Server SYN-ACK, HTTP status codes, DNS NXDOMAIN responses (Downweighted in model).
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Column 3: Multi-Timescale Fusion & Raw Ingest Log */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Innovation 2: Multi-Timescale Fusion Meters */}
          <div className="glass-panel" style={{ padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <Activity size={18} color="#f59e0b" />
              <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#f8fafc' }}>
                Multi-Timescale Behavioral Fusion
              </h2>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {/* Short Window */}
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(51, 65, 85, 0.4)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>Short Window (1–5s)</span>
                  <span style={{ color: '#06b6d4' }}>Floods & Bursts</span>
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '3px' }}>
                  Rate change-point detector active • Monitored at ~500ms intervals
                </div>
              </div>

              {/* Medium Window */}
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(51, 65, 85, 0.4)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>Medium Window (30–60s)</span>
                  <span style={{ color: '#f59e0b' }}>Port Scans & DNS Exfil</span>
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '3px' }}>
                  Subdomain Shannon entropy & destination port fan-out aggregation
                </div>
              </div>

              {/* Long Window */}
              <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(51, 65, 85, 0.4)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>Long Window (5–30m)</span>
                  <span style={{ color: '#8b5cf6' }}>C2 Jittered Beacons</span>
                </div>
                <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '3px' }}>
                  Autocorrelation & CV periodicity scoring for covert heartbeats
                </div>
              </div>
            </div>
          </div>

          {/* Raw Ingestion Stream Ticker */}
          <div className="glass-panel" style={{ padding: '14px', flex: 1, display: 'flex', flexDirection: 'column', maxHeight: '340px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <Terminal size={16} color="#10b981" />
              <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#f8fafc' }}>
                Passive Diode Ingest Ticker ({packetLogs.length})
              </h3>
            </div>

            <div style={{ overflowY: 'auto', flex: 1, fontSize: '11px' }} className="font-mono">
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                <tbody>
                  {packetLogs.map((pkt, i) => (
                    <tr key={i} style={{ borderBottom: '1px solid rgba(51, 65, 85, 0.25)' }}>
                      <td style={{ padding: '4px 6px', color: '#38bdf8' }}>{pkt.proto}</td>
                      <td style={{ padding: '4px 6px', color: '#94a3b8' }}>{pkt.src}</td>
                      <td style={{ padding: '4px 6px', color: '#64748b' }}>➔</td>
                      <td style={{ padding: '4px 6px', color: '#cbd5e1' }}>{pkt.dst}</td>
                      <td style={{ padding: '4px 6px', color: '#f59e0b', fontSize: '10px' }}>
                        {pkt.dns ? `Q: ${pkt.dns.slice(0, 15)}...` : pkt.flags?.length ? pkt.flags.join(',') : `${pkt.len}B`}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>

      {/* Deep-Dive Investigation & Evidence Modal (Innovation 3) */}
      <AlertDetailModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </div>
  );
}
export default App;
