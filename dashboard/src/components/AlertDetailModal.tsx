import { Shield, AlertTriangle, Eye, X } from 'lucide-react';

export interface EvidenceItem {
  feature_name: string;
  observed_value: any;
  baseline_value: any;
  attribution_weight: number;
  interpretation: string;
}

export interface ThreatAlert {
  alert_id: string;
  timestamp: number;
  threat_type: string;
  severity: string;
  risk_score: number;
  model_confidence: number;
  calibrated_confidence: number;
  visibility_quality: number;
  src_ip: string;
  dst_ip?: string;
  target_ports: number[];
  flow_count: number;
  evidence_trail: EvidenceItem[];
  visibility_notes: string;
  recommended_action: string;
  detection_layer: string;
}

interface AlertDetailModalProps {
  alert: ThreatAlert | null;
  onClose: () => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({ alert, onClose }) => {
  if (!alert) return null;

  const severityColor = {
    CRITICAL: '#ef4444',
    HIGH: '#f97316',
    MEDIUM: '#eab308',
    LOW: '#3b82f6',
    INFO: '#10b981',
  }[alert.severity] || '#3b82f6';

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(5, 8, 16, 0.85)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '20px',
    }}>
      <div className="glass-panel" style={{
        width: '100%',
        maxWidth: '780px',
        maxHeight: '90vh',
        overflowY: 'auto',
        border: `1px solid ${severityColor}80`,
        borderRadius: '12px',
        padding: '24px',
        boxShadow: `0 0 30px ${severityColor}30`,
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px', borderBottom: '1px solid rgba(51, 65, 85, 0.5)', paddingBottom: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className={`badge-${alert.severity.toLowerCase()}`} style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold' }}>
                {alert.severity}
              </span>
              <span className="font-mono" style={{ color: '#94a3b8', fontSize: '12px' }}>
                {alert.alert_id}
              </span>
              <span style={{ color: '#64748b', fontSize: '12px' }}>•</span>
              <span style={{ color: '#06b6d4', fontSize: '12px', fontWeight: 600 }}>
                {alert.detection_layer}
              </span>
            </div>
            <h2 style={{ fontSize: '1.4rem', fontWeight: 700, marginTop: '6px', color: '#f8fafc' }}>
              {alert.threat_type.replace(/_/g, ' ').toUpperCase()}
            </h2>
            <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '2px' }}>
              Observed from <span className="font-mono" style={{ color: '#38bdf8' }}>{alert.src_ip}</span> ➔ target <span className="font-mono" style={{ color: '#cbd5e1' }}>{alert.dst_ip || 'Broadcast/Subnet'}</span> (Port {alert.target_ports.join(', ')})
            </p>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#94a3b8',
              cursor: 'pointer',
              padding: '6px',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Score Gauges */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '14px', marginBottom: '20px' }}>
          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(51, 65, 85, 0.4)' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Composite Risk</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, color: severityColor, marginTop: '4px' }}>
              {alert.risk_score} <span style={{ fontSize: '0.9rem', color: '#64748b' }}>/ 100</span>
            </div>
          </div>

          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(51, 65, 85, 0.4)' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Calibrated Confidence</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#38bdf8', marginTop: '4px' }}>
              {(alert.calibrated_confidence * 100).toFixed(1)}%
            </div>
            <div style={{ fontSize: '10px', color: '#64748b' }}>Raw Model: {(alert.model_confidence * 100).toFixed(1)}%</div>
          </div>

          <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(51, 65, 85, 0.4)' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Observability Quality</div>
            <div style={{ fontSize: '1.6rem', fontWeight: 700, color: '#10b981', marginTop: '4px' }}>
              {(alert.visibility_quality * 100).toFixed(1)}%
            </div>
            <div style={{ fontSize: '10px', color: '#64748b' }}>Unidirectional Tap</div>
          </div>
        </div>

        {/* Innovation 3: Structured Evidence Trail */}
        <div style={{ marginBottom: '20px' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
            <Eye size={16} /> Analyst-Readable Forensic Evidence Trail
          </h3>
          <div style={{ background: 'rgba(15, 23, 42, 0.5)', borderRadius: '8px', border: '1px solid rgba(51, 65, 85, 0.4)', overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
              <thead>
                <tr style={{ background: 'rgba(30, 41, 59, 0.6)', color: '#94a3b8', borderBottom: '1px solid rgba(51, 65, 85, 0.5)' }}>
                  <th style={{ padding: '8px 12px' }}>Feature Parameter</th>
                  <th style={{ padding: '8px 12px' }}>Observed</th>
                  <th style={{ padding: '8px 12px' }}>Host Baseline</th>
                  <th style={{ padding: '8px 12px' }}>Attribution Impact</th>
                </tr>
              </thead>
              <tbody>
                {alert.evidence_trail.map((item, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(51, 65, 85, 0.25)' }}>
                    <td style={{ padding: '10px 12px' }} className="font-mono">
                      <div style={{ fontWeight: 600, color: '#f8fafc' }}>{item.feature_name}</div>
                      <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '2px' }}>{item.interpretation}</div>
                    </td>
                    <td style={{ padding: '10px 12px', color: '#f43f5e', fontWeight: 600 }} className="font-mono">
                      {String(item.observed_value)}
                    </td>
                    <td style={{ padding: '10px 12px', color: '#64748b' }} className="font-mono">
                      {String(item.baseline_value)}
                    </td>
                    <td style={{ padding: '10px 12px', minWidth: '120px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <div style={{ flex: 1, background: 'rgba(51, 65, 85, 0.4)', height: '6px', borderRadius: '3px', overflow: 'hidden' }}>
                          <div style={{
                            width: `${Math.abs(item.attribution_weight) * 100}%`,
                            background: item.attribution_weight > 0 ? '#f43f5e' : '#10b981',
                            height: '100%',
                          }} />
                        </div>
                        <span style={{ fontSize: '10px', color: '#94a3b8', width: '32px' }} className="font-mono">
                          {item.attribution_weight > 0 ? `+${(item.attribution_weight * 100).toFixed(0)}%` : `${(item.attribution_weight * 100).toFixed(0)}%`}
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Innovation 1: Visibility Calibration Notes */}
        <div style={{
          background: 'rgba(6, 182, 212, 0.08)',
          border: '1px solid rgba(6, 182, 212, 0.3)',
          borderRadius: '8px',
          padding: '12px 16px',
          marginBottom: '16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#06b6d4', fontWeight: 600, fontSize: '12px', marginBottom: '4px' }}>
            <Shield size={14} /> Data Diode Observability Calibration
          </div>
          <p style={{ fontSize: '12px', color: '#cbd5e1', lineHeight: 1.4 }}>
            {alert.visibility_notes}
          </p>
        </div>

        {/* Passive SOC Playbook Action */}
        <div style={{
          background: 'rgba(15, 23, 42, 0.8)',
          border: '1px solid rgba(245, 158, 11, 0.3)',
          borderRadius: '8px',
          padding: '14px 16px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#f59e0b', fontWeight: 600, fontSize: '12px', marginBottom: '4px' }}>
            <AlertTriangle size={14} /> Passive SOC Remediation Advisory (Out-of-Band)
          </div>
          <p style={{ fontSize: '12px', color: '#e2e8f0', lineHeight: 1.4 }}>
            {alert.recommended_action}
          </p>
        </div>
      </div>
    </div>
  );
};
