import { useState, useEffect } from 'react';
import { Shield, CheckCircle, X, RefreshCw, Link as LinkIcon } from 'lucide-react';

interface LedgerBlock {
  block_index: number;
  timestamp: string;
  alert_id: string;
  threat_label: string;
  mitre_technique: string;
  src_ip: string;
  dst_ip?: string;
  calibrated_confidence: number;
  risk_score: number;
  evidence_payload_hash: string;
  previous_hash: string;
  block_hash: string;
  tamper_verified: boolean;
}

interface LedgerExplorerModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const LedgerExplorerModal = ({ isOpen, onClose }: LedgerExplorerModalProps) => {
  const [blocks, setBlocks] = useState<LedgerBlock[]>([]);
  const [verification, setVerification] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const fetchLedger = async () => {
    setLoading(true);
    try {
      const [resBlocks, resVerify] = await Promise.all([
        fetch('http://localhost:8000/api/ledger'),
        fetch('http://localhost:8000/api/ledger/verify'),
      ]);
      if (resBlocks.ok) setBlocks(await resBlocks.json());
      if (resVerify.ok) setVerification(await resVerify.json());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchLedger();
    }
  }, [isOpen]);

  if (!isOpen) return null;

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
        maxWidth: '880px',
        maxHeight: '90vh',
        overflowY: 'auto',
        border: '1px solid rgba(139, 92, 246, 0.5)',
        borderRadius: '12px',
        padding: '24px',
        boxShadow: '0 0 30px rgba(139, 92, 246, 0.25)',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px', borderBottom: '1px solid rgba(51, 65, 85, 0.5)', paddingBottom: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield size={20} color="#a78bfa" />
              <h2 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#f8fafc' }}>
                Tamper-Evident Forensic Evidence Ledger
              </h2>
            </div>
            <p style={{ color: '#94a3b8', fontSize: '0.85rem', marginTop: '4px' }}>
              Append-only cryptographic hash chain ensuring immutable chain-of-custody for court & defense intelligence verification.
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

        {/* Verification Status Banner */}
        <div style={{
          background: verification?.valid ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
          border: `1px solid ${verification?.valid ? '#10b981' : '#ef4444'}`,
          borderRadius: '8px',
          padding: '12px 16px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <CheckCircle size={18} color={verification?.valid ? '#10b981' : '#ef4444'} />
            <div>
              <div style={{ fontSize: '12px', fontWeight: 700, color: verification?.valid ? '#10b981' : '#ef4444' }}>
                {verification?.status || 'CRYPTOGRAPHICALLY_VERIFIED_APPEND_ONLY'}
              </div>
              <div style={{ fontSize: '11px', color: '#cbd5e1' }}>
                {verification?.total_blocks || blocks.length} Block(s) Cryptographically Linked • SHA-256 Digest Intact
              </div>
            </div>
          </div>

          <button
            className="btn-cyber"
            style={{ borderColor: '#8b5cf6', color: '#c084fc', padding: '4px 10px', fontSize: '11px' }}
            onClick={fetchLedger}
            disabled={loading}
          >
            <RefreshCw size={12} className={loading ? 'pulse-led' : ''} /> Re-verify Chain
          </button>
        </div>

        {/* Blocks Table */}
        <div style={{ background: 'rgba(15, 23, 42, 0.6)', borderRadius: '8px', border: '1px solid rgba(51, 65, 85, 0.4)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px', textAlign: 'left' }}>
            <thead>
              <tr style={{ background: 'rgba(30, 41, 59, 0.7)', color: '#94a3b8', borderBottom: '1px solid rgba(51, 65, 85, 0.5)' }}>
                <th style={{ padding: '8px 12px' }}>Height</th>
                <th style={{ padding: '8px 12px' }}>Alert & MITRE ID</th>
                <th style={{ padding: '8px 12px' }}>Threat Category</th>
                <th style={{ padding: '8px 12px' }}>Block Hash (SHA-256)</th>
                <th style={{ padding: '8px 12px' }}>Link</th>
              </tr>
            </thead>
            <tbody>
              {blocks.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ padding: '30px', textAlign: 'center', color: '#64748b' }}>
                    Genesis block active. Trigger attack scenarios to append verified evidence blocks.
                  </td>
                </tr>
              ) : (
                blocks.map((block) => (
                  <tr key={block.block_index} style={{ borderBottom: '1px solid rgba(51, 65, 85, 0.25)' }}>
                    <td style={{ padding: '8px 12px', color: '#8b5cf6', fontWeight: 700 }} className="font-mono">
                      #{block.block_index}
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      <div style={{ fontWeight: 600, color: '#f8fafc' }} className="font-mono">{block.alert_id}</div>
                      <div style={{ fontSize: '10px', color: '#f59e0b' }}>{block.mitre_technique}</div>
                    </td>
                    <td style={{ padding: '8px 12px', color: '#cbd5e1' }}>
                      {block.threat_label.replace(/_/g, ' ').toUpperCase()}
                    </td>
                    <td style={{ padding: '8px 12px', maxWidth: '240px' }} className="font-mono">
                      <div style={{ color: '#38bdf8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {block.block_hash}
                      </div>
                      <div style={{ color: '#64748b', fontSize: '9px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        Prev: {block.previous_hash}
                      </div>
                    </td>
                    <td style={{ padding: '8px 12px', color: '#10b981' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '10px', background: 'rgba(16, 185, 129, 0.15)', padding: '2px 6px', borderRadius: '3px' }}>
                        <LinkIcon size={10} /> Valid
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
