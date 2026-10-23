import { useMemo } from 'react';

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  risk_score: number;
  alert_count: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  protocol: string;
  flow_count: number;
  byte_count: number;
  last_seen: number;
  is_suspicious: boolean;
}

interface NetworkGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onSelectNode?: (nodeId: string) => void;
}

export const NetworkGraph: React.FC<NetworkGraphProps> = ({ nodes, edges, onSelectNode }) => {
  // Compute positions on a force/radial layout
  const layout = useMemo(() => {
    const width = 500;
    const height = 320;
    const centerX = width / 2;
    const centerY = height / 2;

    const positions: Record<string, { x: number; y: number }> = {};

    const internalNodes = nodes.filter(n => n.type === 'internal_host');
    const externalNodes = nodes.filter(n => n.type !== 'internal_host');

    // Place internal hosts on an inner ring/left side
    internalNodes.forEach((node, idx) => {
      const angle = (idx / Math.max(1, internalNodes.length)) * Math.PI * 2;
      const r = 85;
      positions[node.id] = {
        x: centerX - 80 + r * Math.cos(angle) * 0.7,
        y: centerY + r * Math.sin(angle),
      };
    });

    // Place external targets/domains on an outer ring/right side
    externalNodes.forEach((node, idx) => {
      const angle = (idx / Math.max(1, externalNodes.length)) * Math.PI * 2;
      const r = 110;
      positions[node.id] = {
        x: centerX + 90 + r * Math.cos(angle) * 0.8,
        y: centerY + r * Math.sin(angle),
      };
    });

    return { width, height, positions };
  }, [nodes]);

  if (nodes.length === 0) {
    return (
      <div style={{ height: '320px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b' }}>
        <p className="font-mono text-sm">Awaiting packet telemetry to reconstruct topology...</p>
      </div>
    );
  }

  return (
    <div style={{ width: '100%', height: '320px', position: 'relative', overflow: 'hidden' }}>
      <svg width="100%" height="100%" viewBox={`0 0 ${layout.width} ${layout.height}`}>
        <defs>
          <radialGradient id="nodeGlowRed" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ef4444" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
          </radialGradient>
          <radialGradient id="nodeGlowCyan" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.6" />
            <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* Edges */}
        {edges.map((edge, i) => {
          const srcPos = layout.positions[edge.source];
          const tgtPos = layout.positions[edge.target];
          if (!srcPos || !tgtPos) return null;

          const isSusp = edge.is_suspicious;
          const strokeColor = isSusp ? '#f43f5e' : 'rgba(56, 189, 248, 0.35)';
          const strokeWidth = isSusp ? 2 : 1;

          return (
            <g key={`edge-${i}`}>
              <line
                x1={srcPos.x}
                y1={srcPos.y}
                x2={tgtPos.x}
                y2={tgtPos.y}
                stroke={strokeColor}
                strokeWidth={strokeWidth}
                strokeDasharray={isSusp ? '4,4' : undefined}
                opacity={0.7}
              />
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map(node => {
          const pos = layout.positions[node.id];
          if (!pos) return null;

          const isHighRisk = node.risk_score >= 60 || node.alert_count > 0;
          const isInternal = node.type === 'internal_host';
          const nodeColor = isHighRisk ? '#f43f5e' : isInternal ? '#06b6d4' : '#8b5cf6';
          const radius = isHighRisk ? 10 : 7;

          return (
            <g
              key={node.id}
              transform={`translate(${pos.x}, ${pos.y})`}
              style={{ cursor: 'pointer' }}
              onClick={() => onSelectNode && onSelectNode(node.id)}
            >
              {/* Glow for high risk */}
              {isHighRisk && (
                <circle r={radius * 2.2} fill="url(#nodeGlowRed)" className="pulse-led" />
              )}
              <circle
                r={radius}
                fill={nodeColor}
                stroke={isHighRisk ? '#fff' : '#1e293b'}
                strokeWidth={1.5}
              />
              <text
                y={radius + 12}
                textAnchor="middle"
                fill="#cbd5e1"
                fontSize="9px"
                fontFamily="JetBrains Mono"
                opacity={0.85}
              >
                {node.label.length > 15 ? `${node.label.slice(0, 12)}...` : node.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
