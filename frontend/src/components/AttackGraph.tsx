import { useMemo, useState } from 'react';

import type { AttackGraph as Graph, Evidence, GraphEdge, GraphNode } from '../types';
import { Empty } from './common';

const NODE_W = 152;
const NODE_H = 40;
const COL_GAP = 196;
const ROW_GAP = 62;
const PAD = 18;

interface Placed extends GraphNode {
  x: number;
  y: number;
}

/// Left-to-right layered layout.
///
/// Layer is the longest path to a node, which puts causes left of effects and
/// makes the attack read in the order it happened. Iteration is bounded so a
/// cycle in the evidence cannot hang the render.
function layout(graph: Graph): { placed: Placed[]; width: number; height: number } {
  const layer = new Map<string, number>();
  graph.nodes.forEach((n) => layer.set(n.id, 0));

  for (let pass = 0; pass < graph.nodes.length; pass += 1) {
    let changed = false;
    for (const edge of graph.edges) {
      const from = layer.get(edge.from);
      const to = layer.get(edge.to);
      if (from === undefined || to === undefined) continue;
      if (to < from + 1) {
        layer.set(edge.to, from + 1);
        changed = true;
      }
    }
    if (!changed) break;
  }

  const byLayer = new Map<number, GraphNode[]>();
  for (const node of graph.nodes) {
    const l = layer.get(node.id) ?? 0;
    const bucket = byLayer.get(l) ?? [];
    bucket.push(node);
    byLayer.set(l, bucket);
  }

  const placed: Placed[] = [];
  let maxRows = 0;

  for (const [l, nodes] of [...byLayer.entries()].sort((a, b) => a[0] - b[0])) {
    nodes.sort(
      (a, b) => a.first_seen.localeCompare(b.first_seen) || a.label.localeCompare(b.label),
    );
    nodes.forEach((node, row) => {
      placed.push({ ...node, x: PAD + l * COL_GAP, y: PAD + row * ROW_GAP });
    });
    maxRows = Math.max(maxRows, nodes.length);
  }

  return {
    placed,
    width: PAD * 2 + byLayer.size * COL_GAP,
    height: PAD * 2 + maxRows * ROW_GAP,
  };
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

export function AttackGraphView(props: { graph: Graph; evidence: Evidence[] }) {
  const { graph, evidence } = props;
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);

  const { placed, width, height } = useMemo(() => layout(graph), [graph]);
  const byId = useMemo(() => new Map(placed.map((n) => [n.id, n])), [placed]);
  const evidenceById = useMemo(() => new Map(evidence.map((e) => [e.event_id, e])), [evidence]);

  if (graph.nodes.length === 0) {
    return <Empty what="No graph for this incident" />;
  }

  const node = selectedNode ? byId.get(selectedNode) : undefined;
  const edge = selectedEdge ? graph.edges.find((e) => e.id === selectedEdge) : undefined;

  const select = (nodeId: string | null, edgeId: string | null) => {
    setSelectedNode(nodeId);
    setSelectedEdge(edgeId);
  };

  return (
    <div>
      <div className="graph-wrap" style={{ maxHeight: 460 }}>
        <svg width={Math.max(width, 640)} height={Math.max(height, 220)} role="img">
          <defs>
            <marker
              id="arrow"
              viewBox="0 0 8 8"
              refX="7"
              refY="4"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 7 4 L 0 7 z" fill="#39414c" />
            </marker>
          </defs>

          {graph.edges.map((e) => {
            const from = byId.get(e.from);
            const to = byId.get(e.to);
            if (!from || !to) return null;

            const x1 = from.x + NODE_W;
            const y1 = from.y + NODE_H / 2;
            const x2 = to.x;
            const y2 = to.y + NODE_H / 2;
            const mid = (x1 + x2) / 2;
            const isSelected = e.id === selectedEdge;

            return (
              <g key={e.id}>
                <path
                  className={isSelected ? 'graph-edge selected' : 'graph-edge'}
                  d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                  markerEnd="url(#arrow)"
                  onClick={() => select(null, e.id)}
                />
                <text
                  className={isSelected ? 'graph-edge-label selected' : 'graph-edge-label'}
                  x={mid}
                  y={(y1 + y2) / 2 - 4}
                  textAnchor="middle"
                >
                  {e.label}
                </text>
              </g>
            );
          })}

          {placed.map((n) => (
            <g
              key={n.id}
              className={`graph-node ${n.exposure}${n.id === selectedNode ? ' selected' : ''}`}
              transform={`translate(${n.x},${n.y})`}
              onClick={() => select(n.id, null)}
            >
              <rect width={NODE_W} height={NODE_H} rx="2" />
              <text className="kind" x="8" y="14">
                {n.kind_label.toUpperCase()}
                {n.external ? ' · EXTERNAL' : ''}
                {n.criticality !== null ? ` · C${n.criticality}` : ''}
              </text>
              <text x="8" y="29">
                {truncate(n.label, 20)}
              </text>
            </g>
          ))}
        </svg>
      </div>

      <div className="legend">
        <span>
          <i style={{ borderColor: 'var(--confirmed)', background: '#24151a' }} />
          Confirmed
        </span>
        <span>
          <i style={{ borderColor: 'var(--reachable)', background: '#241f14' }} />
          Reachable
        </span>
        <span>
          <i style={{ borderColor: 'var(--potential)' }} />
          Potential
        </span>
        <span className="faint">
          {graph.nodes.length} entities · {graph.edges.length} relationships · click any node or
          relationship to inspect its evidence
        </span>
      </div>

      {node ? <NodeInspector node={node} /> : null}
      {edge ? (
        <EdgeInspector
          edge={edge}
          from={byId.get(edge.from)}
          to={byId.get(edge.to)}
          evidenceById={evidenceById}
        />
      ) : null}
    </div>
  );
}

function NodeInspector({ node }: { node: Placed }) {
  return (
    <div className="inspector">
      <h3>{node.label}</h3>
      <dl className="kv">
        <dt>Type</dt>
        <dd>{node.kind_label}</dd>
        <dt>Exposure</dt>
        <dd className={node.exposure === 'confirmed' ? 'sev-critical' : 'sev-medium'}>
          {node.exposure.toUpperCase()}
        </dd>
        <dt>Criticality</dt>
        <dd>{node.criticality !== null ? `${node.criticality}/100` : 'not an inventory asset'}</dd>
        <dt>Site</dt>
        <dd>{node.hospital ?? (node.external ? 'external infrastructure' : 'unknown')}</dd>
        <dt>Events</dt>
        <dd>{node.event_count}</dd>
        <dt>First seen</dt>
        <dd>{new Date(node.first_seen).toLocaleTimeString()}</dd>
        <dt>Last seen</dt>
        <dd>{new Date(node.last_seen).toLocaleTimeString()}</dd>
      </dl>
    </div>
  );
}

/// The evidence behind one relationship. This is the answer to "why do you claim
/// these two things are connected?".
function EdgeInspector(props: {
  edge: GraphEdge;
  from?: Placed;
  to?: Placed;
  evidenceById: Map<string, Evidence>;
}) {
  const { edge, from, to, evidenceById } = props;

  return (
    <div className="inspector">
      <h3>
        {from?.label ?? edge.from} <span className="faint">{edge.label}</span>{' '}
        {to?.label ?? edge.to}
      </h3>
      <dl className="kv">
        <dt>Confidence</dt>
        <dd>{(edge.confidence * 100).toFixed(0)}%</dd>
        <dt>First seen</dt>
        <dd>{new Date(edge.first_seen).toLocaleTimeString()}</dd>
        <dt>Last seen</dt>
        <dd>{new Date(edge.last_seen).toLocaleTimeString()}</dd>
        <dt>Detections</dt>
        <dd>{edge.signal_ids.length > 0 ? edge.signal_ids.join(', ') : 'none'}</dd>
      </dl>

      <div style={{ marginTop: 8 }}>
        <div className="label faint" style={{ fontSize: 10, letterSpacing: '0.1em' }}>
          SUPPORTING EVENTS ({edge.evidence_event_ids.length})
        </div>
        {edge.evidence_event_ids.length === 0 ? (
          <div className="dim" style={{ fontSize: 11.5 }}>
            This relationship is structural and cites no events.
          </div>
        ) : (
          <table className="data" style={{ marginTop: 5 }}>
            <tbody>
              {edge.evidence_event_ids.map((id) => {
                const item = evidenceById.get(id);
                return (
                  <tr key={id}>
                    <td className="mono" style={{ width: 90 }}>
                      {id}
                    </td>
                    <td className="mono faint" style={{ width: 120 }}>
                      {item?.source_type ?? '—'}
                    </td>
                    <td className="mono faint" style={{ width: 70 }}>
                      {item ? new Date(item.timestamp).toLocaleTimeString() : '—'}
                    </td>
                    <td>{item?.summary ?? 'event not retained in this incident'}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
