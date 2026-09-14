import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import type { AttackGraph as Graph, Evidence, GraphEdge, GraphNode } from '../types';
import { Empty } from './common';
import { Glyph } from './icons';

const NODE_W = 168;
const NODE_H = 46;
const COL_GAP = 232;
const ROW_GAP = 74;
const PAD = 30;

const MIN_ZOOM = 0.35;
const MAX_ZOOM = 2.6;
const PAN_STEP = 90;

interface Point {
  x: number;
  y: number;
}

interface View extends Point {
  /// Zoom factor.
  k: number;
}

/// Left-to-right layered layout, used as the starting arrangement.
///
/// Layer is the longest path to a node, which puts causes left of effects and
/// makes the attack read in the order it happened. Iteration is bounded so a
/// cycle in the evidence cannot hang the render.
function layout(graph: Graph): Map<string, Point> {
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

  const positions = new Map<string, Point>();

  for (const [l, nodes] of [...byLayer.entries()].sort((a, b) => a[0] - b[0])) {
    nodes.sort(
      (a, b) => a.first_seen.localeCompare(b.first_seen) || a.label.localeCompare(b.label),
    );
    // Columns are centred on each other so a wide layer does not push a
    // single-node layer to the top edge.
    const offset = (nodes.length - 1) * ROW_GAP * -0.5;
    nodes.forEach((node, row) => {
      positions.set(node.id, { x: PAD + l * COL_GAP, y: offset + row * ROW_GAP });
    });
  }

  return positions;
}

function bounds(positions: Map<string, Point>) {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;

  for (const p of positions.values()) {
    minX = Math.min(minX, p.x);
    minY = Math.min(minY, p.y);
    maxX = Math.max(maxX, p.x + NODE_W);
    maxY = Math.max(maxY, p.y + NODE_H);
  }

  if (!Number.isFinite(minX)) return { minX: 0, minY: 0, maxX: NODE_W, maxY: NODE_H };
  return { minX, minY, maxX, maxY };
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}\u2026` : value;
}

export function AttackGraphView(props: { graph: Graph; evidence: Evidence[] }) {
  const { graph, evidence } = props;

  const [positions, setPositions] = useState<Map<string, Point>>(() => layout(graph));
  const [view, setView] = useState<View>({ x: 0, y: 0, k: 1 });
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const [dragging, setDragging] = useState<string | null>(null);

  const svgRef = useRef<SVGSVGElement | null>(null);
  /// Where the pointer grabbed, in graph coordinates, so a node does not jump to
  /// centre itself under the cursor on the first pixel of movement.
  const grab = useRef<Point>({ x: 0, y: 0 });
  const panStart = useRef<{ pointer: Point; view: Point } | null>(null);

  // Re-layout when the incident's graph actually changes shape. Positions the
  // analyst has dragged are deliberately kept while only counts or timestamps
  // update, which happens on every poll during a live attack.
  const shape = graph.nodes
    .map((n) => n.id)
    .sort()
    .join('|');

  useEffect(() => {
    setPositions(layout(graph));
    setView({ x: 0, y: 0, k: 1 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shape]);

  const byId = useMemo(() => new Map(graph.nodes.map((n) => [n.id, n])), [graph.nodes]);
  const evidenceById = useMemo(() => new Map(evidence.map((e) => [e.event_id, e])), [evidence]);

  /// Nodes one hop from the selection, so selecting something dims what it is not
  /// connected to instead of hiding the relationships that matter.
  const neighbours = useMemo(() => {
    if (!selectedNode) return null;
    const set = new Set<string>([selectedNode]);
    for (const edge of graph.edges) {
      if (edge.from === selectedNode) set.add(edge.to);
      if (edge.to === selectedNode) set.add(edge.from);
    }
    return set;
  }, [selectedNode, graph.edges]);

  /// Pointer position in graph coordinates.
  const toGraph = useCallback(
    (event: { clientX: number; clientY: number }): Point => {
      const rect = svgRef.current?.getBoundingClientRect();
      if (!rect) return { x: 0, y: 0 };
      return {
        x: (event.clientX - rect.left - view.x) / view.k,
        y: (event.clientY - rect.top - view.y) / view.k,
      };
    },
    [view],
  );

  const zoomBy = (factor: number, centre?: Point) => {
    setView((current) => {
      const k = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, current.k * factor));
      if (k === current.k) return current;

      const rect = svgRef.current?.getBoundingClientRect();
      // Zoom about the cursor when there is one, and the viewport centre otherwise,
      // so the thing being looked at stays put.
      const px = centre?.x ?? (rect ? rect.width / 2 : 0);
      const py = centre?.y ?? (rect ? rect.height / 2 : 0);
      const ratio = k / current.k;

      return { k, x: px - (px - current.x) * ratio, y: py - (py - current.y) * ratio };
    });
  };

  const fit = () => {
    const rect = svgRef.current?.getBoundingClientRect();
    if (!rect) return;

    const b = bounds(positions);
    const w = b.maxX - b.minX;
    const h = b.maxY - b.minY;
    if (w <= 0 || h <= 0) return;

    const k = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.min((rect.width - 40) / w, (rect.height - 40) / h)));
    setView({
      k,
      x: (rect.width - w * k) / 2 - b.minX * k,
      y: (rect.height - h * k) / 2 - b.minY * k,
    });
  };

  const reset = () => {
    setPositions(layout(graph));
    setView({ x: 0, y: 0, k: 1 });
  };

  const pan = (dx: number, dy: number) =>
    setView((c) => ({ ...c, x: c.x + dx, y: c.y + dy }));

  const onNodePointerDown = (event: React.PointerEvent, node: GraphNode) => {
    event.stopPropagation();
    (event.target as Element).setPointerCapture?.(event.pointerId);

    const p = toGraph(event);
    const at = positions.get(node.id) ?? { x: 0, y: 0 };
    grab.current = { x: p.x - at.x, y: p.y - at.y };

    setDragging(node.id);
    setSelectedNode(node.id);
    setSelectedEdge(null);
  };

  const onPointerMove = (event: React.PointerEvent) => {
    if (dragging) {
      const p = toGraph(event);
      setPositions((current) => {
        const next = new Map(current);
        next.set(dragging, { x: p.x - grab.current.x, y: p.y - grab.current.y });
        return next;
      });
      return;
    }

    if (panStart.current) {
      const { pointer, view: origin } = panStart.current;
      setView((c) => ({
        ...c,
        x: origin.x + (event.clientX - pointer.x),
        y: origin.y + (event.clientY - pointer.y),
      }));
    }
  };

  const endGesture = () => {
    setDragging(null);
    panStart.current = null;
  };

  const onBackgroundPointerDown = (event: React.PointerEvent) => {
    panStart.current = {
      pointer: { x: event.clientX, y: event.clientY },
      view: { x: view.x, y: view.y },
    };
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  // Registered by hand because React's wheel listener is passive: zooming has to
  // suppress the page scroll, and a passive listener cannot.
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;

    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      const rect = svg.getBoundingClientRect();
      zoomBy(event.deltaY < 0 ? 1.12 : 1 / 1.12, {
        x: event.clientX - rect.left,
        y: event.clientY - rect.top,
      });
    };

    svg.addEventListener('wheel', onWheel, { passive: false });
    return () => svg.removeEventListener('wheel', onWheel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (graph.nodes.length === 0) {
    return <Empty what="No graph for this incident" />;
  }

  const node = selectedNode ? byId.get(selectedNode) : undefined;
  const edge = selectedEdge ? graph.edges.find((e) => e.id === selectedEdge) : undefined;

  return (
    <div>
      <div className="graph-toolbar">
        <div className="graph-btn-group">
          <button type="button" onClick={() => zoomBy(1.25)} title="Zoom in">
            +
          </button>
          <button type="button" onClick={() => zoomBy(1 / 1.25)} title="Zoom out">
            &minus;
          </button>
          <span className="zoom-readout">{Math.round(view.k * 100)}%</span>
        </div>

        {/* Arrows move the viewport, so pressing up reveals what is above: the
            content itself travels the other way. */}
        <div className="graph-btn-group">
          <button type="button" onClick={() => pan(0, PAN_STEP)} title="Pan up">
            &uarr;
          </button>
          <button type="button" onClick={() => pan(0, -PAN_STEP)} title="Pan down">
            &darr;
          </button>
          <button type="button" onClick={() => pan(PAN_STEP, 0)} title="Pan left">
            &larr;
          </button>
          <button type="button" onClick={() => pan(-PAN_STEP, 0)} title="Pan right">
            &rarr;
          </button>
        </div>

        <div className="graph-btn-group">
          <button type="button" onClick={fit} title="Fit the whole graph in view">
            FIT
          </button>
          <button type="button" onClick={reset} title="Undo dragging and restore the layout">
            RESET
          </button>
        </div>

        <span className="faint graph-hint">
          drag any node to rearrange &middot; drag the background to pan &middot; scroll to zoom
        </span>
      </div>

      <div className={`graph-canvas${dragging ? ' dragging' : ''}`}>
        <svg
          ref={svgRef}
          width="100%"
          height="480"
          onPointerDown={onBackgroundPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endGesture}
          onPointerLeave={endGesture}
        >
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
              <path d="M 0 1 L 7 4 L 0 7 z" fill="#4a5361" />
            </marker>
            <pattern id="grid" width="26" height="26" patternUnits="userSpaceOnUse">
              <path d="M 26 0 L 0 0 0 26" fill="none" stroke="#1b1f26" strokeWidth="1" />
            </pattern>
          </defs>

          <rect width="100%" height="100%" fill="url(#grid)" />

          <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
            {graph.edges.map((e) => {
              const from = positions.get(e.from);
              const to = positions.get(e.to);
              if (!from || !to) return null;

              const rightwards = to.x >= from.x;
              const x1 = rightwards ? from.x + NODE_W : from.x;
              const x2 = rightwards ? to.x : to.x + NODE_W;
              const y1 = from.y + NODE_H / 2;
              const y2 = to.y + NODE_H / 2;
              const mid = (x1 + x2) / 2;

              const isSelected = e.id === selectedEdge;
              const dim =
                neighbours !== null && !(neighbours.has(e.from) && neighbours.has(e.to));

              return (
                <g
                  key={e.id}
                  className={`edge${isSelected ? ' selected' : ''}${dim ? ' dim' : ''}`}
                >
                  {/* A wide invisible path, so the relationship is clickable
                      without demanding pixel accuracy on a 1px line. */}
                  <path
                    className="edge-hit"
                    d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                    onPointerDown={(event) => {
                      event.stopPropagation();
                      setSelectedEdge(e.id);
                      setSelectedNode(null);
                    }}
                  />
                  <path
                    className="graph-edge"
                    d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                    markerEnd="url(#arrow)"
                  />
                  <text className="graph-edge-label" x={mid} y={(y1 + y2) / 2 - 5}>
                    {e.label}
                  </text>
                </g>
              );
            })}

            {graph.nodes.map((n) => {
              const at = positions.get(n.id);
              if (!at) return null;

              const dim = neighbours !== null && !neighbours.has(n.id);
              const classes = [
                'graph-node',
                n.exposure,
                n.id === selectedNode ? 'selected' : '',
                n.id === hovered ? 'hovered' : '',
                dim ? 'dim' : '',
              ]
                .filter(Boolean)
                .join(' ');

              return (
                <g
                  key={n.id}
                  className={classes}
                  transform={`translate(${at.x},${at.y})`}
                  onPointerDown={(event) => onNodePointerDown(event, n)}
                  onPointerEnter={() => setHovered(n.id)}
                  onPointerLeave={() => setHovered(null)}
                >
                  <rect width={NODE_W} height={NODE_H} rx="3" />
                  <g transform="translate(11,15)">
                    <Glyph kind={n.kind} platform={n.platform} external={n.external} />
                  </g>
                  <text className="node-label" x="36" y="20">
                    {truncate(n.label, 18)}
                  </text>
                  <text className="node-meta" x="36" y="34">
                    {n.external ? 'EXTERNAL' : (n.platform_label ?? n.kind_label).toUpperCase()}
                    {n.criticality !== null ? ` \u00b7 C${n.criticality}` : ''}
                  </text>
                </g>
              );
            })}
          </g>
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
          {graph.nodes.length} entities &middot; {graph.edges.length} relationships &middot; click
          any node or relationship to inspect its evidence
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

function NodeInspector({ node }: { node: GraphNode }) {
  return (
    <div className="inspector">
      <h3>{node.label}</h3>
      <dl className="kv">
        <dt>Type</dt>
        <dd>{node.kind_label}</dd>
        <dt>Platform</dt>
        <dd>
          {node.platform_label ??
            (node.external ? 'external, not an inventory asset' : 'not recorded')}
        </dd>
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
  from?: GraphNode;
  to?: GraphNode;
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
                    <td className="mono" style={{ width: 110 }}>
                      {id}
                    </td>
                    <td className="mono faint" style={{ width: 120 }}>
                      {item?.source_type ?? '\u2014'}
                    </td>
                    <td className="mono faint" style={{ width: 70 }}>
                      {item ? new Date(item.timestamp).toLocaleTimeString() : '\u2014'}
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
