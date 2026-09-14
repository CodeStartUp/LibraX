/// Entity glyphs for the attack graph.
///
/// A graph of identical boxes forces the analyst to read every label before they
/// can tell a domain controller from an attacker's VPS. The icon carries type and
/// platform at a glance, and the label is then only needed to identify *which*
/// one.
///
/// Every glyph draws inside a 16x16 box so the graph can place them on a grid
/// without measuring anything.

export type Platform =
  | 'windows'
  | 'linux'
  | 'network_appliance'
  | 'medical_device'
  | 'cloud';

interface Glyph {
  /// Paths drawn at 16x16.
  paths: string[];
  /// Shapes that read better as circles than as paths.
  circles?: { cx: number; cy: number; r: number }[];
  /// What the icon means, for the title element.
  title: string;
}

const WINDOWS: Glyph = {
  title: 'Windows host',
  paths: ['M2 3.4 L7.3 2.6 V7.6 H2 Z', 'M8.3 2.45 L14 1.6 V7.6 H8.3 Z', 'M2 8.6 H7.3 V13.4 L2 12.6 Z', 'M8.3 8.6 H14 V14.4 L8.3 13.55 Z'],
};

const LINUX: Glyph = {
  title: 'Linux host',
  // A terminal, which is more legible at this size than a penguin.
  paths: ['M1.5 2.5 h13 v11 h-13 z', 'M3.8 6.2 L5.8 8 L3.8 9.8', 'M7.2 10.2 h4'],
};

const APPLIANCE: Glyph = {
  title: 'Network appliance',
  // Brick wall: the firewall convention every analyst already reads.
  paths: [
    'M1.5 3 h13 v10 h-13 z',
    'M1.5 6.3 h13',
    'M1.5 9.7 h13',
    'M5.4 3 v3.3',
    'M10.6 3 v3.3',
    'M8 6.3 v3.4',
    'M5.4 9.7 v3.3',
    'M10.6 9.7 v3.3',
  ],
};

const MEDICAL: Glyph = {
  title: 'Medical / imaging device',
  paths: ['M1.5 2.5 h13 v9 h-13 z', 'M6 14 h4', 'M8 11.5 v2.5', 'M8 4.6 v4.4', 'M5.8 6.8 h4.4'],
};

const CLOUD: Glyph = {
  title: 'Cloud workload',
  paths: ['M4.2 11.5 a3 3 0 0 1 0.3 -5.95 a3.6 3.6 0 0 1 6.85 -0.6 a2.9 2.9 0 0 1 0.75 6.55 z'],
};

const DATABASE: Glyph = {
  title: 'Database',
  paths: [
    'M2.5 4 c0 -1.2 2.5 -2 5.5 -2 s5.5 0.8 5.5 2 s-2.5 2 -5.5 2 s-5.5 -0.8 -5.5 -2 z',
    'M2.5 4 v8 c0 1.2 2.5 2 5.5 2 s5.5 -0.8 5.5 -2 v-8',
    'M2.5 8 c0 1.2 2.5 2 5.5 2 s5.5 -0.8 5.5 -2',
  ],
};

const SERVER: Glyph = {
  title: 'Server',
  paths: ['M2 2.5 h12 v4.2 h-12 z', 'M2 9.3 h12 v4.2 h-12 z', 'M4 4.6 h0.01', 'M4 11.4 h0.01'],
};

const USER: Glyph = {
  title: 'User account',
  paths: ['M2.6 14 c0 -3 2.4 -4.7 5.4 -4.7 s5.4 1.7 5.4 4.7'],
  circles: [{ cx: 8, cy: 5.1, r: 3.1 }],
};

const KEY: Glyph = {
  title: 'Privileged account',
  paths: ['M9.4 6.6 L14 2', 'M11.4 4.6 L12.9 6.1', 'M12.6 3.4 L14.1 4.9'],
  circles: [{ cx: 6.2, cy: 9.8, r: 4.1 }],
};

const GLOBE: Glyph = {
  title: 'External infrastructure',
  paths: ['M1.6 8 h12.8', 'M8 1.6 a10 10 0 0 0 0 12.8', 'M8 1.6 a10 10 0 0 1 0 12.8'],
  circles: [{ cx: 8, cy: 8, r: 6.4 }],
};

const PROCESS: Glyph = {
  title: 'Process',
  paths: ['M5 2.2 h6 v3 h-6 z', 'M8 5.2 v2.4', 'M3 7.6 h10 v2.6 h-10 z', 'M5.5 10.2 v3.4', 'M10.5 10.2 v3.4'],
};

const FILE: Glyph = {
  title: 'File',
  paths: ['M3.4 1.8 h6 l3.2 3.2 v9.2 h-9.2 z', 'M9.4 1.8 v3.2 h3.2', 'M5.6 8.6 h4.8', 'M5.6 11 h4.8'],
};

const DOMAIN: Glyph = {
  title: 'Domain',
  paths: ['M2 6.2 h12', 'M2 6.2 v6.6 h12 v-6.6', 'M8 3 v3.2', 'M4.8 9.4 h6.4'],
  circles: [{ cx: 8, cy: 2.6, r: 1.6 }],
};

const UNKNOWN: Glyph = {
  title: 'Unclassified entity',
  paths: ['M6 5.8 a2.1 2.1 0 1 1 2.2 2.4 v1.4', 'M8.2 12.4 h0.01'],
  circles: [{ cx: 8, cy: 8, r: 6.4 }],
};

const BY_PLATFORM: Record<Platform, Glyph> = {
  windows: WINDOWS,
  linux: LINUX,
  network_appliance: APPLIANCE,
  medical_device: MEDICAL,
  cloud: CLOUD,
};

/// Picks the glyph for an entity.
///
/// Platform wins for anything we own, because "which fleet is this on" is the
/// first thing an analyst needs before deciding what a containment action even
/// means. Entity kind is the fallback for things with no platform: accounts,
/// processes, addresses.
export function glyphFor(kind: string, platform?: string | null, external?: boolean): Glyph {
  if (external) return GLOBE;

  if (platform && platform in BY_PLATFORM) {
    // A database on Linux still reads better as a database.
    if (kind === 'database') return DATABASE;
    return BY_PLATFORM[platform as Platform];
  }

  switch (kind) {
    case 'user':
      return USER;
    case 'account':
      return KEY;
    case 'host':
      return WINDOWS;
    case 'server':
      return SERVER;
    case 'database':
      return DATABASE;
    case 'device':
      return MEDICAL;
    case 'cloud_resource':
      return CLOUD;
    case 'process':
    case 'application':
      return PROCESS;
    case 'file':
      return FILE;
    case 'domain':
      return DOMAIN;
    case 'ip':
      return GLOBE;
    default:
      return UNKNOWN;
  }
}

/// Renders a glyph as SVG children, positioned by the caller's transform.
export function Glyph(props: { kind: string; platform?: string | null; external?: boolean }) {
  const glyph = glyphFor(props.kind, props.platform, props.external);

  return (
    <g className="glyph">
      <title>{glyph.title}</title>
      {glyph.circles?.map((c, i) => (
        <circle key={`c${i}`} cx={c.cx} cy={c.cy} r={c.r} />
      ))}
      {glyph.paths.map((d, i) => (
        <path key={`p${i}`} d={d} />
      ))}
    </g>
  );
}

/// Standalone icon for use outside the graph, in tables and headers.
export function EntityIcon(props: {
  kind: string;
  platform?: string | null;
  external?: boolean;
  size?: number;
}) {
  const size = props.size ?? 14;

  return (
    <svg
      className="entity-icon"
      width={size}
      height={size}
      viewBox="0 0 16 16"
      aria-hidden="true"
    >
      <Glyph kind={props.kind} platform={props.platform} external={props.external} />
    </svg>
  );
}
