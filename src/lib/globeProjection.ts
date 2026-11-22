export interface GeoCoord {
  lat: number;
  lon: number;
  label: string;
}

export interface ProjectedPoint {
  x: number;
  y: number;
  z: number;
  visible: boolean;
}

export const SOC_HOME_HUB: GeoCoord = {
  lat: -6.2,
  lon: 106.8,
  label: 'Jakarta SOC Hub',
};

const KNOWN_GEO_MAP: Array<{ match: string; coord: GeoCoord }> = [
  { match: 'frankfurt', coord: { lat: 50.11, lon: 8.68, label: 'Frankfurt, DE' } },
  { match: 'amsterdam', coord: { lat: 52.37, lon: 4.9, label: 'Amsterdam, NL' } },
  { match: 'singapore', coord: { lat: 1.35, lon: 103.82, label: 'Singapore, SG' } },
  { match: 'bucharest', coord: { lat: 44.43, lon: 26.1, label: 'Bucharest, RO' } },
  { match: 'warsaw', coord: { lat: 52.23, lon: 21.01, label: 'Warsaw, PL' } },
  { match: 'sofia', coord: { lat: 42.7, lon: 23.32, label: 'Sofia, BG' } },
  { match: 'hong kong', coord: { lat: 22.32, lon: 114.17, label: 'Hong Kong, HK' } },
  { match: 'tokyo', coord: { lat: 35.68, lon: 139.69, label: 'Tokyo, JP' } },
  { match: 'london', coord: { lat: 51.51, lon: -0.13, label: 'London, UK' } },
  { match: 'new york', coord: { lat: 40.71, lon: -74.01, label: 'New York, US' } },
  { match: 'sydney', coord: { lat: -33.86, lon: 151.21, label: 'Sydney, AU' } },
  { match: 'sao paulo', coord: { lat: -23.55, lon: -46.63, label: 'Sao Paulo, BR' } },
  { match: 'jakarta', coord: { lat: -6.2, lon: 106.82, label: 'Jakarta, ID' } },
  { match: 'internal', coord: { lat: -6.9, lon: 107.6, label: 'Internal VPC' } },
];

export function resolveGeoCoordinates(sourceGeo: string): GeoCoord {
  const normalized = sourceGeo.toLowerCase();
  for (const item of KNOWN_GEO_MAP) {
    if (normalized.includes(item.match)) {
      return item.coord;
    }
  }
  // Deterministic fallback hash across global coordinates
  let hash = 0;
  for (let i = 0; i < normalized.length; i += 1) {
    hash = (hash * 31 + normalized.charCodeAt(i)) | 0;
  }
  const lat = ((Math.abs(hash) % 110) - 55);
  const lon = ((Math.abs(hash >> 4) % 320) - 160);
  return { lat, lon, label: sourceGeo || 'Unknown Origin' };
}

export function projectSpherePoint(
  latDeg: number,
  lonDeg: number,
  rotationRad: number,
  tiltRad: number,
  radius: number,
  cx: number,
  cy: number,
): ProjectedPoint {
  const lat = (latDeg * Math.PI) / 180;
  const lon = (lonDeg * Math.PI) / 180 + rotationRad;

  const cosLat = Math.cos(lat);
  const x0 = cosLat * Math.sin(lon);
  const y0 = Math.sin(lat);
  const z0 = cosLat * Math.cos(lon);

  // Apply axial X-tilt so northern/southern hemispheres read clearly
  const cosTilt = Math.cos(tiltRad);
  const sinTilt = Math.sin(tiltRad);
  const y1 = y0 * cosTilt - z0 * sinTilt;
  const z1 = y0 * sinTilt + z0 * cosTilt;

  return {
    x: cx + x0 * radius,
    y: cy - y1 * radius,
    z: z1,
    visible: z1 >= -0.05,
  };
}

export function interpolateGreatCircleArc(
  from: { lat: number; lon: number },
  to: { lat: number; lon: number },
  steps = 24,
): Array<{ lat: number; lon: number; altitude: number }> {
  const toVec = (latDeg: number, lonDeg: number): [number, number, number] => {
    const la = (latDeg * Math.PI) / 180;
    const lo = (lonDeg * Math.PI) / 180;
    return [Math.cos(la) * Math.cos(lo), Math.cos(la) * Math.sin(lo), Math.sin(la)];
  };

  const a = toVec(from.lat, from.lon);
  const b = toVec(to.lat, to.lon);
  const dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
  const omega = Math.acos(dot);

  const points: Array<{ lat: number; lon: number; altitude: number }> = [];
  for (let i = 0; i <= steps; i += 1) {
    const t = i / steps;
    let vx: number;
    let vy: number;
    let vz: number;

    if (omega < 0.001) {
      vx = a[0] * (1 - t) + b[0] * t;
      vy = a[1] * (1 - t) + b[1] * t;
      vz = a[2] * (1 - t) + b[2] * t;
    } else {
      const sinOmega = Math.sin(omega);
      const wa = Math.sin((1 - t) * omega) / sinOmega;
      const wb = Math.sin(t * omega) / sinOmega;
      vx = a[0] * wa + b[0] * wb;
      vy = a[1] * wa + b[1] * wb;
      vz = a[2] * wa + b[2] * wb;
    }

    const norm = Math.hypot(vx, vy, vz) || 1;
    const nx = vx / norm;
    const ny = vy / norm;
    const nz = vz / norm;
    const lat = (Math.asin(Math.max(-1, Math.min(1, nz))) * 180) / Math.PI;
    const lon = (Math.atan2(ny, nx) * 180) / Math.PI;
    const altitude = 1 + Math.sin(Math.PI * t) * Math.min(0.26, omega * 0.14);
    points.push({ lat, lon, altitude });
  }
  return points;
}

// Simplified Earth continental coastlines ([lon, lat] polygons) for recognizable spinning globe rendering
export const WORLD_CONTINENTS: Array<Array<[number, number]>> = [
  // North America
  [
    [-168, 65], [-162, 55], [-150, 60], [-136, 58], [-125, 49], [-124, 40],
    [-117, 32], [-105, 20], [-92, 15], [-83, 10], [-78, 9], [-84, 15],
    [-87, 21], [-97, 26], [-90, 29], [-81, 25], [-76, 35], [-70, 42],
    [-60, 46], [-53, 47], [-62, 58], [-78, 62], [-95, 68], [-125, 70],
    [-156, 71], [-168, 65],
  ],
  // Greenland
  [
    [-52, 60], [-42, 60], [-22, 70], [-18, 81], [-45, 83], [-68, 76], [-54, 68], [-52, 60],
  ],
  // South America
  [
    [-79, 9], [-71, 12], [-61, 10], [-50, 1], [-35, -6], [-38, -14],
    [-40, -22], [-48, -28], [-54, -34], [-62, -40], [-67, -50], [-69, -55],
    [-75, -50], [-73, -38], [-71, -20], [-81, -5], [-79, 9],
  ],
  // Europe
  [
    [-9, 37], [-9, 43], [-2, 44], [-5, 48], [2, 51], [8, 54], [9, 58],
    [5, 61], [15, 69], [28, 71], [40, 67], [58, 68], [58, 52], [44, 45],
    [32, 46], [28, 41], [22, 37], [16, 38], [12, 44], [6, 43], [-2, 36], [-9, 37],
  ],
  // UK & Ireland
  [
    [-6, 50], [1, 51], [0, 56], [-5, 58], [-8, 54], [-6, 50],
  ],
  // Africa
  [
    [-17, 15], [-12, 28], [-5, 36], [10, 37], [12, 33], [25, 32], [32, 31],
    [39, 20], [43, 12], [51, 11], [45, 2], [40, -10], [35, -24], [28, -33],
    [18, -34], [14, -22], [12, -6], [9, 4], [2, 6], [-8, 5], [-16, 11], [-17, 15],
  ],
  // Madagascar
  [
    [44, -25], [47, -25], [50, -15], [49, -12], [44, -18], [44, -25],
  ],
  // Asia Mainland
  [
    [28, 41], [42, 42], [52, 40], [58, 52], [65, 68], [95, 74], [135, 72],
    [172, 66], [162, 58], [142, 53], [136, 44], [129, 35], [122, 38],
    [120, 30], [116, 22], [108, 20], [109, 12], [103, 2], [100, 8],
    [98, 16], [90, 22], [80, 10], [77, 8], [72, 20], [66, 25], [57, 26],
    [50, 29], [44, 13], [35, 29], [28, 37], [28, 41],
  ],
  // Japan
  [
    [130, 32], [136, 34], [141, 38], [145, 44], [140, 42], [135, 36], [130, 32],
  ],
  // Sumatra & Java (Indonesia West)
  [
    [95, 5], [99, 3], [104, -2], [106, -6], [114, -8], [113, -7], [105, -5], [99, 0], [95, 5],
  ],
  // Kalimantan / Borneo
  [
    [109, 1], [115, 5], [118, 5], [117, -3], [111, -3], [109, 1],
  ],
  // Sulawesi & Papua
  [
    [119, -5], [122, 1], [125, 1], [123, -4], [119, -5],
  ],
  [
    [132, -2], [141, -3], [148, -9], [142, -9], [135, -5], [132, -2],
  ],
  // Australia
  [
    [114, -22], [122, -17], [131, -12], [137, -15], [142, -11], [149, -20],
    [153, -28], [150, -37], [140, -38], [131, -32], [122, -34], [115, -34], [114, -22],
  ],
];
