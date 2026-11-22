import type {
  ClusterConfig,
  ClusterNode,
  ComplianceControl,
  EncryptedLogEntry,
  ProtocolName,
  SeverityLevel,
  SiemFormat,
  ThreatAlert,
  ThreatCategory,
  TrafficSample,
  WeeklyReport,
} from './types';

export interface PacketObservation {
  sourceIp: string;
  sourceGeo: string;
  destinationAsset: string;
  destinationPort: number;
  protocol: ProtocolName;
  packetsPerSec: number;
  bytesTransferred: number;
  payloadSignature?: string;
}

export function detectThreatFromTraffic(obs: PacketObservation): {
  detected: boolean;
  category?: ThreatCategory;
  severity?: SeverityLevel;
  title?: string;
  mitreTactic?: string;
  signatureId?: string;
} {
  const sig = (obs.payloadSignature ?? '').toLowerCase();

  if (obs.packetsPerSec >= 180_000) {
    return {
      detected: true,
      category: 'ddos_volumetric',
      severity: 'critical',
      title: `Volumetric Flood Detected (${Math.round(obs.packetsPerSec / 1000)}k pps)`,
      mitreTactic: 'TA0040 · Impact (Network Denial of Service)',
      signatureId: 'SIG-NET-4001',
    };
  }

  if (sig.includes('union select') || sig.includes('or 1=1') || sig.includes('sqli')) {
    return {
      detected: true,
      category: 'sqli_probe',
      severity: 'high',
      title: `SQL Injection Payload on Port ${obs.destinationPort}`,
      mitreTactic: 'TA0001 · Initial Access (Exploit Public-Facing App)',
      signatureId: 'SIG-WAF-2104',
    };
  }

  if (obs.destinationPort === 22 && obs.packetsPerSec >= 1200) {
    return {
      detected: true,
      category: 'ssh_bruteforce',
      severity: 'high',
      title: 'High-Velocity SSH Credential Brute Force',
      mitreTactic: 'TA0006 · Credential Access (Brute Force)',
      signatureId: 'SIG-AUTH-1109',
    };
  }

  if (sig.includes('beacon') || (obs.protocol === 'DNS' && obs.bytesTransferred > 65_000)) {
    return {
      detected: true,
      category: 'c2_beacon',
      severity: 'critical',
      title: 'Suspected C2 Tunneling / Periodic Beacon',
      mitreTactic: 'TA0011 · Command and Control',
      signatureId: 'SIG-DNS-3302',
    };
  }

  if (obs.bytesTransferred >= 85_000_000) {
    return {
      detected: true,
      category: 'data_exfiltration',
      severity: 'critical',
      title: 'Anomalous Outbound Data Exfiltration Spike',
      mitreTactic: 'TA0010 · Exfiltration',
      signatureId: 'SIG-DLP-5018',
    };
  }

  if ((obs.destinationPort === 445 || obs.destinationPort === 3389) && obs.packetsPerSec >= 400) {
    return {
      detected: true,
      category: 'lateral_movement',
      severity: 'medium',
      title: `East-West Lateral Movement Probe (:${obs.destinationPort})`,
      mitreTactic: 'TA0008 · Lateral Movement',
      signatureId: 'SIG-INT-2840',
    };
  }

  return { detected: false };
}

const SEVERITY_MAP: Record<SeverityLevel, number> = {
  critical: 10,
  high: 8,
  medium: 5,
  low: 2,
};

export function severityRank(level: SeverityLevel): number {
  return SEVERITY_MAP[level];
}

export function formatSiemEvent(alert: ThreatAlert, format: SiemFormat): string {
  if (format === 'CEF') {
    const sevNum = SEVERITY_MAP[alert.severity];
    const cleanTitle = alert.title.replace(/[|=\\]/g, ' ');
    return `CEF:0|SentinelGrid|SOC-Engine|1.0|${alert.signatureId}|${cleanTitle}|${sevNum}|src=${alert.sourceIp} dst=${alert.destinationAsset} dpt=${alert.destinationPort} proto=${alert.protocol} act=${alert.status} cs1Label=MitreTactic cs1=${alert.mitreTactic}`;
  }

  if (format === 'LEEF') {
    return `LEEF:2.0|SentinelGrid|SOC-Engine|1.0|${alert.signatureId}|devTime=${alert.timestamp}\tsev=${SEVERITY_MAP[alert.severity]}\tsrc=${alert.sourceIp}\tdst=${alert.destinationAsset}\tdstPort=${alert.destinationPort}\tproto=${alert.protocol}\taction=${alert.status}`;
  }

  return JSON.stringify(
    {
      schema: 'sentinelgrid.siem.v1',
      eventId: alert.id,
      timestamp: alert.timestamp,
      severity: alert.severity,
      category: alert.category,
      signatureId: alert.signatureId,
      source: { ip: alert.sourceIp, geo: alert.sourceGeo },
      destination: { asset: alert.destinationAsset, port: alert.destinationPort },
      protocol: alert.protocol,
      status: alert.status,
      mitreTactic: alert.mitreTactic,
      packetsMatched: alert.packetsMatched,
      bytesTransferred: alert.bytesTransferred,
    },
    null,
    2,
  );
}

export function calculateClusterScale(
  currentThroughputGbps: number,
  eventsPerSec: number,
  current: ClusterConfig,
): ClusterConfig {
  const perNodeCapacityGbps = 12.5;
  const requiredNodes = Math.ceil(
    (currentThroughputGbps / perNodeCapacityGbps) * (100 / Math.max(30, current.targetLoadPercent)),
  );

  const nextActiveNodes = current.autoScaleEnabled
    ? Math.max(current.minNodes, Math.min(current.maxNodes, requiredNodes))
    : current.activeNodes;

  const totalCapacity = Number((nextActiveNodes * perNodeCapacityGbps).toFixed(1));
  const avgCpu = Math.min(96, Math.max(14, Math.round((currentThroughputGbps / totalCapacity) * 88)));
  const avgMem = Math.min(92, Math.max(22, Math.round(avgCpu * 0.82 + 10)));
  const bufferPct = Math.min(94, Math.max(4, Math.round((eventsPerSec / (nextActiveNodes * 180_000)) * 72)));

  const regions = ['ap-southeast-1', 'ap-southeast-3', 'eu-central-1', 'us-east-1'];
  const nodes: ClusterNode[] = Array.from({ length: nextActiveNodes }, (_, idx) => {
    const jitter = ((idx * 7) % 9) - 4;
    return {
      id: `sg-ingest-${String(idx + 1).padStart(2, '0')}`,
      region: regions[idx % regions.length],
      status: idx >= current.activeNodes ? 'scaling' : 'active',
      cpuPercent: Math.min(98, Math.max(10, avgCpu + jitter)),
      memoryPercent: Math.min(95, Math.max(18, avgMem + jitter)),
      ingestGbps: Number((currentThroughputGbps / nextActiveNodes).toFixed(2)),
      eventsPerSec: Math.round(eventsPerSec / nextActiveNodes),
    };
  });

  return {
    ...current,
    activeNodes: nextActiveNodes,
    maxCapacityGbps: totalCapacity,
    kafkaBufferPercent: bufferPct,
    nodes,
  };
}

export function buildWeeklyReport(params: {
  id: string;
  generatedAt: string;
  periodLabel: string;
  trafficHistory: TrafficSample[];
  alerts: ThreatAlert[];
  logs: EncryptedLogEntry[];
  complianceControls: ComplianceControl[];
}): WeeklyReport {
  const { id, generatedAt, periodLabel, trafficHistory, alerts, logs, complianceControls } = params;
  const totalPps = trafficHistory.reduce((acc, s) => acc + s.packetsPerSec, 0);
  const scaledTotalPackets = Math.max(12_400_000, totalPps * 420);
  const formattedPackets =
    scaledTotalPackets >= 1_000_000_000
      ? `${(scaledTotalPackets / 1_000_000_000).toFixed(2)}B`
      : `${(scaledTotalPackets / 1_000_000).toFixed(1)}M`;

  const criticalMitigated = alerts.filter(
    (a) => (a.severity === 'critical' || a.severity === 'high') && (a.status === 'blocked' || a.status === 'mitigated'),
  ).length;

  const vectorCounts = new Map<ThreatCategory, number>();
  for (const alert of alerts) {
    vectorCounts.set(alert.category, (vectorCounts.get(alert.category) ?? 0) + 1);
  }
  const topVectors = Array.from(vectorCounts.entries())
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 4);

  const avgCompliance =
    complianceControls.length > 0
      ? Math.round(
          complianceControls.reduce((sum, c) => sum + c.coveragePercent, 0) / complianceControls.length,
        )
      : 100;

  const e2eCount = logs.filter((l) => l.envelope.algorithm === 'AES-256-GCM').length;
  const e2ePct = logs.length > 0 ? Math.round((e2eCount / logs.length) * 100) : 100;

  return {
    id,
    generatedAt,
    periodLabel,
    totalPacketsAnalyzed: formattedPackets,
    totalThreatsDetected: alerts.length,
    criticalMitigated,
    meanTimeToRespondSec: alerts.some((a) => a.autoMitigated) ? 1.8 : 4.2,
    e2eLogEncryptionPercent: e2ePct,
    siemSyncSuccessPercent: 99.94,
    topVectors,
    complianceScorePercent: avgCompliance,
    summaryNote: `Automated digest covering ${alerts.length} detected incidents, ${e2eCount} AES-256-GCM sealed logs, and ${avgCompliance}% framework compliance.`,
  };
}

export function isSafeExternalWebhookUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '0.0.0.0' ||
      host === '::1' ||
      host.startsWith('169.254.') ||
      host.startsWith('10.') ||
      host.startsWith('192.168.')
    ) {
      return false;
    }
    if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(host)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function reportToCsv(report: WeeklyReport): string {
  const rows = [
    ['Field', 'Value'],
    ['Report ID', report.id],
    ['Generated At', report.generatedAt],
    ['Period', report.periodLabel],
    ['Total Packets Analyzed', report.totalPacketsAnalyzed],
    ['Total Threats Detected', String(report.totalThreatsDetected)],
    ['Critical/High Mitigated', String(report.criticalMitigated)],
    ['Mean Time To Respond (s)', String(report.meanTimeToRespondSec)],
    ['E2E Log Encryption (%)', `${report.e2eLogEncryptionPercent}%`],
    ['SIEM Sync Success (%)', `${report.siemSyncSuccessPercent}%`],
    ['Compliance Coverage (%)', `${report.complianceScorePercent}%`],
    ...report.topVectors.map((v) => [`Vector: ${v.category}`, String(v.count)]),
  ];
  return rows
    .map((cols) => cols.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(','))
    .join('\n');
}
