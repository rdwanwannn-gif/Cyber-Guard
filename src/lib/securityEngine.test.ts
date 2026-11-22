import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildWeeklyReport,
  calculateClusterScale,
  detectThreatFromTraffic,
  formatSiemEvent,
  isSafeExternalWebhookUrl,
  reportToCsv,
} from './securityEngine';
import type { ClusterConfig, ThreatAlert } from './types';

test('detectThreatFromTraffic identifies volumetric DDoS, SQLi, and normal traffic', () => {
  const ddos = detectThreatFromTraffic({
    sourceIp: '185.220.101.4',
    sourceGeo: 'Frankfurt, DE',
    destinationAsset: 'edge-lb-01',
    destinationPort: 443,
    protocol: 'QUIC',
    packetsPerSec: 250_000,
    bytesTransferred: 12_000_000,
  });
  assert.equal(ddos.detected, true);
  assert.equal(ddos.category, 'ddos_volumetric');
  assert.equal(ddos.severity, 'critical');

  const sqli = detectThreatFromTraffic({
    sourceIp: '45.155.205.9',
    sourceGeo: 'Amsterdam, NL',
    destinationAsset: 'api-gateway-prod',
    destinationPort: 443,
    protocol: 'HTTPS',
    packetsPerSec: 40,
    bytesTransferred: 2400,
    payloadSignature: "GET /v1/users?id=1' UNION SELECT password FROM admins--",
  });
  assert.equal(sqli.detected, true);
  assert.equal(sqli.category, 'sqli_probe');

  const normal = detectThreatFromTraffic({
    sourceIp: '10.24.0.15',
    sourceGeo: 'Jakarta, ID',
    destinationAsset: 'core-db-read',
    destinationPort: 5432,
    protocol: 'TLS 1.3',
    packetsPerSec: 120,
    bytesTransferred: 48_000,
  });
  assert.equal(normal.detected, false);
});

test('formatSiemEvent generates valid CEF, LEEF, and JSON strings', () => {
  const sampleAlert: ThreatAlert = {
    id: 'ALT-101',
    timestamp: '2026-11-22T09:15:00.000Z',
    title: 'Volumetric Flood Detected',
    category: 'ddos_volumetric',
    severity: 'critical',
    status: 'blocked',
    sourceIp: '185.220.101.4',
    sourceGeo: 'Frankfurt, DE',
    destinationAsset: 'edge-lb-01',
    destinationPort: 443,
    protocol: 'QUIC',
    packetsMatched: 250_000,
    bytesTransferred: 18_000_000,
    mitreTactic: 'TA0040',
    signatureId: 'SIG-NET-4001',
    summary: 'SYN/QUIC flood mitigated at edge',
    autoMitigated: true,
    acknowledged: false,
  };

  const cef = formatSiemEvent(sampleAlert, 'CEF');
  assert.ok(cef.startsWith('CEF:0|SentinelGrid|SOC-Engine|1.0|SIG-NET-4001|'));
  assert.ok(cef.includes('src=185.220.101.4'));

  const leef = formatSiemEvent(sampleAlert, 'LEEF');
  assert.ok(leef.startsWith('LEEF:2.0|SentinelGrid|SOC-Engine|1.0|SIG-NET-4001|'));

  const parsedJson = JSON.parse(formatSiemEvent(sampleAlert, 'JSON')) as { eventId: string };
  assert.equal(parsedJson.eventId, 'ALT-101');
});

test('calculateClusterScale scales worker nodes up under heavy throughput spikes', () => {
  const baseCluster: ClusterConfig = {
    autoScaleEnabled: true,
    minNodes: 4,
    maxNodes: 24,
    activeNodes: 4,
    targetLoadPercent: 70,
    maxCapacityGbps: 50,
    kafkaBufferPercent: 18,
    stressTestActive: false,
    nodes: [],
  };

  const scaled = calculateClusterScale(98.5, 920_000, baseCluster);
  assert.ok(scaled.activeNodes > 4);
  assert.ok(scaled.activeNodes <= 24);
  assert.equal(scaled.nodes.length, scaled.activeNodes);
  assert.ok(scaled.maxCapacityGbps > 50);
});

test('isSafeExternalWebhookUrl blocks SSRF targets and allows public HTTPS URLs', () => {
  assert.equal(isSafeExternalWebhookUrl('https://splunk.corp-siem.example/services/collector'), true);
  assert.equal(isSafeExternalWebhookUrl('http://127.0.0.1:8080/hook'), false);
  assert.equal(isSafeExternalWebhookUrl('http://169.254.169.254/latest/meta-data/'), false);
  assert.equal(isSafeExternalWebhookUrl('http://10.0.0.12/internal'), false);
  assert.equal(isSafeExternalWebhookUrl('javascript:alert(1)'), false);
});

test('buildWeeklyReport & reportToCsv produce non-empty valid CSV', () => {
  const report = buildWeeklyReport({
    id: 'RPT-W47',
    generatedAt: '2026-11-22T09:00:00.000Z',
    periodLabel: '2026-11-15 — 2026-11-22',
    trafficHistory: [],
    alerts: [],
    logs: [],
    complianceControls: [
      {
        framework: 'ISO 27001',
        status: 'compliant',
        coveragePercent: 98,
        lastAuditedAt: '2026-11-22T00:00:00Z',
        evidenceSummary: 'E2E encryption verified',
      },
    ],
  });
  const csv = reportToCsv(report);
  assert.ok(csv.includes('"Report ID","RPT-W47"'));
  assert.ok(csv.includes('"Compliance Coverage (%)","98%"'));
});
