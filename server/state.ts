import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  computeLogIntegrityHash,
  encryptTrafficPayload,
  generateEncryptionKeyHex,
  generateTotpSecret,
  hashApiKey,
  hashPasswordScrypt,
} from '../src/lib/cryptoSecurity';
import {
  isValidUserRole,
  roleDisplayName,
} from '../src/lib/userControl';
import {
  buildWeeklyReport,
  calculateClusterScale,
  detectThreatFromTraffic,
  severityRank,
} from '../src/lib/securityEngine';
import type {
  AccountControlAuditEntry,
  ActiveSessionInfo,
  AttackSimulationState,
  AutomationRule,
  ClusterConfig,
  ComplaintCategory,
  ComplaintStatus,
  ComplianceControl,
  DecryptedLogPayload,
  EncryptedLogEntry,
  ManagedUserAccount,
  ProtocolName,
  SecurityNotification,
  SeverityLevel,
  SiemApiKey,
  SiemConnector,
  SocSnapshot,
  ThirdPartyIntegration,
  ThreatAlert,
  ThreatCategory,
  TrafficSample,
  UserAccountStatus,
  UserComplaintReport,
  UserRole,
  WeeklyReport,
  WeeklyReportSchedule,
} from '../src/lib/types';

export interface AdminAccount {
  email: string;
  passwordHash: string;
  totpSecret: string;
  mfaConfirmed: boolean;
  backupCodeHashes: string[];
}

export interface ServerUserAccount {
  id: string;
  fullName: string;
  email: string;
  department: string;
  role: UserRole;
  status: UserAccountStatus;
  passwordHash: string;
  totpSecret: string;
  mfaConfirmed: boolean;
  backupCodeHashes: string[];
  registeredAt: string;
  registeredIp: string;
  deviceInfo: string;
  lastLoginAt: string | null;
  issueFlagged: boolean;
  issueNote: string;
  approvedBy: string | null;
  updatedAt: string;
}

export interface ServerSession {
  token: string;
  id: string;
  userId: string;
  email: string;
  role: string;
  roleKey: UserRole;
  mfaVerified: boolean;
  createdAt: string;
  lastSeenAt: string;
  userAgent: string;
  ipAddress: string;
}

export interface PendingChallenge {
  challengeToken: string;
  userId: string;
  email: string;
  accountType: 'admin' | 'user';
  expiresAt: number;
  isInitialSetup: boolean;
}

interface PersistedAccountsPayload {
  admin: AdminAccount | null;
  users: ServerUserAccount[];
  userReports: UserComplaintReport[];
  accountAuditLogs: AccountControlAuditEntry[];
  requireAdminApproval: boolean;
  mfaPolicy: {
    requireMfaForDecryption: boolean;
    requireMfaForKeyRotation: boolean;
  };
}

const PROTOCOLS: ProtocolName[] = ['TLS 1.3', 'HTTPS', 'DNS', 'SSH', 'QUIC', 'gRPC'];

export class SecurityWorkspaceStore {
  public admin: AdminAccount | null = null;
  public readonly sessionSigningSecret: string;
  public activeKeyId = 'KEY-2026-01';
  public encryptionKeys: Map<string, string> = new Map();
  public sessions: Map<string, ServerSession> = new Map();
  public challenges: Map<string, PendingChallenge> = new Map();
  public users: ServerUserAccount[] = [];
  public userReports: UserComplaintReport[] = [];
  public accountAuditLogs: AccountControlAuditEntry[] = [];
  public requireAdminApproval = true;
  public simulation: AttackSimulationState = {
    running: false,
    scenario: 'mixed',
    wavesSent: 0,
    lastTriggeredAt: null,
  };

  private readonly dataDir = path.resolve(process.cwd(), '.sentinelgrid-data');
  private readonly accountsFile = path.resolve(this.dataDir, 'accounts.json');

  public trafficHistory: TrafficSample[] = [];
  public alerts: ThreatAlert[] = [];
  public encryptedLogs: EncryptedLogEntry[] = [];
  public siemConnectors: SiemConnector[] = [];
  public siemApiKeys: Array<SiemApiKey & { keyHash: string }> = [];
  public integrations: ThirdPartyIntegration[] = [];
  public automationRules: AutomationRule[] = [];
  public complianceControls: ComplianceControl[] = [];
  public weeklyReports: WeeklyReport[] = [];
  public reportSchedule: WeeklyReportSchedule;
  public cluster: ClusterConfig;
  public notifications: SecurityNotification[] = [];
  public mfaPolicy = {
    requireMfaForDecryption: true,
    requireMfaForKeyRotation: true,
  };

  private logSequence = 0;
  private alertCounter = 1040;
  private reportCounter = 47;
  private userCounter = 200;
  private complaintCounter = 100;

  constructor() {
    this.sessionSigningSecret =
      process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
    const primaryKeyHex = process.env.E2E_LOG_KEY || generateEncryptionKeyHex();
    this.encryptionKeys.set(this.activeKeyId, primaryKeyHex);

    this.loadAccountsFromDisk();

    if (process.env.ADMIN_PASSCODE && process.env.ADMIN_PASSCODE.trim().length >= 6) {
      if (!this.admin) {
        this.admin = {
          email: 'admin@sentinelgrid.io',
          passwordHash: hashPasswordScrypt(process.env.ADMIN_PASSCODE.trim()),
          totpSecret: generateTotpSecret(),
          mfaConfirmed: false,
          backupCodeHashes: [],
        };
      }
    }

    this.reportSchedule = {
      enabled: true,
      dayOfWeek: 'Monday',
      timeUtc: '07:00',
      recipients: ['secops@enterprise.local', 'ciso-audit@enterprise.local'],
      includeEncryptedAudit: true,
      frameworks: ['ISO 27001', 'SOC 2 Type II', 'PCI-DSS 4.0', 'GDPR'],
    };

    this.cluster = calculateClusterScale(28.4, 245_000, {
      autoScaleEnabled: true,
      minNodes: 4,
      maxNodes: 24,
      activeNodes: 4,
      targetLoadPercent: 72,
      maxCapacityGbps: 50,
      kafkaBufferPercent: 22,
      stressTestActive: false,
      nodes: [],
    });

    this.seedInitialTelemetry();
    this.syncPendingNotificationsFromRegisteredUsers();
  }

  private loadAccountsFromDisk() {
    try {
      if (!fs.existsSync(this.accountsFile)) return;
      const raw = fs.readFileSync(this.accountsFile, 'utf8');
      const parsed = JSON.parse(raw) as Partial<PersistedAccountsPayload>;
      if (parsed.admin) {
        this.admin = parsed.admin;
      }
      if (Array.isArray(parsed.users)) {
        this.users = parsed.users;
        this.userCounter = Math.max(200, this.users.length + 200);
      }
      if (Array.isArray(parsed.userReports)) {
        this.userReports = parsed.userReports;
        this.complaintCounter = Math.max(100, this.userReports.length + 100);
      }
      if (Array.isArray(parsed.accountAuditLogs)) {
        this.accountAuditLogs = parsed.accountAuditLogs;
      }
      if (typeof parsed.requireAdminApproval === 'boolean') {
        this.requireAdminApproval = parsed.requireAdminApproval;
      }
      if (parsed.mfaPolicy) {
        this.mfaPolicy = parsed.mfaPolicy;
      }
    } catch {
      // Fall back to empty state if persisted store cannot be parsed
    }
  }

  public persistAccountsToDisk() {
    try {
      fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
      const payload: PersistedAccountsPayload = {
        admin: this.admin,
        users: this.users,
        userReports: this.userReports.slice(0, 200),
        accountAuditLogs: this.accountAuditLogs.slice(0, 200),
        requireAdminApproval: this.requireAdminApproval,
        mfaPolicy: this.mfaPolicy,
      };
      const tmpFile = `${this.accountsFile}.tmp`;
      fs.writeFileSync(tmpFile, JSON.stringify(payload, null, 2), { mode: 0o600 });
      fs.renameSync(tmpFile, this.accountsFile);
    } catch {
      // Ignore write failures in read-only test harnesses
    }
  }

  private syncPendingNotificationsFromRegisteredUsers() {
    for (const user of this.users) {
      if (user.status === 'pending') {
        this.notifications.unshift({
          id: `NTF-REG-${user.id}`,
          timestamp: user.registeredAt,
          title: `Permintaan Akses Pengguna Baru: ${user.fullName}`,
          message: `${user.email} (${user.deviceInfo} · ${user.registeredIp}) menunggu persetujuan Admin`,
          severity: 'medium',
          read: false,
          targetRole: 'admin',
        });
      }
    }
    for (const report of this.userReports) {
      if (report.status === 'open') {
        this.notifications.unshift({
          id: `NTF-CMP-${report.id}`,
          timestamp: report.createdAt,
          title: `Keluhan Pengguna: ${report.subject}`,
          message: `${report.userFullName} (${report.userEmail}) · ${report.deviceInfo} (${report.ipAddress})`,
          severity: report.severity,
          read: false,
          reportId: report.id,
          targetRole: 'admin',
        });
      }
    }
  }

  private seedInitialTelemetry() {
    const now = Date.now();
    for (let i = 29; i >= 0; i -= 1) {
      const ts = new Date(now - i * 2000).toISOString();
      const baseIn = 22 + Math.sin(i * 0.4) * 5.2 + (i % 5) * 0.6;
      const baseOut = 14 + Math.cos(i * 0.35) * 3.1;
      const pps = Math.round((baseIn + baseOut) * 6800);
      this.trafficHistory.push({
        id: `pkt-${i}`,
        timestamp: ts,
        inboundGbps: Number(baseIn.toFixed(2)),
        outboundGbps: Number(baseOut.toFixed(2)),
        packetsPerSec: pps,
        blockedPacketsPerSec: Math.round(pps * 0.018),
        latencyMs: Number((1.4 + (i % 4) * 0.15).toFixed(2)),
        anomalyScore: i === 6 ? 78 : 12 + (i % 7) * 2,
        protocols: {
          'TLS 1.3': 42,
          HTTPS: 24,
          QUIC: 15,
          gRPC: 9,
          DNS: 7,
          SSH: 3,
        },
      });
    }

    const seedThreats: Array<Omit<ThreatAlert, 'id' | 'timestamp'>> = [
      {
        title: 'SQL Injection Payload on Port 443',
        category: 'sqli_probe',
        severity: 'high',
        status: 'blocked',
        sourceIp: '45.155.205.91',
        sourceGeo: 'Amsterdam, NL',
        destinationAsset: 'api-gateway-edge-02',
        destinationPort: 443,
        protocol: 'HTTPS',
        packetsMatched: 1480,
        bytesTransferred: 924_000,
        mitreTactic: 'TA0001 · Initial Access',
        signatureId: 'SIG-WAF-2104',
        summary: 'Automated UNION SELECT signature dropped at edge WAF before upstream routing.',
        autoMitigated: true,
        acknowledged: true,
      },
      {
        title: 'High-Velocity SSH Credential Brute Force',
        category: 'ssh_bruteforce',
        severity: 'high',
        status: 'active',
        sourceIp: '185.220.101.44',
        sourceGeo: 'Frankfurt, DE',
        destinationAsset: 'bastion-ap-southeast',
        destinationPort: 22,
        protocol: 'SSH',
        packetsMatched: 9420,
        bytesTransferred: 2_310_000,
        mitreTactic: 'TA0006 · Credential Access',
        signatureId: 'SIG-AUTH-1109',
        summary: 'Sustained 1,850 auth attempts/min targeting administrative SSH bastion.',
        autoMitigated: false,
        acknowledged: false,
      },
      {
        title: 'Suspected C2 Tunneling / Periodic Beacon',
        category: 'c2_beacon',
        severity: 'critical',
        status: 'investigating',
        sourceIp: '103.149.28.17',
        sourceGeo: 'Singapore, SG',
        destinationAsset: 'dns-resolver-int-03',
        destinationPort: 53,
        protocol: 'DNS',
        packetsMatched: 612,
        bytesTransferred: 184_500,
        mitreTactic: 'TA0011 · Command and Control',
        signatureId: 'SIG-DNS-3302',
        summary: 'High-entropy TXT record exfiltration cadence detected every 45 seconds.',
        autoMitigated: false,
        acknowledged: false,
      },
      {
        title: 'East-West Lateral Movement Probe (:445)',
        category: 'lateral_movement',
        severity: 'medium',
        status: 'mitigated',
        sourceIp: '10.42.18.77',
        sourceGeo: 'Internal VPC-Prod',
        destinationAsset: 'finance-erp-node-04',
        destinationPort: 445,
        protocol: 'TLS 1.3',
        packetsMatched: 520,
        bytesTransferred: 312_000,
        mitreTactic: 'TA0008 · Lateral Movement',
        signatureId: 'SIG-INT-2840',
        summary: 'SMB port sweep isolated to quarantine VLAN by automated micro-segmentation.',
        autoMitigated: true,
        acknowledged: true,
      },
    ];

    seedThreats.forEach((t, idx) => {
      const ts = new Date(now - (idx + 1) * 95_000).toISOString();
      const alert: ThreatAlert = {
        ...t,
        id: `ALT-${this.alertCounter++}`,
        timestamp: ts,
      };
      this.alerts.push(alert);
      this.appendEncryptedLog({
        eventId: alert.id,
        timestamp: ts,
        sourceIp: alert.sourceIp,
        destinationIp: '10.24.8.12',
        destinationPort: alert.destinationPort,
        protocol: alert.protocol,
        action: alert.status === 'blocked' ? 'DROP' : alert.status === 'mitigated' ? 'QUARANTINE' : 'ALLOW',
        bytes: alert.bytesTransferred,
        tlsCipher: 'TLS_AES_256_GCM_SHA384',
        userAgentOrProcess: alert.destinationAsset,
        threatSignature: alert.signatureId,
      }, alert.severity);
    });

    // Seed additional normal encrypted traffic logs
    for (let i = 0; i < 6; i += 1) {
      const ts = new Date(now - (i + 1) * 18_000).toISOString();
      this.appendEncryptedLog(
        {
          eventId: `FLW-${8100 + i}`,
          timestamp: ts,
          sourceIp: `172.16.40.${20 + i}`,
          destinationIp: '10.24.0.15',
          destinationPort: i % 2 === 0 ? 443 : 8443,
          protocol: PROTOCOLS[i % PROTOCOLS.length],
          action: 'ALLOW',
          bytes: 18_400 + i * 3200,
          tlsCipher: 'TLS_AES_256_GCM_SHA384',
          userAgentOrProcess: 'envoy-mesh-proxy',
          threatSignature: null,
        },
        'low',
      );
    }

    this.notifications = this.alerts
      .filter((a) => !a.acknowledged)
      .map((a) => ({
        id: `NTF-${a.id}`,
        timestamp: a.timestamp,
        title: a.title,
        message: `${a.sourceIp} -> ${a.destinationAsset} (:${a.destinationPort})`,
        severity: a.severity,
        read: false,
        alertId: a.id,
      }));

    this.siemConnectors = [
      {
        id: 'siem-splunk',
        name: 'Enterprise Splunk HEC',
        vendor: 'Splunk HEC',
        endpointUrl: 'https://splunk-hec.corp-soc.example/services/collector/event',
        format: 'JSON',
        enabled: true,
        eventsSynced: 482_910,
        lastSyncAt: new Date(now - 12_000).toISOString(),
        lastStatus: 'healthy',
        avgLatencyMs: 38,
      },
      {
        id: 'siem-elastic',
        name: 'Elastic Security Cluster',
        vendor: 'Elastic SIEM',
        endpointUrl: 'https://elastic-ingest.corp-soc.example:9200/_bulk',
        format: 'JSON',
        enabled: true,
        eventsSynced: 319_440,
        lastSyncAt: new Date(now - 18_000).toISOString(),
        lastStatus: 'healthy',
        avgLatencyMs: 44,
      },
      {
        id: 'siem-qradar',
        name: 'IBM QRadar Collector',
        vendor: 'IBM QRadar',
        endpointUrl: 'https://qradar-gw.corp-soc.example/api/leef/ingest',
        format: 'LEEF',
        enabled: false,
        eventsSynced: 94_120,
        lastSyncAt: new Date(now - 3_600_000).toISOString(),
        lastStatus: 'standby',
        avgLatencyMs: 61,
      },
      {
        id: 'siem-sentinel',
        name: 'Microsoft Sentinel Workspace',
        vendor: 'Microsoft Sentinel',
        endpointUrl: 'https://sentinel-dce.corp-soc.example/dataCollectionRules/cef',
        format: 'CEF',
        enabled: true,
        eventsSynced: 215_800,
        lastSyncAt: new Date(now - 9_000).toISOString(),
        lastStatus: 'healthy',
        avgLatencyMs: 52,
      },
    ];

    const seedRaw1 = 'sg_live_splunk_9921a8f0c441e882b';
    const seedRaw2 = 'sg_live_elastic_4410d7b2a903f112c';
    this.siemApiKeys = [
      {
        id: 'key-1',
        label: 'Splunk Production Forwarder',
        prefix: seedRaw1.slice(0, 14),
        scopes: ['logs:read', 'alerts:stream', 'siem:export'],
        createdAt: new Date(now - 14 * 86_400_000).toISOString(),
        lastUsedAt: new Date(now - 12_000).toISOString(),
        revoked: false,
        keyHash: hashApiKey(seedRaw1),
      },
      {
        id: 'key-2',
        label: 'Elastic SOC Bridge',
        prefix: seedRaw2.slice(0, 14),
        scopes: ['alerts:stream', 'reports:read'],
        createdAt: new Date(now - 7 * 86_400_000).toISOString(),
        lastUsedAt: new Date(now - 18_000).toISOString(),
        revoked: false,
        keyHash: hashApiKey(seedRaw2),
      },
    ];

    this.integrations = [
      {
        id: 'int-slack',
        name: 'Slack #sec-ops-alerts',
        category: 'messaging',
        description: 'Instant threat cards & interactive block-IP actions for SOC analysts.',
        enabled: true,
        syncMode: 'realtime',
        eventsDispatched: 1420,
        lastDeliveredAt: new Date(now - 95_000).toISOString(),
      },
      {
        id: 'int-pagerduty',
        name: 'PagerDuty On-Call Escalation',
        category: 'incident',
        description: 'Automated 24/7 paging for Critical severity DDoS and C2 alerts.',
        enabled: true,
        syncMode: 'realtime',
        eventsDispatched: 118,
        lastDeliveredAt: new Date(now - 310_000).toISOString(),
      },
      {
        id: 'int-cloudflare',
        name: 'Cloudflare WAF Edge Sync',
        category: 'waf',
        description: 'Pushes blocked attacker CIDRs directly to global edge firewall rules.',
        enabled: true,
        syncMode: 'realtime',
        eventsDispatched: 642,
        lastDeliveredAt: new Date(now - 95_000).toISOString(),
      },
      {
        id: 'int-jira',
        name: 'Jira Security Compliance',
        category: 'ticketing',
        description: 'Creates audit-linked remediation tickets for High/Critical incidents.',
        enabled: false,
        syncMode: 'batched',
        eventsDispatched: 89,
        lastDeliveredAt: new Date(now - 86_400_000).toISOString(),
      },
    ];

    this.automationRules = [
      {
        id: 'rule-1',
        name: 'Auto-Block Critical Edge Floods & C2',
        minSeverity: 'critical',
        action: 'block_ip_and_notify',
        channels: ['Cloudflare WAF', 'Slack #sec-ops-alerts', 'PagerDuty'],
        enabled: true,
        triggerCount: 28,
        lastTriggeredAt: new Date(now - 190_000).toISOString(),
      },
      {
        id: 'rule-2',
        name: 'Escalate High-Severity Probes to SIEM',
        minSeverity: 'high',
        action: 'siem_escalate',
        channels: ['Splunk HEC', 'Elastic SIEM', 'Slack #sec-ops-alerts'],
        enabled: true,
        triggerCount: 74,
        lastTriggeredAt: new Date(now - 95_000).toISOString(),
      },
      {
        id: 'rule-3',
        name: 'Isolate East-West Lateral Movement',
        minSeverity: 'medium',
        action: 'quarantine_host',
        channels: ['Internal Micro-Segmentation', 'Jira Security'],
        enabled: true,
        triggerCount: 14,
        lastTriggeredAt: new Date(now - 380_000).toISOString(),
      },
    ];

    this.complianceControls = [
      {
        framework: 'ISO 27001',
        status: 'compliant',
        coveragePercent: 98,
        lastAuditedAt: new Date(now - 43_200_000).toISOString(),
        evidenceSummary: 'A.12.4 E2E AES-256-GCM encrypted logging & A.9.4 MFA enforced.',
      },
      {
        framework: 'SOC 2 Type II',
        status: 'compliant',
        coveragePercent: 97,
        lastAuditedAt: new Date(now - 43_200_000).toISOString(),
        evidenceSummary: 'CC7.2 Continuous anomaly detection & automated SIEM archival.',
      },
      {
        framework: 'PCI-DSS 4.0',
        status: 'compliant',
        coveragePercent: 96,
        lastAuditedAt: new Date(now - 86_400_000).toISOString(),
        evidenceSummary: 'Req 10.3 Tamper-evident SHA-256 log chain & Req 8.4 TOTP MFA.',
      },
      {
        framework: 'GDPR',
        status: 'compliant',
        coveragePercent: 99,
        lastAuditedAt: new Date(now - 86_400_000).toISOString(),
        evidenceSummary: 'Art. 32 End-to-end encryption of packet telemetry & key rotation.',
      },
    ];

    const initialReport = buildWeeklyReport({
      id: `RPT-W${this.reportCounter}`,
      generatedAt: new Date(now - 2 * 86_400_000).toISOString(),
      periodLabel: '2026-11-13 — 2026-11-20',
      trafficHistory: this.trafficHistory,
      alerts: this.alerts,
      logs: this.encryptedLogs,
      complianceControls: this.complianceControls,
    });
    this.weeklyReports.push(initialReport);
  }

  public appendEncryptedLog(payload: DecryptedLogPayload, severity: SeverityLevel): EncryptedLogEntry {
    this.logSequence += 1;
    const prevHash =
      this.encryptedLogs.length > 0 ? this.encryptedLogs[0].integrityHash : 'GENESIS';
    const keyHex = this.encryptionKeys.get(this.activeKeyId)!;
    const envelope = encryptTrafficPayload(payload, keyHex, this.activeKeyId);
    const integrityHash = computeLogIntegrityHash(prevHash, {
      sequence: this.logSequence,
      timestamp: payload.timestamp,
      sourceIp: payload.sourceIp,
      destinationPort: payload.destinationPort,
      ciphertext: envelope.ciphertext,
      keyId: this.activeKeyId,
    });

    const entry: EncryptedLogEntry = {
      id: `LOG-${String(this.logSequence).padStart(5, '0')}`,
      sequence: this.logSequence,
      timestamp: payload.timestamp,
      sourceIp: payload.sourceIp,
      destinationPort: payload.destinationPort,
      protocol: payload.protocol,
      severity,
      keyId: this.activeKeyId,
      prevHash,
      integrityHash,
      envelope,
    };

    this.encryptedLogs.unshift(entry);
    if (this.encryptedLogs.length > 120) {
      this.encryptedLogs.length = 120;
    }
    return entry;
  }

  public generateLiveTrafficTick(): {
    sample: TrafficSample;
    newAlert: ThreatAlert | null;
    newLog: EncryptedLogEntry;
    newNotification: SecurityNotification | null;
    cluster: ClusterConfig;
  } {
    const nowIso = new Date().toISOString();
    const spikeFactor = this.cluster.stressTestActive ? 3.4 : 1.0;
    const jitter = (Math.random() - 0.45) * 4.5;
    const inboundGbps = Number(Math.max(8.5, (24.5 + jitter) * spikeFactor).toFixed(2));
    const outboundGbps = Number(Math.max(4.2, (14.2 + jitter * 0.5) * spikeFactor).toFixed(2));
    const packetsPerSec = Math.round((inboundGbps + outboundGbps) * 7200);
    const blockedPacketsPerSec = Math.round(packetsPerSec * (this.cluster.stressTestActive ? 0.08 : 0.016));
    const latencyMs = Number((this.cluster.stressTestActive ? 3.1 : 1.35 + Math.random() * 0.5).toFixed(2));

    const sample: TrafficSample = {
      id: `pkt-${Date.now()}`,
      timestamp: nowIso,
      inboundGbps,
      outboundGbps,
      packetsPerSec,
      blockedPacketsPerSec,
      latencyMs,
      anomalyScore: this.cluster.stressTestActive ? 64 : Math.round(10 + Math.random() * 18),
      protocols: {
        'TLS 1.3': 43,
        HTTPS: 23,
        QUIC: 15,
        gRPC: 9,
        DNS: 7,
        SSH: 3,
      },
    };

    this.trafficHistory.push(sample);
    if (this.trafficHistory.length > 60) {
      this.trafficHistory.shift();
    }

    this.cluster = calculateClusterScale(inboundGbps + outboundGbps, packetsPerSec, this.cluster);

    // Sync enabled SIEM connectors incrementally
    for (const connector of this.siemConnectors) {
      if (connector.enabled) {
        connector.eventsSynced += Math.round(packetsPerSec / 1800);
        connector.lastSyncAt = nowIso;
      }
    }

    const newLog = this.appendEncryptedLog(
      {
        eventId: `FLW-${Date.now().toString().slice(-6)}`,
        timestamp: nowIso,
        sourceIp: `172.16.${Math.floor(10 + Math.random() * 40)}.${Math.floor(2 + Math.random() * 240)}`,
        destinationIp: '10.24.0.15',
        destinationPort: 443,
        protocol: 'TLS 1.3',
        action: 'ALLOW',
        bytes: Math.round(inboundGbps * 12_500),
        tlsCipher: 'TLS_AES_256_GCM_SHA384',
        userAgentOrProcess: 'envoy-edge-ingress',
        threatSignature: null,
      },
      'low',
    );

    return { sample, newAlert: null, newLog, newNotification: null, cluster: this.cluster };
  }

  public triggerThreatScenario(scenario: ThreatCategory): {
    alert: ThreatAlert;
    log: EncryptedLogEntry;
    notification: SecurityNotification;
    triggeredRules: string[];
    trafficSample: TrafficSample;
    cluster: ClusterConfig;
    simulation: AttackSimulationState;
  } {
    const nowIso = new Date().toISOString();
    const geoVariants: Record<ThreatCategory, Array<{ ip: string; geo: string }>> = {
      ddos_volumetric: [
        { ip: '198.51.100.204', geo: 'Bucharest, RO' },
        { ip: '203.0.113.92', geo: 'Tokyo, JP' },
        { ip: '192.0.2.177', geo: 'New York, US' },
      ],
      sqli_probe: [
        { ip: '91.214.124.88', geo: 'Warsaw, PL' },
        { ip: '185.199.108.41', geo: 'Frankfurt, DE' },
        { ip: '177.54.148.19', geo: 'Sao Paulo, BR' },
      ],
      ssh_bruteforce: [
        { ip: '185.156.73.12', geo: 'Sofia, BG' },
        { ip: '51.140.44.83', geo: 'London, UK' },
        { ip: '45.155.205.61', geo: 'Amsterdam, NL' },
      ],
      c2_beacon: [
        { ip: '103.214.112.55', geo: 'Hong Kong, HK' },
        { ip: '103.149.28.99', geo: 'Singapore, SG' },
        { ip: '202.12.27.33', geo: 'Sydney, AU' },
      ],
      data_exfiltration: [
        { ip: '10.24.19.88', geo: 'Internal Subnet-B' },
        { ip: '172.20.14.52', geo: 'Jakarta, ID' },
      ],
      lateral_movement: [
        { ip: '10.24.44.19', geo: 'Internal Dev-VPC' },
        { ip: '10.42.18.90', geo: 'Internal VPC-Prod' },
      ],
    };

    const pool = geoVariants[scenario];
    const originPick = pool[this.alertCounter % pool.length];

    const scenarios: Record<
      ThreatCategory,
      {
        sourceIp: string;
        sourceGeo: string;
        destinationAsset: string;
        destinationPort: number;
        protocol: ProtocolName;
        packetsPerSec: number;
        bytesTransferred: number;
        payloadSignature?: string;
        summary: string;
        inboundSpikeGbps: number;
        outboundSpikeGbps: number;
      }
    > = {
      ddos_volumetric: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: 'edge-lb-prod-01',
        destinationPort: 443,
        protocol: 'QUIC',
        packetsPerSec: 340_000,
        bytesTransferred: 48_000_000,
        summary: 'Distributed UDP/QUIC amplification flood exceeding 340k pps edge threshold.',
        inboundSpikeGbps: 94.6,
        outboundSpikeGbps: 19.4,
      },
      sqli_probe: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: 'checkout-api-svc',
        destinationPort: 443,
        protocol: 'HTTPS',
        packetsPerSec: 210,
        bytesTransferred: 19_200,
        payloadSignature: "POST /api/orders?id=1' UNION SELECT * FROM users--",
        summary: 'Crafted SQL injection payload probing customer order endpoint.',
        inboundSpikeGbps: 44.8,
        outboundSpikeGbps: 16.2,
      },
      ssh_bruteforce: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: 'bastion-eu-01',
        destinationPort: 22,
        protocol: 'SSH',
        packetsPerSec: 2_400,
        bytesTransferred: 840_000,
        summary: 'Automated credential stuffing burst targeting OpenSSH administrative port.',
        inboundSpikeGbps: 52.3,
        outboundSpikeGbps: 15.8,
      },
      c2_beacon: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: 'worker-pod-77a',
        destinationPort: 53,
        protocol: 'DNS',
        packetsPerSec: 85,
        bytesTransferred: 142_000,
        payloadSignature: 'beacon-c2-exfil-txt',
        summary: 'Encoded DNS TXT command-and-control beacon detected on internal pod.',
        inboundSpikeGbps: 38.9,
        outboundSpikeGbps: 28.4,
      },
      data_exfiltration: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: 'ext-relay-45.9.12.4',
        destinationPort: 8443,
        protocol: 'TLS 1.3',
        packetsPerSec: 18_500,
        bytesTransferred: 128_000_000,
        summary: 'Unusual 128 MB encrypted outbound transfer outside business hours.',
        inboundSpikeGbps: 34.2,
        outboundSpikeGbps: 71.5,
      },
      lateral_movement: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: 'vault-kms-02',
        destinationPort: 445,
        protocol: 'TLS 1.3',
        packetsPerSec: 650,
        bytesTransferred: 410_000,
        summary: 'Unauthorized SMB enumeration scan from non-privileged host toward KMS.',
        inboundSpikeGbps: 46.5,
        outboundSpikeGbps: 21.0,
      },
    };

    const chosen = scenarios[scenario];
    const detection = detectThreatFromTraffic({
      sourceIp: chosen.sourceIp,
      sourceGeo: chosen.sourceGeo,
      destinationAsset: chosen.destinationAsset,
      destinationPort: chosen.destinationPort,
      protocol: chosen.protocol,
      packetsPerSec: chosen.packetsPerSec,
      bytesTransferred: chosen.bytesTransferred,
      payloadSignature: chosen.payloadSignature,
    });

    const severity: SeverityLevel = detection.severity ?? 'high';
    const triggeredRules: string[] = [];
    let autoMitigated = false;

    for (const rule of this.automationRules) {
      if (rule.enabled && severityRank(severity) >= severityRank(rule.minSeverity)) {
        rule.triggerCount += 1;
        rule.lastTriggeredAt = nowIso;
        triggeredRules.push(rule.name);
        if (rule.action === 'block_ip_and_notify' || rule.action === 'quarantine_host') {
          autoMitigated = true;
        }
      }
    }

    for (const integration of this.integrations) {
      if (integration.enabled) {
        integration.eventsDispatched += 1;
        integration.lastDeliveredAt = nowIso;
      }
    }

    const alert: ThreatAlert = {
      id: `ALT-${this.alertCounter++}`,
      timestamp: nowIso,
      title: detection.title ?? 'Security Anomaly Detected',
      category: detection.category ?? scenario,
      severity,
      status: autoMitigated ? 'blocked' : 'active',
      sourceIp: chosen.sourceIp,
      sourceGeo: chosen.sourceGeo,
      destinationAsset: chosen.destinationAsset,
      destinationPort: chosen.destinationPort,
      protocol: chosen.protocol,
      packetsMatched: chosen.packetsPerSec,
      bytesTransferred: chosen.bytesTransferred,
      mitreTactic: detection.mitreTactic ?? 'TA0001 · Initial Access',
      signatureId: detection.signatureId ?? 'SIG-GEN-9001',
      summary: chosen.summary,
      autoMitigated,
      acknowledged: false,
    };

    this.alerts.unshift(alert);
    if (this.alerts.length > 80) {
      this.alerts.length = 80;
    }

    const log = this.appendEncryptedLog(
      {
        eventId: alert.id,
        timestamp: nowIso,
        sourceIp: alert.sourceIp,
        destinationIp: '10.24.0.15',
        destinationPort: alert.destinationPort,
        protocol: alert.protocol,
        action: autoMitigated ? 'DROP' : 'QUARANTINE',
        bytes: alert.bytesTransferred,
        tlsCipher: 'TLS_AES_256_GCM_SHA384',
        userAgentOrProcess: alert.destinationAsset,
        threatSignature: alert.signatureId,
      },
      severity,
    );

    const notification: SecurityNotification = {
      id: `NTF-${alert.id}`,
      timestamp: nowIso,
      title: alert.title,
      message: `${alert.sourceIp} -> ${alert.destinationAsset} (:${alert.destinationPort})${
        autoMitigated ? ' · Auto-blocked' : ''
      }`,
      severity,
      read: false,
      alertId: alert.id,
    };
    this.notifications.unshift(notification);
    if (this.notifications.length > 40) {
      this.notifications.length = 40;
    }

    const spikePps = Math.round(
      (chosen.inboundSpikeGbps + chosen.outboundSpikeGbps) * 7600 + chosen.packetsPerSec,
    );
    const trafficSample: TrafficSample = {
      id: `pkt-sim-${Date.now()}-${this.alertCounter}`,
      timestamp: nowIso,
      inboundGbps: chosen.inboundSpikeGbps,
      outboundGbps: chosen.outboundSpikeGbps,
      packetsPerSec: spikePps,
      blockedPacketsPerSec: Math.round(spikePps * (autoMitigated ? 0.34 : 0.14)),
      latencyMs: Number((2.8 + Math.random() * 1.6).toFixed(2)),
      anomalyScore: severity === 'critical' ? 96 : severity === 'high' ? 88 : 74,
      protocols: {
        'TLS 1.3': 34,
        HTTPS: 22,
        QUIC: scenario === 'ddos_volumetric' ? 28 : 14,
        gRPC: 8,
        DNS: scenario === 'c2_beacon' ? 14 : 6,
        SSH: scenario === 'ssh_bruteforce' ? 16 : 2,
      },
    };
    this.trafficHistory.push(trafficSample);
    if (this.trafficHistory.length > 60) {
      this.trafficHistory.shift();
    }
    this.cluster = calculateClusterScale(
      chosen.inboundSpikeGbps + chosen.outboundSpikeGbps,
      spikePps,
      this.cluster,
    );

    this.simulation = {
      ...this.simulation,
      wavesSent: this.simulation.wavesSent + 1,
      lastTriggeredAt: nowIso,
    };

    return {
      alert,
      log,
      notification,
      triggeredRules,
      trafficSample,
      cluster: this.cluster,
      simulation: this.simulation,
    };
  }

  public toPublicManagedUser(account: ServerUserAccount): ManagedUserAccount {
    let activeSessionCount = 0;
    for (const session of this.sessions.values()) {
      if (session.userId === account.id) {
        activeSessionCount += 1;
      }
    }
    return {
      id: account.id,
      fullName: account.fullName,
      email: account.email,
      department: account.department,
      role: account.role,
      status: account.status,
      mfaEnrolled: account.mfaConfirmed,
      registeredAt: account.registeredAt,
      registeredIp: account.registeredIp,
      deviceInfo: account.deviceInfo,
      lastLoginAt: account.lastLoginAt,
      activeSessionCount,
      issueFlagged: account.issueFlagged,
      issueNote: account.issueNote,
      approvedBy: account.approvedBy,
      updatedAt: account.updatedAt,
    };
  }

  public registerUserAccount(params: {
    fullName: string;
    email: string;
    department: string;
    password: string;
    registeredIp: string;
    deviceInfo: string;
  }): {
    user: ManagedUserAccount;
    auditEntry: AccountControlAuditEntry;
    notification: SecurityNotification;
  } {
    this.userCounter += 1;
    const nowIso = new Date().toISOString();
    const initialStatus: UserAccountStatus = this.requireAdminApproval ? 'pending' : 'active';
    const id = `USR-${this.userCounter}`;
    const account: ServerUserAccount = {
      id,
      fullName: params.fullName,
      email: params.email,
      department: params.department,
      role: 'analyst',
      status: initialStatus,
      passwordHash: hashPasswordScrypt(params.password),
      totpSecret: generateTotpSecret(),
      mfaConfirmed: false,
      backupCodeHashes: [],
      registeredAt: nowIso,
      registeredIp: params.registeredIp,
      deviceInfo: params.deviceInfo,
      lastLoginAt: null,
      issueFlagged: false,
      issueNote: '',
      approvedBy: initialStatus === 'active' ? 'Auto-Policy' : null,
      updatedAt: nowIso,
    };
    this.users.unshift(account);

    const auditEntry: AccountControlAuditEntry = {
      id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: nowIso,
      actorEmail: params.email,
      targetEmail: params.email,
      targetUserId: id,
      action: 'user_registered',
      detail: `Registered from ${params.deviceInfo} (status: ${initialStatus})`,
      ipAddress: params.registeredIp,
      deviceInfo: params.deviceInfo,
    };
    this.accountAuditLogs.unshift(auditEntry);
    if (this.accountAuditLogs.length > 200) {
      this.accountAuditLogs.length = 200;
    }

    const notification: SecurityNotification = {
      id: `NTF-REG-${id}`,
      timestamp: nowIso,
      title: `Pendaftaran Akun Baru: ${params.fullName}`,
      message: `${params.email} · ${params.deviceInfo} (${params.registeredIp}) — masuk antrean kontrol Admin`,
      severity: 'medium',
      read: false,
      targetRole: 'admin',
    };
    this.notifications.unshift(notification);
    if (this.notifications.length > 40) {
      this.notifications.length = 40;
    }

    this.persistAccountsToDisk();
    return {
      user: this.toPublicManagedUser(account),
      auditEntry,
      notification,
    };
  }

  public createUserComplaintReport(params: {
    userId: string;
    email: string;
    ipAddress: string;
    deviceInfo: string;
    category: ComplaintCategory;
    severity: SeverityLevel;
    subject: string;
    description: string;
  }): { report: UserComplaintReport; notification: SecurityNotification } {
    this.complaintCounter += 1;
    const nowIso = new Date().toISOString();
    const account = this.users.find((u) => u.id === params.userId);
    const fullName = account?.fullName || (params.userId === 'ADMIN-ROOT' ? 'SOC Administrator' : params.email);
    const department = account?.department || 'SOC Operations';

    const report: UserComplaintReport = {
      id: `CMP-${this.complaintCounter}`,
      userId: params.userId,
      userFullName: fullName,
      userEmail: params.email,
      department,
      deviceInfo: params.deviceInfo,
      ipAddress: params.ipAddress,
      category: params.category,
      severity: params.severity,
      subject: params.subject,
      description: params.description,
      status: 'open',
      adminNote: '',
      handledBy: null,
      createdAt: nowIso,
      updatedAt: nowIso,
    };

    this.userReports.unshift(report);
    if (this.userReports.length > 200) {
      this.userReports.length = 200;
    }

    const notification: SecurityNotification = {
      id: `NTF-CMP-${report.id}`,
      timestamp: nowIso,
      title: `Keluhan Pengguna: ${report.subject}`,
      message: `${report.userFullName} (${report.userEmail}) · ${report.deviceInfo} (${report.ipAddress})`,
      severity: report.severity,
      read: false,
      reportId: report.id,
      targetRole: 'admin',
    };
    this.notifications.unshift(notification);
    if (this.notifications.length > 40) {
      this.notifications.length = 40;
    }

    this.persistAccountsToDisk();
    return { report, notification };
  }

  public respondToUserComplaintReport(params: {
    reportId: string;
    adminEmail: string;
    status: ComplaintStatus;
    adminNote?: string;
  }): { report: UserComplaintReport; notification: SecurityNotification } | null {
    const report = this.userReports.find((r) => r.id === params.reportId);
    if (!report) return null;

    const nowIso = new Date().toISOString();
    report.status = params.status;
    if (typeof params.adminNote === 'string') {
      report.adminNote = params.adminNote.trim().slice(0, 600);
    }
    report.handledBy = params.adminEmail;
    report.updatedAt = nowIso;

    const statusText =
      params.status === 'resolved'
        ? 'Selesai'
        : params.status === 'in_review'
          ? 'Ditinjau Admin'
          : 'Menunggu';

    const notification: SecurityNotification = {
      id: `NTF-CMP-RES-${report.id}-${Date.now()}`,
      timestamp: nowIso,
      title: `Pembaruan Keluhan: ${report.subject}`,
      message: `Status: ${statusText}${report.adminNote ? ` · Catatan Admin: ${report.adminNote}` : ''}`,
      severity: params.status === 'resolved' ? 'low' : 'medium',
      read: false,
      reportId: report.id,
      targetRole: 'all',
      targetUserId: report.userId,
    };
    this.notifications.unshift(notification);
    if (this.notifications.length > 40) {
      this.notifications.length = 40;
    }

    this.persistAccountsToDisk();
    return { report, notification };
  }

  public revokeSessionsForUser(userId: string): number {
    let revokedCount = 0;
    for (const [token, sess] of this.sessions.entries()) {
      if (sess.userId === userId) {
        this.sessions.delete(token);
        revokedCount += 1;
      }
    }
    return revokedCount;
  }

  public applyAdminUserControl(params: {
    userId: string;
    actorEmail: string;
    actorIp: string;
    actorDevice: string;
    action:
      | 'activate'
      | 'suspend'
      | 'block'
      | 'reset_mfa'
      | 'revoke_sessions'
      | 'change_role'
      | 'update_issue';
    role?: UserRole;
    issueFlagged?: boolean;
    issueNote?: string;
  }): {
    user: ManagedUserAccount;
    auditEntry: AccountControlAuditEntry;
    revokedSessionCount: number;
    shouldRevokeWs: boolean;
    revokeReason: string;
  } | null {
    const account = this.users.find((u) => u.id === params.userId);
    if (!account) return null;

    const nowIso = new Date().toISOString();
    let auditAction: AccountControlAuditEntry['action'] = 'issue_updated';
    let detail = '';
    let revokedSessionCount = 0;
    let shouldRevokeWs = false;
    let revokeReason = 'Session updated by administrator';

    if (params.action === 'activate') {
      account.status = 'active';
      account.approvedBy = params.actorEmail;
      if (params.issueFlagged === false) {
        account.issueFlagged = false;
        account.issueNote = '';
      }
      auditAction = 'user_activated';
      detail = `Account activated by ${params.actorEmail}`;
    } else if (params.action === 'suspend') {
      account.status = 'suspended';
      account.issueFlagged = true;
      if (typeof params.issueNote === 'string' && params.issueNote.trim()) {
        account.issueNote = params.issueNote.trim().slice(0, 240);
      } else if (!account.issueNote) {
        account.issueNote = 'Suspended by administrator during incident review';
      }
      revokedSessionCount = this.revokeSessionsForUser(account.id);
      shouldRevokeWs = true;
      revokeReason = account.issueNote;
      auditAction = 'user_suspended';
      detail = `Account suspended (${account.issueNote})`;
    } else if (params.action === 'block') {
      account.status = 'blocked';
      account.issueFlagged = true;
      if (typeof params.issueNote === 'string' && params.issueNote.trim()) {
        account.issueNote = params.issueNote.trim().slice(0, 240);
      } else if (!account.issueNote) {
        account.issueNote = 'Blocked by administrator due to security policy';
      }
      revokedSessionCount = this.revokeSessionsForUser(account.id);
      shouldRevokeWs = true;
      revokeReason = account.issueNote;
      auditAction = 'user_blocked';
      detail = `Account blocked (${account.issueNote})`;
    } else if (params.action === 'reset_mfa') {
      account.totpSecret = generateTotpSecret();
      account.mfaConfirmed = false;
      account.backupCodeHashes = [];
      revokedSessionCount = this.revokeSessionsForUser(account.id);
      shouldRevokeWs = true;
      revokeReason = 'MFA credentials reset by administrator; re-login required';
      auditAction = 'mfa_reset';
      detail = 'TOTP MFA reset & active sessions terminated';
    } else if (params.action === 'revoke_sessions') {
      revokedSessionCount = this.revokeSessionsForUser(account.id);
      shouldRevokeWs = true;
      revokeReason = 'Active sessions terminated by administrator';
      auditAction = 'sessions_revoked';
      detail = `Revoked ${revokedSessionCount} active session(s)`;
    } else if (params.action === 'change_role' && params.role && isValidUserRole(params.role)) {
      const prevRole = account.role;
      account.role = params.role;
      for (const sess of this.sessions.values()) {
        if (sess.userId === account.id) {
          sess.roleKey = params.role;
          sess.role = roleDisplayName(params.role);
        }
      }
      auditAction = 'role_changed';
      detail = `Role changed from ${prevRole} to ${params.role}`;
    } else if (params.action === 'update_issue') {
      account.issueFlagged = Boolean(params.issueFlagged);
      account.issueNote = (params.issueNote || '').trim().slice(0, 240);
      auditAction = 'issue_updated';
      detail = account.issueFlagged
        ? `Issue flagged: ${account.issueNote || 'Under investigation'}`
        : 'Issue flag cleared by administrator';
    }

    account.updatedAt = nowIso;

    const auditEntry: AccountControlAuditEntry = {
      id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
      timestamp: nowIso,
      actorEmail: params.actorEmail,
      targetEmail: account.email,
      targetUserId: account.id,
      action: auditAction,
      detail,
      ipAddress: params.actorIp,
      deviceInfo: params.actorDevice,
    };
    this.accountAuditLogs.unshift(auditEntry);
    if (this.accountAuditLogs.length > 200) {
      this.accountAuditLogs.length = 200;
    }

    this.persistAccountsToDisk();
    return {
      user: this.toPublicManagedUser(account),
      auditEntry,
      revokedSessionCount,
      shouldRevokeWs,
      revokeReason,
    };
  }

  public createSignedSession(params: {
    userId: string;
    email: string;
    roleKey: UserRole;
    userAgent: string;
    ipAddress: string;
  }): ServerSession {
    const id = `SES-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const payload = Buffer.from(
      JSON.stringify({ id, userId: params.userId, email: params.email, iat: Date.now() }),
      'utf8',
    ).toString('base64url');
    const sig = crypto
      .createHmac('sha256', this.sessionSigningSecret)
      .update(payload)
      .digest('base64url');
    const token = `${payload}.${sig}`;
    const nowIso = new Date().toISOString();
    const session: ServerSession = {
      token,
      id,
      userId: params.userId,
      email: params.email,
      role: roleDisplayName(params.roleKey),
      roleKey: params.roleKey,
      mfaVerified: true,
      createdAt: nowIso,
      lastSeenAt: nowIso,
      userAgent: params.userAgent,
      ipAddress: params.ipAddress,
    };
    this.sessions.set(token, session);
    return session;
  }

  public verifyBearerToken(token: string | undefined): ServerSession | null {
    if (!token) return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [payload, sig] = parts;
    const expectedSig = crypto
      .createHmac('sha256', this.sessionSigningSecret)
      .update(payload)
      .digest('base64url');
    const sigBuf = Buffer.from(sig);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    const session = this.sessions.get(token);
    if (!session) return null;

    if (session.userId !== 'ADMIN-ROOT') {
      const account = this.users.find((u) => u.id === session.userId);
      if (!account || account.status !== 'active') {
        this.sessions.delete(token);
        return null;
      }
    }

    session.lastSeenAt = new Date().toISOString();
    return session;
  }

  public getSnapshot(viewerSession?: ServerSession): SocSnapshot {
    const publicKeys: SiemApiKey[] = this.siemApiKeys.map(({ keyHash: _unused, ...rest }) => rest);
    const allPublicSessions: ActiveSessionInfo[] = Array.from(this.sessions.values()).map(
      ({ token: _unused, ...rest }) => rest,
    );
    const isAdminViewer = !viewerSession || viewerSession.roleKey === 'admin';
    const visibleSessions = isAdminViewer
      ? allPublicSessions
      : allPublicSessions.filter((s) => s.userId === viewerSession.userId);
    const visibleUsers = isAdminViewer
      ? this.users.map((u) => this.toPublicManagedUser(u))
      : [];
    const visibleAuditLogs = isAdminViewer ? this.accountAuditLogs : [];
    const visibleReports = isAdminViewer
      ? this.userReports
      : this.userReports.filter((r) => r.userId === viewerSession.userId);
    const visibleNotifications = isAdminViewer
      ? this.notifications
      : this.notifications.filter(
          (n) =>
            !n.targetRole ||
            (n.targetRole === 'all' && (!n.targetUserId || n.targetUserId === viewerSession.userId)),
        );

    return {
      trafficHistory: this.trafficHistory,
      alerts: this.alerts,
      encryptedLogs: this.encryptedLogs,
      siemConnectors: this.siemConnectors,
      siemApiKeys: isAdminViewer ? publicKeys : [],
      integrations: this.integrations,
      automationRules: this.automationRules,
      complianceControls: this.complianceControls,
      weeklyReports: this.weeklyReports,
      reportSchedule: this.reportSchedule,
      cluster: this.cluster,
      notifications: visibleNotifications,
      sessions: visibleSessions,
      users: visibleUsers,
      userReports: visibleReports,
      accountAuditLogs: visibleAuditLogs,
      requireAdminApproval: this.requireAdminApproval,
      simulation: this.simulation,
      activeKeyId: this.activeKeyId,
      mfaPolicy: {
        ...this.mfaPolicy,
        backupCodesRemaining: this.admin?.backupCodeHashes.length ?? 0,
      },
    };
  }

  public nextReportId(): string {
    this.reportCounter += 1;
    return `RPT-W${this.reportCounter}`;
  }
}
