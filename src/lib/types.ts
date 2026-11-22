export type LanguageCode = 'id' | 'en' | 'ja' | 'de';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low';

export type ThreatStatus = 'active' | 'mitigated' | 'blocked' | 'investigating';

export type ThreatCategory =
  | 'ddos_volumetric'
  | 'sqli_probe'
  | 'ssh_bruteforce'
  | 'c2_beacon'
  | 'data_exfiltration'
  | 'lateral_movement';

export type ProtocolName = 'TLS 1.3' | 'HTTPS' | 'DNS' | 'SSH' | 'QUIC' | 'gRPC';

export interface TrafficSample {
  id: string;
  timestamp: string;
  inboundGbps: number;
  outboundGbps: number;
  packetsPerSec: number;
  blockedPacketsPerSec: number;
  latencyMs: number;
  anomalyScore: number;
  protocols: Record<ProtocolName, number>;
}

export interface ThreatAlert {
  id: string;
  timestamp: string;
  title: string;
  category: ThreatCategory;
  severity: SeverityLevel;
  status: ThreatStatus;
  sourceIp: string;
  sourceGeo: string;
  destinationAsset: string;
  destinationPort: number;
  protocol: ProtocolName;
  packetsMatched: number;
  bytesTransferred: number;
  mitreTactic: string;
  signatureId: string;
  summary: string;
  autoMitigated: boolean;
  acknowledged: boolean;
}

export interface EncryptedEnvelope {
  ciphertext: string;
  iv: string;
  authTag: string;
  keyId: string;
  algorithm: 'AES-256-GCM';
}

export interface EncryptedLogEntry {
  id: string;
  sequence: number;
  timestamp: string;
  sourceIp: string;
  destinationPort: number;
  protocol: ProtocolName;
  severity: SeverityLevel;
  keyId: string;
  prevHash: string;
  integrityHash: string;
  envelope: EncryptedEnvelope;
}

export interface DecryptedLogPayload {
  eventId: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  destinationPort: number;
  protocol: ProtocolName;
  action: 'ALLOW' | 'DROP' | 'QUARANTINE';
  bytes: number;
  tlsCipher: string;
  userAgentOrProcess: string;
  threatSignature: string | null;
}

export type SiemFormat = 'JSON' | 'CEF' | 'LEEF';

export interface SiemConnector {
  id: string;
  name: string;
  vendor: 'Splunk HEC' | 'Elastic SIEM' | 'IBM QRadar' | 'Microsoft Sentinel';
  endpointUrl: string;
  format: SiemFormat;
  enabled: boolean;
  eventsSynced: number;
  lastSyncAt: string;
  lastStatus: 'healthy' | 'standby' | 'error';
  avgLatencyMs: number;
}

export interface SiemApiKey {
  id: string;
  label: string;
  prefix: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt: string | null;
  revoked: boolean;
}

export interface ThirdPartyIntegration {
  id: string;
  name: string;
  category: 'messaging' | 'incident' | 'waf' | 'edr' | 'ticketing';
  description: string;
  enabled: boolean;
  syncMode: 'realtime' | 'batched';
  eventsDispatched: number;
  lastDeliveredAt: string | null;
}

export interface AutomationRule {
  id: string;
  name: string;
  minSeverity: SeverityLevel;
  action: 'block_ip_and_notify' | 'quarantine_host' | 'siem_escalate' | 'pagerduty_page';
  channels: string[];
  enabled: boolean;
  triggerCount: number;
  lastTriggeredAt: string | null;
}

export interface ComplianceControl {
  framework: 'ISO 27001' | 'SOC 2 Type II' | 'PCI-DSS 4.0' | 'GDPR' | 'NIST CSF';
  status: 'compliant' | 'attention';
  coveragePercent: number;
  lastAuditedAt: string;
  evidenceSummary: string;
}

export interface WeeklyReportSchedule {
  enabled: boolean;
  dayOfWeek: 'Monday' | 'Friday' | 'Sunday';
  timeUtc: string;
  recipients: string[];
  includeEncryptedAudit: boolean;
  frameworks: string[];
}

export interface WeeklyReport {
  id: string;
  generatedAt: string;
  periodLabel: string;
  totalPacketsAnalyzed: string;
  totalThreatsDetected: number;
  criticalMitigated: number;
  meanTimeToRespondSec: number;
  e2eLogEncryptionPercent: number;
  siemSyncSuccessPercent: number;
  topVectors: Array<{ category: ThreatCategory; count: number }>;
  complianceScorePercent: number;
  summaryNote: string;
}

export interface ClusterNode {
  id: string;
  region: string;
  status: 'active' | 'scaling';
  cpuPercent: number;
  memoryPercent: number;
  ingestGbps: number;
  eventsPerSec: number;
}

export interface ClusterConfig {
  autoScaleEnabled: boolean;
  minNodes: number;
  maxNodes: number;
  activeNodes: number;
  targetLoadPercent: number;
  maxCapacityGbps: number;
  kafkaBufferPercent: number;
  stressTestActive: boolean;
  nodes: ClusterNode[];
}

export interface SecurityNotification {
  id: string;
  timestamp: string;
  title: string;
  message: string;
  severity: SeverityLevel;
  read: boolean;
  alertId?: string;
  reportId?: string;
  targetRole?: 'admin' | 'all';
  targetUserId?: string;
}

export type PortalMode = 'admin' | 'user';

export type ComplaintCategory =
  | 'access_mfa'
  | 'security_incident'
  | 'performance_bug'
  | 'policy_request'
  | 'other';

export type ComplaintStatus = 'open' | 'in_review' | 'resolved';

export interface UserComplaintReport {
  id: string;
  userId: string;
  userFullName: string;
  userEmail: string;
  department: string;
  deviceInfo: string;
  ipAddress: string;
  category: ComplaintCategory;
  severity: SeverityLevel;
  subject: string;
  description: string;
  status: ComplaintStatus;
  adminNote: string;
  handledBy: string | null;
  createdAt: string;
  updatedAt: string;
}

export type UserRole = 'admin' | 'analyst' | 'viewer';

export type UserAccountStatus = 'pending' | 'active' | 'suspended' | 'blocked';

export interface ManagedUserAccount {
  id: string;
  fullName: string;
  email: string;
  department: string;
  role: UserRole;
  status: UserAccountStatus;
  mfaEnrolled: boolean;
  registeredAt: string;
  registeredIp: string;
  deviceInfo: string;
  lastLoginAt: string | null;
  activeSessionCount: number;
  issueFlagged: boolean;
  issueNote: string;
  approvedBy: string | null;
  updatedAt: string;
}

export interface AccountControlAuditEntry {
  id: string;
  timestamp: string;
  actorEmail: string;
  targetEmail: string;
  targetUserId: string;
  action:
    | 'user_registered'
    | 'user_activated'
    | 'user_suspended'
    | 'user_blocked'
    | 'role_changed'
    | 'mfa_reset'
    | 'sessions_revoked'
    | 'issue_updated';
  detail: string;
  ipAddress: string;
  deviceInfo: string;
}

export interface ActiveSessionInfo {
  id: string;
  userId: string;
  email: string;
  role: string;
  roleKey: UserRole;
  mfaVerified: boolean;
  createdAt: string;
  lastSeenAt: string;
  userAgent: string;
  ipAddress?: string;
}

export interface AttackSimulationState {
  running: boolean;
  scenario: ThreatCategory | 'mixed';
  wavesSent: number;
  lastTriggeredAt: string | null;
}

export interface SocSnapshot {
  trafficHistory: TrafficSample[];
  alerts: ThreatAlert[];
  encryptedLogs: EncryptedLogEntry[];
  siemConnectors: SiemConnector[];
  siemApiKeys: SiemApiKey[];
  integrations: ThirdPartyIntegration[];
  automationRules: AutomationRule[];
  complianceControls: ComplianceControl[];
  weeklyReports: WeeklyReport[];
  reportSchedule: WeeklyReportSchedule;
  cluster: ClusterConfig;
  notifications: SecurityNotification[];
  sessions: ActiveSessionInfo[];
  users: ManagedUserAccount[];
  userReports: UserComplaintReport[];
  accountAuditLogs: AccountControlAuditEntry[];
  requireAdminApproval: boolean;
  simulation: AttackSimulationState;
  activeKeyId: string;
  mfaPolicy: {
    requireMfaForDecryption: boolean;
    requireMfaForKeyRotation: boolean;
    backupCodesRemaining: number;
  };
}

