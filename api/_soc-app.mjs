// server/vercel-entry.ts
import dotenv from "dotenv";

// server/app.ts
import crypto2 from "node:crypto";
import express from "express";

// src/lib/cryptoSecurity.ts
import crypto from "node:crypto";
var BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function generateEncryptionKeyHex() {
  return crypto.randomBytes(32).toString("hex");
}
function encryptTrafficPayload(payload, keyHex, keyId) {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) {
    throw new Error("AES-256-GCM requires a 32-byte (64 hex chars) key");
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    keyId,
    algorithm: "AES-256-GCM"
  };
}
function decryptTrafficPayload(envelope, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) {
    throw new Error("AES-256-GCM requires a 32-byte (64 hex chars) key");
  }
  const iv = Buffer.from(envelope.iv, "base64");
  const authTag = Buffer.from(envelope.authTag, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString("utf8"));
}
function computeLogIntegrityHash(prevHash, fields) {
  const canonical = `${prevHash}|${fields.sequence}|${fields.timestamp}|${fields.sourceIp}|${fields.destinationPort}|${fields.keyId}|${fields.ciphertext}`;
  return crypto.createHash("sha256").update(canonical).digest("hex");
}
function verifyLogChain(logs) {
  if (logs.length === 0) {
    return { valid: true, verifiedCount: 0, brokenSequence: null };
  }
  const ordered = [...logs].sort((a, b) => a.sequence - b.sequence);
  for (let i = 0; i < ordered.length; i += 1) {
    const entry = ordered[i];
    if (i > 0 && entry.prevHash !== ordered[i - 1].integrityHash) {
      return { valid: false, verifiedCount: i, brokenSequence: entry.sequence };
    }
    const expectedHash = computeLogIntegrityHash(entry.prevHash, {
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      sourceIp: entry.sourceIp,
      destinationPort: entry.destinationPort,
      ciphertext: entry.envelope.ciphertext,
      keyId: entry.keyId
    });
    if (expectedHash !== entry.integrityHash) {
      return { valid: false, verifiedCount: i, brokenSequence: entry.sequence };
    }
  }
  return { valid: true, verifiedCount: ordered.length, brokenSequence: null };
}
function generateTotpSecret(byteLength = 20) {
  const bytes = crypto.randomBytes(byteLength);
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = value << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[value >>> bits - 5 & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[value << 5 - bits & 31];
  }
  return output;
}
function base32Decode(secret) {
  const cleaned = secret.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = value << 5 | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push(value >>> bits - 8 & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
function computeTotpCode(secretBase32, timeMs = Date.now(), stepSeconds = 30) {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(timeMs / 1e3 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 15;
  const binary = (hmac[offset] & 127) << 24 | (hmac[offset + 1] & 255) << 16 | (hmac[offset + 2] & 255) << 8 | hmac[offset + 3] & 255;
  const otp = binary % 1e6;
  return otp.toString().padStart(6, "0");
}
function verifyTotpCode(secretBase32, submittedCode, timeMs = Date.now(), windowSteps = 1) {
  const normalized = submittedCode.replace(/\s+/g, "");
  if (!/^\d{6}$/.test(normalized)) {
    return false;
  }
  const submittedBuf = Buffer.from(normalized, "utf8");
  for (let delta = -windowSteps; delta <= windowSteps; delta += 1) {
    const candidate = computeTotpCode(secretBase32, timeMs + delta * 3e4);
    const candidateBuf = Buffer.from(candidate, "utf8");
    if (crypto.timingSafeEqual(submittedBuf, candidateBuf)) {
      return true;
    }
  }
  return false;
}
function hashPasswordScrypt(password, saltHex) {
  const salt = saltHex ?? crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}
function verifyPasswordScrypt(password, storedHash) {
  const parts = storedHash.split(":");
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHex, "hex");
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}
function hashApiKey(rawKey) {
  return crypto.createHash("sha256").update(rawKey).digest("hex");
}

// src/lib/securityEngine.ts
function detectThreatFromTraffic(obs) {
  const sig = (obs.payloadSignature ?? "").toLowerCase();
  if (obs.packetsPerSec >= 18e4) {
    return {
      detected: true,
      category: "ddos_volumetric",
      severity: "critical",
      title: `Volumetric Flood Detected (${Math.round(obs.packetsPerSec / 1e3)}k pps)`,
      mitreTactic: "TA0040 \xB7 Impact (Network Denial of Service)",
      signatureId: "SIG-NET-4001"
    };
  }
  if (sig.includes("union select") || sig.includes("or 1=1") || sig.includes("sqli")) {
    return {
      detected: true,
      category: "sqli_probe",
      severity: "high",
      title: `SQL Injection Payload on Port ${obs.destinationPort}`,
      mitreTactic: "TA0001 \xB7 Initial Access (Exploit Public-Facing App)",
      signatureId: "SIG-WAF-2104"
    };
  }
  if (obs.destinationPort === 22 && obs.packetsPerSec >= 1200) {
    return {
      detected: true,
      category: "ssh_bruteforce",
      severity: "high",
      title: "High-Velocity SSH Credential Brute Force",
      mitreTactic: "TA0006 \xB7 Credential Access (Brute Force)",
      signatureId: "SIG-AUTH-1109"
    };
  }
  if (sig.includes("beacon") || obs.protocol === "DNS" && obs.bytesTransferred > 65e3) {
    return {
      detected: true,
      category: "c2_beacon",
      severity: "critical",
      title: "Suspected C2 Tunneling / Periodic Beacon",
      mitreTactic: "TA0011 \xB7 Command and Control",
      signatureId: "SIG-DNS-3302"
    };
  }
  if (obs.bytesTransferred >= 85e6) {
    return {
      detected: true,
      category: "data_exfiltration",
      severity: "critical",
      title: "Anomalous Outbound Data Exfiltration Spike",
      mitreTactic: "TA0010 \xB7 Exfiltration",
      signatureId: "SIG-DLP-5018"
    };
  }
  if ((obs.destinationPort === 445 || obs.destinationPort === 3389) && obs.packetsPerSec >= 400) {
    return {
      detected: true,
      category: "lateral_movement",
      severity: "medium",
      title: `East-West Lateral Movement Probe (:${obs.destinationPort})`,
      mitreTactic: "TA0008 \xB7 Lateral Movement",
      signatureId: "SIG-INT-2840"
    };
  }
  return { detected: false };
}
var SEVERITY_MAP = {
  critical: 10,
  high: 8,
  medium: 5,
  low: 2
};
function severityRank(level) {
  return SEVERITY_MAP[level];
}
function formatSiemEvent(alert, format) {
  if (format === "CEF") {
    const sevNum = SEVERITY_MAP[alert.severity];
    const cleanTitle = alert.title.replace(/[|=\\]/g, " ");
    return `CEF:0|SentinelGrid|SOC-Engine|1.0|${alert.signatureId}|${cleanTitle}|${sevNum}|src=${alert.sourceIp} dst=${alert.destinationAsset} dpt=${alert.destinationPort} proto=${alert.protocol} act=${alert.status} cs1Label=MitreTactic cs1=${alert.mitreTactic}`;
  }
  if (format === "LEEF") {
    return `LEEF:2.0|SentinelGrid|SOC-Engine|1.0|${alert.signatureId}|devTime=${alert.timestamp}	sev=${SEVERITY_MAP[alert.severity]}	src=${alert.sourceIp}	dst=${alert.destinationAsset}	dstPort=${alert.destinationPort}	proto=${alert.protocol}	action=${alert.status}`;
  }
  return JSON.stringify(
    {
      schema: "sentinelgrid.siem.v1",
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
      bytesTransferred: alert.bytesTransferred
    },
    null,
    2
  );
}
function calculateClusterScale(currentThroughputGbps, eventsPerSec, current) {
  const perNodeCapacityGbps = 12.5;
  const requiredNodes = Math.ceil(
    currentThroughputGbps / perNodeCapacityGbps * (100 / Math.max(30, current.targetLoadPercent))
  );
  const nextActiveNodes = current.autoScaleEnabled ? Math.max(current.minNodes, Math.min(current.maxNodes, requiredNodes)) : current.activeNodes;
  const totalCapacity = Number((nextActiveNodes * perNodeCapacityGbps).toFixed(1));
  const avgCpu = Math.min(96, Math.max(14, Math.round(currentThroughputGbps / totalCapacity * 88)));
  const avgMem = Math.min(92, Math.max(22, Math.round(avgCpu * 0.82 + 10)));
  const bufferPct = Math.min(94, Math.max(4, Math.round(eventsPerSec / (nextActiveNodes * 18e4) * 72)));
  const regions = ["ap-southeast-1", "ap-southeast-3", "eu-central-1", "us-east-1"];
  const nodes = Array.from({ length: nextActiveNodes }, (_, idx) => {
    const jitter = idx * 7 % 9 - 4;
    return {
      id: `sg-ingest-${String(idx + 1).padStart(2, "0")}`,
      region: regions[idx % regions.length],
      status: idx >= current.activeNodes ? "scaling" : "active",
      cpuPercent: Math.min(98, Math.max(10, avgCpu + jitter)),
      memoryPercent: Math.min(95, Math.max(18, avgMem + jitter)),
      ingestGbps: Number((currentThroughputGbps / nextActiveNodes).toFixed(2)),
      eventsPerSec: Math.round(eventsPerSec / nextActiveNodes)
    };
  });
  return {
    ...current,
    activeNodes: nextActiveNodes,
    maxCapacityGbps: totalCapacity,
    kafkaBufferPercent: bufferPct,
    nodes
  };
}
function buildWeeklyReport(params) {
  const { id, generatedAt, periodLabel, trafficHistory, alerts, logs, complianceControls } = params;
  const totalPps = trafficHistory.reduce((acc, s) => acc + s.packetsPerSec, 0);
  const scaledTotalPackets = Math.max(124e5, totalPps * 420);
  const formattedPackets = scaledTotalPackets >= 1e9 ? `${(scaledTotalPackets / 1e9).toFixed(2)}B` : `${(scaledTotalPackets / 1e6).toFixed(1)}M`;
  const criticalMitigated = alerts.filter(
    (a) => (a.severity === "critical" || a.severity === "high") && (a.status === "blocked" || a.status === "mitigated")
  ).length;
  const vectorCounts = /* @__PURE__ */ new Map();
  for (const alert of alerts) {
    vectorCounts.set(alert.category, (vectorCounts.get(alert.category) ?? 0) + 1);
  }
  const topVectors = Array.from(vectorCounts.entries()).map(([category, count]) => ({ category, count })).sort((a, b) => b.count - a.count).slice(0, 4);
  const avgCompliance = complianceControls.length > 0 ? Math.round(
    complianceControls.reduce((sum, c) => sum + c.coveragePercent, 0) / complianceControls.length
  ) : 100;
  const e2eCount = logs.filter((l) => l.envelope.algorithm === "AES-256-GCM").length;
  const e2ePct = logs.length > 0 ? Math.round(e2eCount / logs.length * 100) : 100;
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
    summaryNote: `Automated digest covering ${alerts.length} detected incidents, ${e2eCount} AES-256-GCM sealed logs, and ${avgCompliance}% framework compliance.`
  };
}
function isSafeExternalWebhookUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      return false;
    }
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0" || host === "::1" || host.startsWith("169.254.") || host.startsWith("10.") || host.startsWith("192.168.")) {
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

// src/lib/userControl.ts
var VALID_COMPLAINT_CATEGORIES = [
  "access_mfa",
  "security_incident",
  "performance_bug",
  "policy_request",
  "other"
];
var VALID_COMPLAINT_STATUSES = ["open", "in_review", "resolved"];
var VALID_SEVERITIES = ["critical", "high", "medium", "low"];
function isValidComplaintCategory(value) {
  return typeof value === "string" && VALID_COMPLAINT_CATEGORIES.includes(value);
}
function isValidComplaintStatus(value) {
  return typeof value === "string" && VALID_COMPLAINT_STATUSES.includes(value);
}
function validateComplaintInput(input) {
  const cleanCategory = isValidComplaintCategory(input.category) ? input.category : "other";
  const cleanSeverity = typeof input.severity === "string" && VALID_SEVERITIES.includes(input.severity) ? input.severity : "medium";
  const cleanSubject = (input.subject || "").trim().slice(0, 140);
  const cleanDescription = (input.description || "").trim().slice(0, 1200);
  if (cleanSubject.length < 3) {
    return {
      valid: false,
      error: "Subject must be at least 3 characters",
      cleanCategory,
      cleanSeverity,
      cleanSubject,
      cleanDescription
    };
  }
  if (cleanDescription.length < 10) {
    return {
      valid: false,
      error: "Description must be at least 10 characters",
      cleanCategory,
      cleanSeverity,
      cleanSubject,
      cleanDescription
    };
  }
  return {
    valid: true,
    cleanCategory,
    cleanSeverity,
    cleanSubject,
    cleanDescription
  };
}
var VALID_ROLES = ["admin", "analyst", "viewer"];
function isValidUserRole(value) {
  return typeof value === "string" && VALID_ROLES.includes(value);
}
function validateRegistrationInput(input) {
  const cleanName = (input.fullName || "").trim().slice(0, 80);
  const cleanEmail = (input.email || "").trim().toLowerCase().slice(0, 120);
  const cleanDepartment = (input.department || "SOC Operations").trim().slice(0, 60) || "SOC Operations";
  const password = input.password || "";
  if (cleanName.length < 2) {
    return {
      valid: false,
      error: "Full name must be at least 2 characters",
      cleanName,
      cleanEmail,
      cleanDepartment
    };
  }
  if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return {
      valid: false,
      error: "Valid email address is required",
      cleanName,
      cleanEmail,
      cleanDepartment
    };
  }
  if (password.length < 8) {
    return {
      valid: false,
      error: "Password must be at least 8 characters",
      cleanName,
      cleanEmail,
      cleanDepartment
    };
  }
  return {
    valid: true,
    cleanName,
    cleanEmail,
    cleanDepartment
  };
}
function summarizeDeviceUserAgent(uaRaw) {
  const ua = (uaRaw || "").trim();
  if (!ua) return "Unknown Device";
  let os2 = "Unknown OS";
  if (/android/i.test(ua)) os2 = "Android";
  else if (/iphone|ipad|ios/i.test(ua)) os2 = "iOS";
  else if (/windows/i.test(ua)) os2 = "Windows";
  else if (/mac os x|macintosh/i.test(ua)) os2 = "macOS";
  else if (/linux/i.test(ua)) os2 = "Linux";
  let browser = "Browser";
  if (/edg\//i.test(ua)) browser = "Edge";
  else if (/chrome|crios/i.test(ua)) browser = "Chrome";
  else if (/firefox|fxios/i.test(ua)) browser = "Firefox";
  else if (/safari/i.test(ua)) browser = "Safari";
  else if (/curl|postman|node|playwright/i.test(ua)) browser = "API / Automation";
  return `${browser} \xB7 ${os2}`;
}
function extractClientIp(forwardedFor, remoteAddr) {
  const raw = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
  if (raw && raw.trim().length > 0) {
    return raw.split(",")[0].trim().slice(0, 64);
  }
  const cleanRemote = (remoteAddr || "127.0.0.1").replace(/^::ffff:/, "");
  return cleanRemote.slice(0, 64);
}
function canUserAuthenticate(status) {
  if (status === "active") return { allowed: true };
  if (status === "pending") {
    return {
      allowed: false,
      reason: "ACCOUNT_PENDING"
    };
  }
  if (status === "suspended") {
    return {
      allowed: false,
      reason: "ACCOUNT_SUSPENDED"
    };
  }
  return {
    allowed: false,
    reason: "ACCOUNT_BLOCKED"
  };
}
function roleDisplayName(role) {
  if (role === "admin") return "SOC Lead Administrator";
  if (role === "analyst") return "SOC Security Analyst";
  return "Security Viewer";
}

// server/app.ts
function generateBackupCodes() {
  const plain = [];
  const hashes = [];
  for (let i = 0; i < 6; i += 1) {
    const code = `${crypto2.randomBytes(2).toString("hex").toUpperCase()}-${crypto2.randomBytes(2).toString("hex").toUpperCase()}`;
    plain.push(code);
    hashes.push(hashApiKey(code));
  }
  return { plain, hashes };
}
function createSocApp(store, hooks = { wsSupported: false }) {
  const app = express();
  app.set("trust proxy", 1);
  app.use((req, res, next) => {
    const anyReq = req;
    if (req.body !== void 0) {
      if (Buffer.isBuffer(req.body)) {
        const raw = req.body.toString("utf8");
        if (req.headers["content-type"]?.includes("application/json")) {
          try {
            req.body = raw ? JSON.parse(raw) : {};
          } catch {
            res.status(400).json({ error: "Invalid JSON request body" });
            return;
          }
        }
      } else if (typeof req.body === "string" && req.headers["content-type"]?.includes("application/json")) {
        try {
          req.body = req.body ? JSON.parse(req.body) : {};
        } catch {
          res.status(400).json({ error: "Invalid JSON request body" });
          return;
        }
      }
      anyReq._body = true;
    }
    next();
  });
  app.use(express.json({ limit: "1mb" }));
  const broadcastEvent = hooks.broadcastEvent ?? (() => {
  });
  const broadcastAdminEvent = hooks.broadcastAdminEvent ?? (() => {
  });
  const sendUserEvent = hooks.sendUserEvent ?? (() => {
  });
  const revokeUserSockets = hooks.revokeUserSockets ?? (() => {
  });
  const requireAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : void 0;
    const session = store.verifyBearerToken(token);
    if (!session) {
      res.status(401).json({ error: "Unauthorized: valid MFA session token required" });
      return;
    }
    req.socSession = session;
    next();
  };
  const requireAdmin = (req, res, next) => {
    const session = req.socSession;
    if (!session || session.roleKey !== "admin") {
      res.status(403).json({ error: "Forbidden: Administrator role required" });
      return;
    }
    next();
  };
  const requireOperatorOrAdmin = (req, res, next) => {
    const session = req.socSession;
    if (!session || session.roleKey !== "admin" && session.roleKey !== "analyst") {
      res.status(403).json({ error: "Forbidden: Analyst or Administrator role required" });
      return;
    }
    next();
  };
  app.get("/api/health", (_req, res) => {
    res.json({
      ok: true,
      service: "SentinelGrid SOC",
      runtime: process.env.VERCEL ? "vercel-serverless" : "node-express",
      wsSupported: hooks.wsSupported,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  });
  app.get("/api/auth/status", (_req, res) => {
    res.json({
      initialized: store.admin !== null,
      mfaEnrolled: store.admin?.mfaConfirmed ?? false,
      wsSupported: hooks.wsSupported,
      envOverrideActive: Boolean(
        process.env.ADMIN_PASSCODE && process.env.ADMIN_PASSCODE.trim().length >= 6
      )
    });
  });
  app.post("/api/auth/setup", (req, res) => {
    if (store.admin !== null) {
      res.status(409).json({ error: "Admin workspace has already been initialized" });
      return;
    }
    const { email, password } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    if (!cleanEmail || !cleanEmail.includes("@")) {
      res.status(400).json({ error: "Valid administrator email is required" });
      return;
    }
    if (!password || password.length < 8) {
      res.status(400).json({ error: "Password must be at least 8 characters" });
      return;
    }
    const totpSecret = generateTotpSecret();
    const backup = generateBackupCodes();
    store.admin = {
      email: cleanEmail,
      passwordHash: hashPasswordScrypt(password),
      totpSecret,
      mfaConfirmed: false,
      backupCodeHashes: backup.hashes
    };
    store.persistAccountsToDisk();
    const challengeToken = store.createSignedChallenge({
      userId: "ADMIN-ROOT",
      email: cleanEmail,
      accountType: "admin",
      isInitialSetup: true,
      ttlMs: 10 * 6e4
    });
    const otpauthUri = `otpauth://totp/SentinelGrid:${encodeURIComponent(
      cleanEmail
    )}?secret=${totpSecret}&issuer=SentinelGrid&digits=6&period=30`;
    res.json({
      mfaRequired: true,
      isInitialSetup: true,
      challengeToken,
      totpSecret,
      otpauthUri,
      backupCodes: backup.plain
    });
  });
  app.post("/api/auth/register", (req, res) => {
    const { fullName, email, password, department } = req.body;
    const validation = validateRegistrationInput({ fullName, email, password, department });
    if (!validation.valid) {
      res.status(400).json({ error: validation.error });
      return;
    }
    if (store.admin && store.admin.email === validation.cleanEmail || store.users.some((u) => u.email === validation.cleanEmail)) {
      res.status(409).json({ error: "An account with this email is already registered" });
      return;
    }
    const registeredIp = extractClientIp(
      req.headers["x-forwarded-for"],
      req.socket.remoteAddress
    );
    const deviceInfo = summarizeDeviceUserAgent(req.headers["user-agent"]);
    const created = store.registerUserAccount({
      fullName: validation.cleanName,
      email: validation.cleanEmail,
      department: validation.cleanDepartment,
      password,
      registeredIp,
      deviceInfo
    });
    broadcastAdminEvent("user:registered", {
      user: created.user,
      auditEntry: created.auditEntry,
      notification: created.notification
    });
    res.status(201).json({
      ok: true,
      user: created.user,
      requireAdminApproval: created.user.status === "pending"
    });
  });
  app.post("/api/auth/login", (req, res) => {
    const { email, password, portal } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    if (!cleanEmail || !password) {
      res.status(400).json({ error: "Email and password are required" });
      return;
    }
    const envPass = process.env.ADMIN_PASSCODE?.trim();
    if (store.admin && cleanEmail === store.admin.email) {
      if (portal === "user") {
        res.status(403).json({
          error: "Akun Administrator harus masuk melalui link Portal Admin (/admin)."
        });
        return;
      }
      const passwordValid = envPass && envPass.length >= 6 ? password === envPass : verifyPasswordScrypt(password, store.admin.passwordHash);
      if (!passwordValid) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }
      const isInitialSetup2 = !store.admin.mfaConfirmed;
      const challengeToken2 = store.createSignedChallenge({
        userId: "ADMIN-ROOT",
        email: cleanEmail,
        accountType: "admin",
        isInitialSetup: isInitialSetup2
      });
      if (isInitialSetup2) {
        const backup = generateBackupCodes();
        store.admin.backupCodeHashes = backup.hashes;
        store.persistAccountsToDisk();
        res.json({
          mfaRequired: true,
          isInitialSetup: true,
          challengeToken: challengeToken2,
          totpSecret: store.admin.totpSecret,
          otpauthUri: `otpauth://totp/SentinelGrid:${encodeURIComponent(
            cleanEmail
          )}?secret=${store.admin.totpSecret}&issuer=SentinelGrid&digits=6&period=30`,
          backupCodes: backup.plain
        });
        return;
      }
      res.json({
        mfaRequired: true,
        isInitialSetup: false,
        challengeToken: challengeToken2
      });
      return;
    }
    const user = store.users.find((u) => u.email === cleanEmail);
    if (!user || !verifyPasswordScrypt(password, user.passwordHash)) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }
    if (portal === "admin" && user.role !== "admin") {
      res.status(403).json({
        error: "Akun pengguna silakan masuk melalui link Portal Pengguna (/user)."
      });
      return;
    }
    const accessCheck = canUserAuthenticate(user.status);
    if (!accessCheck.allowed) {
      const errorMessage = accessCheck.reason === "ACCOUNT_PENDING" ? "Akun Anda terdaftar dan sedang menunggu persetujuan & aktivasi dari Admin." : accessCheck.reason === "ACCOUNT_SUSPENDED" ? `Akun Anda ditangguhkan sementara oleh Admin${user.issueNote ? `: ${user.issueNote}` : "."}` : `Akun Anda diblokir oleh Admin${user.issueNote ? `: ${user.issueNote}` : "."}`;
      res.status(403).json({
        error: errorMessage,
        errorCode: accessCheck.reason,
        status: user.status,
        issueNote: user.issueNote
      });
      return;
    }
    const isInitialSetup = !user.mfaConfirmed;
    const challengeToken = store.createSignedChallenge({
      userId: user.id,
      email: user.email,
      accountType: "user",
      isInitialSetup
    });
    if (isInitialSetup) {
      const backup = generateBackupCodes();
      user.backupCodeHashes = backup.hashes;
      store.persistAccountsToDisk();
      res.json({
        mfaRequired: true,
        isInitialSetup: true,
        challengeToken,
        totpSecret: user.totpSecret,
        otpauthUri: `otpauth://totp/SentinelGrid:${encodeURIComponent(
          user.email
        )}?secret=${user.totpSecret}&issuer=SentinelGrid&digits=6&period=30`,
        backupCodes: backup.plain
      });
      return;
    }
    res.json({
      mfaRequired: true,
      isInitialSetup: false,
      challengeToken
    });
  });
  app.post("/api/auth/verify-mfa", (req, res) => {
    const { challengeToken, code } = req.body;
    if (!challengeToken || !code) {
      res.status(400).json({ error: "Challenge token and verification code are required" });
      return;
    }
    const challenge = store.verifySignedChallenge(challengeToken);
    if (!challenge) {
      res.status(401).json({ error: "MFA challenge expired. Please sign in again." });
      return;
    }
    const cleanCode = code.trim().toUpperCase();
    const ipAddress = extractClientIp(
      req.headers["x-forwarded-for"],
      req.socket.remoteAddress
    );
    const deviceInfo = summarizeDeviceUserAgent(req.headers["user-agent"]);
    if (challenge.accountType === "admin") {
      if (!store.admin) {
        res.status(400).json({ error: "Workspace not initialized" });
        return;
      }
      let verified2 = verifyTotpCode(store.admin.totpSecret, cleanCode);
      if (!verified2) {
        const codeHash = hashApiKey(cleanCode);
        const backupIdx = store.admin.backupCodeHashes.indexOf(codeHash);
        if (backupIdx !== -1) {
          store.admin.backupCodeHashes.splice(backupIdx, 1);
          verified2 = true;
        }
      }
      if (!verified2) {
        res.status(401).json({ error: "Invalid 6-digit TOTP or recovery code" });
        return;
      }
      store.admin.mfaConfirmed = true;
      store.persistAccountsToDisk();
      store.challenges.delete(challengeToken);
      const session2 = store.createSignedSession({
        userId: "ADMIN-ROOT",
        email: challenge.email,
        roleKey: "admin",
        userAgent: deviceInfo,
        ipAddress
      });
      res.json({
        token: session2.token,
        session: {
          id: session2.id,
          userId: session2.userId,
          email: session2.email,
          role: session2.role,
          roleKey: session2.roleKey,
          mfaVerified: session2.mfaVerified
        }
      });
      return;
    }
    const user = store.users.find((u) => u.id === challenge.userId);
    if (!user) {
      res.status(401).json({ error: "Account not found" });
      return;
    }
    const accessCheck = canUserAuthenticate(user.status);
    if (!accessCheck.allowed) {
      store.challenges.delete(challengeToken);
      res.status(403).json({
        error: "Account access has been restricted by Administrator.",
        errorCode: accessCheck.reason
      });
      return;
    }
    let verified = verifyTotpCode(user.totpSecret, cleanCode);
    if (!verified) {
      const codeHash = hashApiKey(cleanCode);
      const backupIdx = user.backupCodeHashes.indexOf(codeHash);
      if (backupIdx !== -1) {
        user.backupCodeHashes.splice(backupIdx, 1);
        verified = true;
      }
    }
    if (!verified) {
      res.status(401).json({ error: "Invalid 6-digit TOTP or recovery code" });
      return;
    }
    user.mfaConfirmed = true;
    user.lastLoginAt = (/* @__PURE__ */ new Date()).toISOString();
    store.persistAccountsToDisk();
    store.challenges.delete(challengeToken);
    const session = store.createSignedSession({
      userId: user.id,
      email: user.email,
      roleKey: user.role,
      userAgent: deviceInfo,
      ipAddress
    });
    broadcastAdminEvent("user:updated", {
      user: store.toPublicManagedUser(user),
      sessions: Array.from(store.sessions.values()).map(({ token: _unused, ...rest }) => rest)
    });
    res.json({
      token: session.token,
      session: {
        id: session.id,
        userId: session.userId,
        email: session.email,
        role: session.role,
        roleKey: session.roleKey,
        mfaVerified: session.mfaVerified
      }
    });
  });
  app.post("/api/auth/logout", requireAuth, (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.slice(7).trim();
    if (token) {
      store.revokeToken(token);
    }
    res.json({ ok: true });
  });
  app.get("/api/soc/snapshot", requireAuth, (req, res) => {
    const session = req.socSession;
    if (req.query.live === "1") {
      store.advanceLiveTelemetryIfDue();
    }
    res.json(store.getSnapshot(session));
  });
  app.get("/api/admin/users", requireAuth, requireAdmin, (_req, res) => {
    const publicSessions = Array.from(store.sessions.values()).map(
      ({ token: _unused, ...rest }) => rest
    );
    res.json({
      users: store.users.map((u) => store.toPublicManagedUser(u)),
      accountAuditLogs: store.accountAuditLogs,
      requireAdminApproval: store.requireAdminApproval,
      sessions: publicSessions
    });
  });
  app.patch("/api/admin/settings", requireAuth, requireAdmin, (req, res) => {
    const { requireAdminApproval } = req.body;
    if (typeof requireAdminApproval === "boolean") {
      store.requireAdminApproval = requireAdminApproval;
      store.persistAccountsToDisk();
    }
    broadcastAdminEvent("admin:settings_updated", {
      requireAdminApproval: store.requireAdminApproval
    });
    res.json({ requireAdminApproval: store.requireAdminApproval });
  });
  app.post("/api/admin/users/:id/control", requireAuth, requireAdmin, (req, res) => {
    const session = req.socSession;
    const { action, role, issueFlagged, issueNote } = req.body;
    const validActions = [
      "activate",
      "suspend",
      "block",
      "reset_mfa",
      "revoke_sessions",
      "change_role",
      "update_issue"
    ];
    if (!action || !validActions.includes(action)) {
      res.status(400).json({ error: "Invalid admin control action" });
      return;
    }
    if (action === "change_role" && !isValidUserRole(role)) {
      res.status(400).json({ error: "Invalid role selection" });
      return;
    }
    const result = store.applyAdminUserControl({
      userId: req.params.id,
      actorEmail: session.email,
      actorIp: extractClientIp(req.headers["x-forwarded-for"], req.socket.remoteAddress),
      actorDevice: summarizeDeviceUserAgent(req.headers["user-agent"]),
      action,
      role,
      issueFlagged,
      issueNote
    });
    if (!result) {
      res.status(404).json({ error: "User account not found" });
      return;
    }
    if (result.shouldRevokeWs) {
      revokeUserSockets(result.user.id, result.revokeReason);
    }
    const publicSessions = Array.from(store.sessions.values()).map(
      ({ token: _unused, ...rest }) => rest
    );
    broadcastAdminEvent("user:updated", {
      user: result.user,
      auditEntry: result.auditEntry,
      sessions: publicSessions
    });
    res.json({
      user: result.user,
      auditEntry: result.auditEntry,
      revokedSessionCount: result.revokedSessionCount,
      sessions: publicSessions
    });
  });
  app.post("/api/user/reports", requireAuth, (req, res) => {
    const session = req.socSession;
    const { category, severity, subject, description } = req.body;
    const validation = validateComplaintInput({ category, severity, subject, description });
    if (!validation.valid) {
      res.status(400).json({ error: validation.error });
      return;
    }
    const ipAddress = extractClientIp(
      req.headers["x-forwarded-for"],
      req.socket.remoteAddress
    );
    const deviceInfo = summarizeDeviceUserAgent(req.headers["user-agent"]);
    const created = store.createUserComplaintReport({
      userId: session.userId,
      email: session.email,
      ipAddress,
      deviceInfo,
      category: validation.cleanCategory,
      severity: validation.cleanSeverity,
      subject: validation.cleanSubject,
      description: validation.cleanDescription
    });
    broadcastAdminEvent("user:report_created", created);
    if (session.roleKey !== "admin") {
      sendUserEvent(session.userId, "user:report_created", { report: created.report });
    }
    res.status(201).json(created);
  });
  app.post("/api/admin/reports/:id/respond", requireAuth, requireAdmin, (req, res) => {
    const session = req.socSession;
    const { status, adminNote } = req.body;
    if (!isValidComplaintStatus(status)) {
      res.status(400).json({ error: "Invalid complaint status" });
      return;
    }
    const updated = store.respondToUserComplaintReport({
      reportId: req.params.id,
      adminEmail: session.email,
      status,
      adminNote
    });
    if (!updated) {
      res.status(404).json({ error: "User report not found" });
      return;
    }
    broadcastAdminEvent("user:report_updated", { report: updated.report });
    if (updated.report.userId !== "ADMIN-ROOT") {
      sendUserEvent(updated.report.userId, "user:report_updated", {
        report: updated.report,
        notification: updated.notification
      });
    }
    res.json(updated);
  });
  app.post("/api/soc/threats/simulate", requireAuth, requireOperatorOrAdmin, (req, res) => {
    const { category } = req.body;
    const validCategories = [
      "ddos_volumetric",
      "sqli_probe",
      "ssh_bruteforce",
      "c2_beacon",
      "data_exfiltration",
      "lateral_movement"
    ];
    const chosen = category && validCategories.includes(category) ? category : validCategories[Math.floor(Math.random() * validCategories.length)];
    const result = store.triggerThreatScenario(chosen);
    broadcastEvent("threat:detected", result);
    res.json(result);
  });
  app.post("/api/soc/threats/simulation-mode", requireAuth, requireOperatorOrAdmin, (req, res) => {
    const { running, scenario } = req.body;
    const validScenarios = [
      "mixed",
      "ddos_volumetric",
      "sqli_probe",
      "ssh_bruteforce",
      "c2_beacon",
      "data_exfiltration",
      "lateral_movement"
    ];
    if (scenario && validScenarios.includes(scenario)) {
      store.simulation.scenario = scenario;
    }
    if (typeof running === "boolean") {
      store.simulation.running = running;
    }
    let firstWave = null;
    if (store.simulation.running) {
      const cat = store.simulation.scenario === "mixed" ? "ddos_volumetric" : store.simulation.scenario;
      firstWave = store.triggerThreatScenario(cat);
      broadcastEvent("threat:detected", firstWave);
    }
    broadcastEvent("simulation:state", { simulation: store.simulation });
    res.json({ simulation: store.simulation, firstWave });
  });
  app.post("/api/soc/alerts/:id/mitigate", requireAuth, requireOperatorOrAdmin, (req, res) => {
    const { id } = req.params;
    const { action } = req.body;
    const alert = store.alerts.find((a) => a.id === id);
    if (!alert) {
      res.status(404).json({ error: "Alert not found" });
      return;
    }
    if (action === "block") {
      alert.status = "blocked";
      alert.acknowledged = true;
    } else if (action === "mitigate") {
      alert.status = "mitigated";
      alert.acknowledged = true;
    } else {
      alert.acknowledged = true;
    }
    for (const notif of store.notifications) {
      if (notif.alertId === alert.id) {
        notif.read = true;
      }
    }
    broadcastEvent("alert:updated", { alert });
    res.json({ alert });
  });
  app.post("/api/soc/notifications/mark-read", requireAuth, (_req, res) => {
    store.notifications = [];
    res.json({ notifications: store.notifications });
  });
  app.post("/api/soc/logs/decrypt", requireAuth, requireOperatorOrAdmin, (req, res) => {
    const { logIds } = req.body;
    const targets = Array.isArray(logIds) && logIds.length > 0 ? store.encryptedLogs.filter((l) => logIds.includes(l.id)) : store.encryptedLogs.slice(0, 25);
    const decrypted = {};
    for (const entry of targets) {
      const keyHex = store.encryptionKeys.get(entry.keyId);
      if (keyHex) {
        try {
          decrypted[entry.id] = decryptTrafficPayload(entry.envelope, keyHex);
        } catch {
        }
      }
    }
    res.json({ decrypted });
  });
  app.post("/api/soc/logs/verify-chain", requireAuth, (_req, res) => {
    const result = verifyLogChain(store.encryptedLogs);
    res.json(result);
  });
  app.post("/api/soc/logs/rotate-key", requireAuth, requireAdmin, (_req, res) => {
    const nextNum = store.encryptionKeys.size + 1;
    const newKeyId = `KEY-2026-${String(nextNum).padStart(2, "0")}`;
    store.encryptionKeys.set(newKeyId, generateEncryptionKeyHex());
    store.activeKeyId = newKeyId;
    res.json({ activeKeyId: newKeyId, totalKeysHeld: store.encryptionKeys.size });
  });
  app.post("/api/soc/siem/keys", requireAuth, requireAdmin, (req, res) => {
    const { label, scopes } = req.body;
    const cleanLabel = (label || "").trim();
    if (!cleanLabel || cleanLabel.length < 3) {
      res.status(400).json({ error: "API key label must be at least 3 characters" });
      return;
    }
    const rawSecret = `sg_live_${crypto2.randomBytes(18).toString("hex")}`;
    const newKey = {
      id: `key-${Date.now()}`,
      label: cleanLabel,
      prefix: rawSecret.slice(0, 14),
      scopes: Array.isArray(scopes) && scopes.length > 0 ? scopes : ["logs:read", "alerts:stream"],
      createdAt: (/* @__PURE__ */ new Date()).toISOString(),
      lastUsedAt: null,
      revoked: false,
      keyHash: hashApiKey(rawSecret)
    };
    store.siemApiKeys.unshift(newKey);
    const { keyHash: _unused, ...publicMeta } = newKey;
    res.json({ apiKey: publicMeta, rawSecret });
  });
  app.delete("/api/soc/siem/keys/:id", requireAuth, requireAdmin, (req, res) => {
    const target = store.siemApiKeys.find((k) => k.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: "API key not found" });
      return;
    }
    target.revoked = true;
    res.json({ ok: true, id: target.id });
  });
  app.patch("/api/soc/siem/connectors/:id", requireAuth, (req, res) => {
    const connector = store.siemConnectors.find((c) => c.id === req.params.id);
    if (!connector) {
      res.status(404).json({ error: "SIEM connector not found" });
      return;
    }
    const { enabled, format, endpointUrl } = req.body;
    if (endpointUrl !== void 0) {
      if (!isSafeExternalWebhookUrl(endpointUrl)) {
        res.status(400).json({ error: "Invalid or restricted endpoint URL (SSRF policy)" });
        return;
      }
      connector.endpointUrl = endpointUrl.trim();
    }
    if (typeof enabled === "boolean") {
      connector.enabled = enabled;
      connector.lastStatus = enabled ? "healthy" : "standby";
    }
    if (format && ["JSON", "CEF", "LEEF"].includes(format)) {
      connector.format = format;
    }
    res.json({ connector });
  });
  app.post("/api/soc/siem/connectors/:id/test", requireAuth, (req, res) => {
    const connector = store.siemConnectors.find((c) => c.id === req.params.id);
    if (!connector) {
      res.status(404).json({ error: "SIEM connector not found" });
      return;
    }
    const sampleAlert = store.alerts[0];
    const formattedPayload = sampleAlert ? formatSiemEvent(sampleAlert, connector.format) : "{}";
    connector.eventsSynced += 1;
    connector.lastSyncAt = (/* @__PURE__ */ new Date()).toISOString();
    connector.lastStatus = "healthy";
    connector.enabled = true;
    res.json({
      connector,
      dispatchedPayload: formattedPayload,
      deliveryLatencyMs: connector.avgLatencyMs
    });
  });
  app.patch("/api/soc/integrations/:id", requireAuth, (req, res) => {
    const item = store.integrations.find((i) => i.id === req.params.id);
    if (!item) {
      res.status(404).json({ error: "Integration not found" });
      return;
    }
    const { enabled, syncMode } = req.body;
    if (typeof enabled === "boolean") item.enabled = enabled;
    if (syncMode === "realtime" || syncMode === "batched") item.syncMode = syncMode;
    res.json({ integration: item });
  });
  app.post("/api/soc/rules", requireAuth, (req, res) => {
    const { name, minSeverity, action, channels } = req.body;
    if (!name || name.trim().length < 3) {
      res.status(400).json({ error: "Rule name is required" });
      return;
    }
    const rule = {
      id: `rule-${Date.now()}`,
      name: name.trim(),
      minSeverity: minSeverity ?? "high",
      action: action ?? "block_ip_and_notify",
      channels: Array.isArray(channels) && channels.length > 0 ? channels : ["Slack #sec-ops-alerts"],
      enabled: true,
      triggerCount: 0,
      lastTriggeredAt: null
    };
    store.automationRules.unshift(rule);
    res.json({ rule });
  });
  app.patch("/api/soc/rules/:id", requireAuth, (req, res) => {
    const rule = store.automationRules.find((r) => r.id === req.params.id);
    if (!rule) {
      res.status(404).json({ error: "Rule not found" });
      return;
    }
    const { enabled } = req.body;
    if (typeof enabled === "boolean") rule.enabled = enabled;
    res.json({ rule });
  });
  app.post("/api/soc/reports/generate", requireAuth, (_req, res) => {
    const now = /* @__PURE__ */ new Date();
    const start = new Date(now.getTime() - 7 * 864e5);
    const periodLabel = `${start.toISOString().slice(0, 10)} \u2014 ${now.toISOString().slice(0, 10)}`;
    const report = buildWeeklyReport({
      id: store.nextReportId(),
      generatedAt: now.toISOString(),
      periodLabel,
      trafficHistory: store.trafficHistory,
      alerts: store.alerts,
      logs: store.encryptedLogs,
      complianceControls: store.complianceControls
    });
    store.weeklyReports.unshift(report);
    res.json({ report });
  });
  app.patch("/api/soc/reports/schedule", requireAuth, (req, res) => {
    const { enabled, dayOfWeek, timeUtc, recipients } = req.body;
    if (typeof enabled === "boolean") store.reportSchedule.enabled = enabled;
    if (dayOfWeek && ["Monday", "Friday", "Sunday"].includes(dayOfWeek)) {
      store.reportSchedule.dayOfWeek = dayOfWeek;
    }
    if (timeUtc && /^\d{2}:\d{2}$/.test(timeUtc)) {
      store.reportSchedule.timeUtc = timeUtc;
    }
    if (Array.isArray(recipients)) {
      store.reportSchedule.recipients = recipients.filter((r) => r.includes("@")).slice(0, 10);
    }
    res.json({ reportSchedule: store.reportSchedule });
  });
  app.patch("/api/soc/cluster", requireAuth, (req, res) => {
    const { autoScaleEnabled, maxNodes, targetLoadPercent, stressTestActive } = req.body;
    if (typeof autoScaleEnabled === "boolean") store.cluster.autoScaleEnabled = autoScaleEnabled;
    if (typeof maxNodes === "number" && maxNodes >= 4 && maxNodes <= 64) {
      store.cluster.maxNodes = maxNodes;
    }
    if (typeof targetLoadPercent === "number" && targetLoadPercent >= 40 && targetLoadPercent <= 90) {
      store.cluster.targetLoadPercent = targetLoadPercent;
    }
    if (typeof stressTestActive === "boolean") {
      store.cluster.stressTestActive = stressTestActive;
    }
    const latest = store.trafficHistory[store.trafficHistory.length - 1];
    const baseGbps = (latest?.inboundGbps ?? 24) + (latest?.outboundGbps ?? 14);
    const effectiveGbps = store.cluster.stressTestActive ? Math.max(92, baseGbps * 3.1) : baseGbps;
    const effectivePps = store.cluster.stressTestActive ? 88e4 : latest?.packetsPerSec ?? 24e4;
    store.cluster = calculateClusterScale(effectiveGbps, effectivePps, store.cluster);
    broadcastEvent("cluster:scaled", { cluster: store.cluster });
    res.json({ cluster: store.cluster });
  });
  app.post("/api/soc/mfa/backup-codes", requireAuth, (req, res) => {
    const session = req.socSession;
    const backup = generateBackupCodes();
    if (session.userId === "ADMIN-ROOT") {
      if (!store.admin) {
        res.status(400).json({ error: "Admin account not initialized" });
        return;
      }
      store.admin.backupCodeHashes = backup.hashes;
    } else {
      const user = store.users.find((u) => u.id === session.userId);
      if (!user) {
        res.status(404).json({ error: "User account not found" });
        return;
      }
      user.backupCodeHashes = backup.hashes;
    }
    store.persistAccountsToDisk();
    res.json({ backupCodes: backup.plain, remaining: backup.plain.length });
  });
  app.patch("/api/soc/mfa/policy", requireAuth, requireAdmin, (req, res) => {
    const { requireMfaForDecryption, requireMfaForKeyRotation } = req.body;
    if (typeof requireMfaForDecryption === "boolean") {
      store.mfaPolicy.requireMfaForDecryption = requireMfaForDecryption;
    }
    if (typeof requireMfaForKeyRotation === "boolean") {
      store.mfaPolicy.requireMfaForKeyRotation = requireMfaForKeyRotation;
    }
    store.persistAccountsToDisk();
    res.json({
      mfaPolicy: {
        ...store.mfaPolicy,
        backupCodesRemaining: store.admin?.backupCodeHashes.length ?? 0
      }
    });
  });
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "API endpoint not found" });
  });
  app.use(
    (err, req, res, next) => {
      if (res.headersSent) {
        next(err);
        return;
      }
      if (req.path.startsWith("/api")) {
        const message = err instanceof Error ? err.message : "Internal authentication server error";
        res.status(500).json({ error: message });
        return;
      }
      next(err);
    }
  );
  return app;
}

// server/state.ts
import crypto3 from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
var PROTOCOLS = ["TLS 1.3", "HTTPS", "DNS", "SSH", "QUIC", "gRPC"];
var SecurityWorkspaceStore = class {
  constructor() {
    this.admin = null;
    this.activeKeyId = "KEY-2026-01";
    this.encryptionKeys = /* @__PURE__ */ new Map();
    this.sessions = /* @__PURE__ */ new Map();
    this.challenges = /* @__PURE__ */ new Map();
    this.users = [];
    this.userReports = [];
    this.accountAuditLogs = [];
    this.requireAdminApproval = true;
    this.simulation = {
      running: false,
      scenario: "mixed",
      wavesSent: 0,
      lastTriggeredAt: null
    };
    this.dataDir = process.env.VERCEL ? path.resolve(os.tmpdir(), ".sentinelgrid-data") : path.resolve(process.cwd(), ".sentinelgrid-data");
    this.accountsFile = path.resolve(this.dataDir, "accounts.json");
    this.trafficHistory = [];
    this.alerts = [];
    this.encryptedLogs = [];
    this.siemConnectors = [];
    this.siemApiKeys = [];
    this.integrations = [];
    this.automationRules = [];
    this.complianceControls = [];
    this.weeklyReports = [];
    this.notifications = [];
    this.mfaPolicy = {
      requireMfaForDecryption: true,
      requireMfaForKeyRotation: true
    };
    this.revokedSessionIds = /* @__PURE__ */ new Set();
    this.logSequence = 0;
    this.alertCounter = 1040;
    this.reportCounter = 47;
    this.userCounter = 200;
    this.complaintCounter = 100;
    this.lastLiveTickAt = 0;
    this.lastSimWaveAt = 0;
    this.simWavesCounter = 0;
    const vercelFallbackSeed = process.env.VERCEL_PROJECT_PRODUCTION_URL || process.env.VERCEL_URL || process.env.VERCEL_GIT_COMMIT_SHA || "sentinelgrid-vercel-runtime";
    this.sessionSigningSecret = process.env.SESSION_SECRET?.trim() || (process.env.VERCEL ? crypto3.createHash("sha256").update(`session:${vercelFallbackSeed}`).digest("hex") : crypto3.randomBytes(32).toString("hex"));
    const envKeyHex = process.env.E2E_LOG_KEY?.trim();
    const primaryKeyHex = envKeyHex && /^[0-9a-fA-F]{64}$/.test(envKeyHex) ? envKeyHex : process.env.VERCEL ? crypto3.createHash("sha256").update(`e2e:${vercelFallbackSeed}`).digest("hex") : generateEncryptionKeyHex();
    this.encryptionKeys.set(this.activeKeyId, primaryKeyHex);
    this.loadAccountsFromDisk();
    if (process.env.ADMIN_PASSCODE && process.env.ADMIN_PASSCODE.trim().length >= 6) {
      if (!this.admin) {
        const adminEmail = (process.env.ADMIN_EMAIL || "admin@sentinelgrid.io").trim().toLowerCase();
        this.admin = {
          email: adminEmail,
          passwordHash: hashPasswordScrypt(process.env.ADMIN_PASSCODE.trim()),
          totpSecret: generateTotpSecret(),
          mfaConfirmed: false,
          backupCodeHashes: []
        };
      }
    }
    this.reportSchedule = {
      enabled: true,
      dayOfWeek: "Monday",
      timeUtc: "07:00",
      recipients: ["secops@enterprise.local", "ciso-audit@enterprise.local"],
      includeEncryptedAudit: true,
      frameworks: ["ISO 27001", "SOC 2 Type II", "PCI-DSS 4.0", "GDPR"]
    };
    this.cluster = calculateClusterScale(28.4, 245e3, {
      autoScaleEnabled: true,
      minNodes: 4,
      maxNodes: 24,
      activeNodes: 4,
      targetLoadPercent: 72,
      maxCapacityGbps: 50,
      kafkaBufferPercent: 22,
      stressTestActive: false,
      nodes: []
    });
    this.seedInitialTelemetry();
    this.syncPendingNotificationsFromRegisteredUsers();
  }
  loadAccountsFromDisk() {
    try {
      if (!fs.existsSync(this.accountsFile)) return;
      const raw = fs.readFileSync(this.accountsFile, "utf8");
      const parsed = JSON.parse(raw);
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
      if (typeof parsed.requireAdminApproval === "boolean") {
        this.requireAdminApproval = parsed.requireAdminApproval;
      }
      if (parsed.mfaPolicy) {
        this.mfaPolicy = parsed.mfaPolicy;
      }
    } catch {
    }
  }
  persistAccountsToDisk() {
    try {
      fs.mkdirSync(this.dataDir, { recursive: true, mode: 448 });
      const payload = {
        admin: this.admin,
        users: this.users,
        userReports: this.userReports.slice(0, 200),
        accountAuditLogs: this.accountAuditLogs.slice(0, 200),
        requireAdminApproval: this.requireAdminApproval,
        mfaPolicy: this.mfaPolicy
      };
      const tmpFile = `${this.accountsFile}.tmp`;
      fs.writeFileSync(tmpFile, JSON.stringify(payload, null, 2), { mode: 384 });
      fs.renameSync(tmpFile, this.accountsFile);
    } catch {
    }
  }
  syncPendingNotificationsFromRegisteredUsers() {
    for (const user of this.users) {
      if (user.status === "pending") {
        this.notifications.unshift({
          id: `NTF-REG-${user.id}`,
          timestamp: user.registeredAt,
          title: `Permintaan Akses Pengguna Baru: ${user.fullName}`,
          message: `${user.email} (${user.deviceInfo} \xB7 ${user.registeredIp}) menunggu persetujuan Admin`,
          severity: "medium",
          read: false,
          targetRole: "admin"
        });
      }
    }
    for (const report of this.userReports) {
      if (report.status === "open") {
        this.notifications.unshift({
          id: `NTF-CMP-${report.id}`,
          timestamp: report.createdAt,
          title: `Keluhan Pengguna: ${report.subject}`,
          message: `${report.userFullName} (${report.userEmail}) \xB7 ${report.deviceInfo} (${report.ipAddress})`,
          severity: report.severity,
          read: false,
          reportId: report.id,
          targetRole: "admin"
        });
      }
    }
  }
  seedInitialTelemetry() {
    const now = Date.now();
    for (let i = 29; i >= 0; i -= 1) {
      const ts = new Date(now - i * 2e3).toISOString();
      const baseIn = 22 + Math.sin(i * 0.4) * 5.2 + i % 5 * 0.6;
      const baseOut = 14 + Math.cos(i * 0.35) * 3.1;
      const pps = Math.round((baseIn + baseOut) * 6800);
      this.trafficHistory.push({
        id: `pkt-${i}`,
        timestamp: ts,
        inboundGbps: Number(baseIn.toFixed(2)),
        outboundGbps: Number(baseOut.toFixed(2)),
        packetsPerSec: pps,
        blockedPacketsPerSec: Math.round(pps * 0.018),
        latencyMs: Number((1.4 + i % 4 * 0.15).toFixed(2)),
        anomalyScore: i === 6 ? 78 : 12 + i % 7 * 2,
        protocols: {
          "TLS 1.3": 42,
          HTTPS: 24,
          QUIC: 15,
          gRPC: 9,
          DNS: 7,
          SSH: 3
        }
      });
    }
    const seedThreats = [
      {
        title: "SQL Injection Payload on Port 443",
        category: "sqli_probe",
        severity: "high",
        status: "blocked",
        sourceIp: "45.155.205.91",
        sourceGeo: "Amsterdam, NL",
        destinationAsset: "api-gateway-edge-02",
        destinationPort: 443,
        protocol: "HTTPS",
        packetsMatched: 1480,
        bytesTransferred: 924e3,
        mitreTactic: "TA0001 \xB7 Initial Access",
        signatureId: "SIG-WAF-2104",
        summary: "Automated UNION SELECT signature dropped at edge WAF before upstream routing.",
        autoMitigated: true,
        acknowledged: true
      },
      {
        title: "High-Velocity SSH Credential Brute Force",
        category: "ssh_bruteforce",
        severity: "high",
        status: "active",
        sourceIp: "185.220.101.44",
        sourceGeo: "Frankfurt, DE",
        destinationAsset: "bastion-ap-southeast",
        destinationPort: 22,
        protocol: "SSH",
        packetsMatched: 9420,
        bytesTransferred: 231e4,
        mitreTactic: "TA0006 \xB7 Credential Access",
        signatureId: "SIG-AUTH-1109",
        summary: "Sustained 1,850 auth attempts/min targeting administrative SSH bastion.",
        autoMitigated: false,
        acknowledged: false
      },
      {
        title: "Suspected C2 Tunneling / Periodic Beacon",
        category: "c2_beacon",
        severity: "critical",
        status: "investigating",
        sourceIp: "103.149.28.17",
        sourceGeo: "Singapore, SG",
        destinationAsset: "dns-resolver-int-03",
        destinationPort: 53,
        protocol: "DNS",
        packetsMatched: 612,
        bytesTransferred: 184500,
        mitreTactic: "TA0011 \xB7 Command and Control",
        signatureId: "SIG-DNS-3302",
        summary: "High-entropy TXT record exfiltration cadence detected every 45 seconds.",
        autoMitigated: false,
        acknowledged: false
      },
      {
        title: "East-West Lateral Movement Probe (:445)",
        category: "lateral_movement",
        severity: "medium",
        status: "mitigated",
        sourceIp: "10.42.18.77",
        sourceGeo: "Internal VPC-Prod",
        destinationAsset: "finance-erp-node-04",
        destinationPort: 445,
        protocol: "TLS 1.3",
        packetsMatched: 520,
        bytesTransferred: 312e3,
        mitreTactic: "TA0008 \xB7 Lateral Movement",
        signatureId: "SIG-INT-2840",
        summary: "SMB port sweep isolated to quarantine VLAN by automated micro-segmentation.",
        autoMitigated: true,
        acknowledged: true
      }
    ];
    seedThreats.forEach((t, idx) => {
      const ts = new Date(now - (idx + 1) * 95e3).toISOString();
      const alert = {
        ...t,
        id: `ALT-${this.alertCounter++}`,
        timestamp: ts
      };
      this.alerts.push(alert);
      this.appendEncryptedLog({
        eventId: alert.id,
        timestamp: ts,
        sourceIp: alert.sourceIp,
        destinationIp: "10.24.8.12",
        destinationPort: alert.destinationPort,
        protocol: alert.protocol,
        action: alert.status === "blocked" ? "DROP" : alert.status === "mitigated" ? "QUARANTINE" : "ALLOW",
        bytes: alert.bytesTransferred,
        tlsCipher: "TLS_AES_256_GCM_SHA384",
        userAgentOrProcess: alert.destinationAsset,
        threatSignature: alert.signatureId
      }, alert.severity);
    });
    for (let i = 0; i < 6; i += 1) {
      const ts = new Date(now - (i + 1) * 18e3).toISOString();
      this.appendEncryptedLog(
        {
          eventId: `FLW-${8100 + i}`,
          timestamp: ts,
          sourceIp: `172.16.40.${20 + i}`,
          destinationIp: "10.24.0.15",
          destinationPort: i % 2 === 0 ? 443 : 8443,
          protocol: PROTOCOLS[i % PROTOCOLS.length],
          action: "ALLOW",
          bytes: 18400 + i * 3200,
          tlsCipher: "TLS_AES_256_GCM_SHA384",
          userAgentOrProcess: "envoy-mesh-proxy",
          threatSignature: null
        },
        "low"
      );
    }
    this.notifications = this.alerts.filter((a) => !a.acknowledged).map((a) => ({
      id: `NTF-${a.id}`,
      timestamp: a.timestamp,
      title: a.title,
      message: `${a.sourceIp} -> ${a.destinationAsset} (:${a.destinationPort})`,
      severity: a.severity,
      read: false,
      alertId: a.id
    }));
    this.siemConnectors = [
      {
        id: "siem-splunk",
        name: "Enterprise Splunk HEC",
        vendor: "Splunk HEC",
        endpointUrl: "https://splunk-hec.corp-soc.example/services/collector/event",
        format: "JSON",
        enabled: true,
        eventsSynced: 482910,
        lastSyncAt: new Date(now - 12e3).toISOString(),
        lastStatus: "healthy",
        avgLatencyMs: 38
      },
      {
        id: "siem-elastic",
        name: "Elastic Security Cluster",
        vendor: "Elastic SIEM",
        endpointUrl: "https://elastic-ingest.corp-soc.example:9200/_bulk",
        format: "JSON",
        enabled: true,
        eventsSynced: 319440,
        lastSyncAt: new Date(now - 18e3).toISOString(),
        lastStatus: "healthy",
        avgLatencyMs: 44
      },
      {
        id: "siem-qradar",
        name: "IBM QRadar Collector",
        vendor: "IBM QRadar",
        endpointUrl: "https://qradar-gw.corp-soc.example/api/leef/ingest",
        format: "LEEF",
        enabled: false,
        eventsSynced: 94120,
        lastSyncAt: new Date(now - 36e5).toISOString(),
        lastStatus: "standby",
        avgLatencyMs: 61
      },
      {
        id: "siem-sentinel",
        name: "Microsoft Sentinel Workspace",
        vendor: "Microsoft Sentinel",
        endpointUrl: "https://sentinel-dce.corp-soc.example/dataCollectionRules/cef",
        format: "CEF",
        enabled: true,
        eventsSynced: 215800,
        lastSyncAt: new Date(now - 9e3).toISOString(),
        lastStatus: "healthy",
        avgLatencyMs: 52
      }
    ];
    const seedRaw1 = "sg_live_splunk_9921a8f0c441e882b";
    const seedRaw2 = "sg_live_elastic_4410d7b2a903f112c";
    this.siemApiKeys = [
      {
        id: "key-1",
        label: "Splunk Production Forwarder",
        prefix: seedRaw1.slice(0, 14),
        scopes: ["logs:read", "alerts:stream", "siem:export"],
        createdAt: new Date(now - 14 * 864e5).toISOString(),
        lastUsedAt: new Date(now - 12e3).toISOString(),
        revoked: false,
        keyHash: hashApiKey(seedRaw1)
      },
      {
        id: "key-2",
        label: "Elastic SOC Bridge",
        prefix: seedRaw2.slice(0, 14),
        scopes: ["alerts:stream", "reports:read"],
        createdAt: new Date(now - 7 * 864e5).toISOString(),
        lastUsedAt: new Date(now - 18e3).toISOString(),
        revoked: false,
        keyHash: hashApiKey(seedRaw2)
      }
    ];
    this.integrations = [
      {
        id: "int-slack",
        name: "Slack #sec-ops-alerts",
        category: "messaging",
        description: "Instant threat cards & interactive block-IP actions for SOC analysts.",
        enabled: true,
        syncMode: "realtime",
        eventsDispatched: 1420,
        lastDeliveredAt: new Date(now - 95e3).toISOString()
      },
      {
        id: "int-pagerduty",
        name: "PagerDuty On-Call Escalation",
        category: "incident",
        description: "Automated 24/7 paging for Critical severity DDoS and C2 alerts.",
        enabled: true,
        syncMode: "realtime",
        eventsDispatched: 118,
        lastDeliveredAt: new Date(now - 31e4).toISOString()
      },
      {
        id: "int-cloudflare",
        name: "Cloudflare WAF Edge Sync",
        category: "waf",
        description: "Pushes blocked attacker CIDRs directly to global edge firewall rules.",
        enabled: true,
        syncMode: "realtime",
        eventsDispatched: 642,
        lastDeliveredAt: new Date(now - 95e3).toISOString()
      },
      {
        id: "int-jira",
        name: "Jira Security Compliance",
        category: "ticketing",
        description: "Creates audit-linked remediation tickets for High/Critical incidents.",
        enabled: false,
        syncMode: "batched",
        eventsDispatched: 89,
        lastDeliveredAt: new Date(now - 864e5).toISOString()
      }
    ];
    this.automationRules = [
      {
        id: "rule-1",
        name: "Auto-Block Critical Edge Floods & C2",
        minSeverity: "critical",
        action: "block_ip_and_notify",
        channels: ["Cloudflare WAF", "Slack #sec-ops-alerts", "PagerDuty"],
        enabled: true,
        triggerCount: 28,
        lastTriggeredAt: new Date(now - 19e4).toISOString()
      },
      {
        id: "rule-2",
        name: "Escalate High-Severity Probes to SIEM",
        minSeverity: "high",
        action: "siem_escalate",
        channels: ["Splunk HEC", "Elastic SIEM", "Slack #sec-ops-alerts"],
        enabled: true,
        triggerCount: 74,
        lastTriggeredAt: new Date(now - 95e3).toISOString()
      },
      {
        id: "rule-3",
        name: "Isolate East-West Lateral Movement",
        minSeverity: "medium",
        action: "quarantine_host",
        channels: ["Internal Micro-Segmentation", "Jira Security"],
        enabled: true,
        triggerCount: 14,
        lastTriggeredAt: new Date(now - 38e4).toISOString()
      }
    ];
    this.complianceControls = [
      {
        framework: "ISO 27001",
        status: "compliant",
        coveragePercent: 98,
        lastAuditedAt: new Date(now - 432e5).toISOString(),
        evidenceSummary: "A.12.4 E2E AES-256-GCM encrypted logging & A.9.4 MFA enforced."
      },
      {
        framework: "SOC 2 Type II",
        status: "compliant",
        coveragePercent: 97,
        lastAuditedAt: new Date(now - 432e5).toISOString(),
        evidenceSummary: "CC7.2 Continuous anomaly detection & automated SIEM archival."
      },
      {
        framework: "PCI-DSS 4.0",
        status: "compliant",
        coveragePercent: 96,
        lastAuditedAt: new Date(now - 864e5).toISOString(),
        evidenceSummary: "Req 10.3 Tamper-evident SHA-256 log chain & Req 8.4 TOTP MFA."
      },
      {
        framework: "GDPR",
        status: "compliant",
        coveragePercent: 99,
        lastAuditedAt: new Date(now - 864e5).toISOString(),
        evidenceSummary: "Art. 32 End-to-end encryption of packet telemetry & key rotation."
      }
    ];
    const initialReport = buildWeeklyReport({
      id: `RPT-W${this.reportCounter}`,
      generatedAt: new Date(now - 2 * 864e5).toISOString(),
      periodLabel: "2026-11-13 \u2014 2026-11-20",
      trafficHistory: this.trafficHistory,
      alerts: this.alerts,
      logs: this.encryptedLogs,
      complianceControls: this.complianceControls
    });
    this.weeklyReports.push(initialReport);
  }
  appendEncryptedLog(payload, severity) {
    this.logSequence += 1;
    const prevHash = this.encryptedLogs.length > 0 ? this.encryptedLogs[0].integrityHash : "GENESIS";
    const keyHex = this.encryptionKeys.get(this.activeKeyId);
    const envelope = encryptTrafficPayload(payload, keyHex, this.activeKeyId);
    const integrityHash = computeLogIntegrityHash(prevHash, {
      sequence: this.logSequence,
      timestamp: payload.timestamp,
      sourceIp: payload.sourceIp,
      destinationPort: payload.destinationPort,
      ciphertext: envelope.ciphertext,
      keyId: this.activeKeyId
    });
    const entry = {
      id: `LOG-${String(this.logSequence).padStart(5, "0")}`,
      sequence: this.logSequence,
      timestamp: payload.timestamp,
      sourceIp: payload.sourceIp,
      destinationPort: payload.destinationPort,
      protocol: payload.protocol,
      severity,
      keyId: this.activeKeyId,
      prevHash,
      integrityHash,
      envelope
    };
    this.encryptedLogs.unshift(entry);
    if (this.encryptedLogs.length > 120) {
      this.encryptedLogs.length = 120;
    }
    return entry;
  }
  generateLiveTrafficTick() {
    const nowIso = (/* @__PURE__ */ new Date()).toISOString();
    const spikeFactor = this.cluster.stressTestActive ? 3.4 : 1;
    const jitter = (Math.random() - 0.45) * 4.5;
    const inboundGbps = Number(Math.max(8.5, (24.5 + jitter) * spikeFactor).toFixed(2));
    const outboundGbps = Number(Math.max(4.2, (14.2 + jitter * 0.5) * spikeFactor).toFixed(2));
    const packetsPerSec = Math.round((inboundGbps + outboundGbps) * 7200);
    const blockedPacketsPerSec = Math.round(packetsPerSec * (this.cluster.stressTestActive ? 0.08 : 0.016));
    const latencyMs = Number((this.cluster.stressTestActive ? 3.1 : 1.35 + Math.random() * 0.5).toFixed(2));
    const sample = {
      id: `pkt-${Date.now()}`,
      timestamp: nowIso,
      inboundGbps,
      outboundGbps,
      packetsPerSec,
      blockedPacketsPerSec,
      latencyMs,
      anomalyScore: this.cluster.stressTestActive ? 64 : Math.round(10 + Math.random() * 18),
      protocols: {
        "TLS 1.3": 43,
        HTTPS: 23,
        QUIC: 15,
        gRPC: 9,
        DNS: 7,
        SSH: 3
      }
    };
    this.trafficHistory.push(sample);
    if (this.trafficHistory.length > 60) {
      this.trafficHistory.shift();
    }
    this.cluster = calculateClusterScale(inboundGbps + outboundGbps, packetsPerSec, this.cluster);
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
        destinationIp: "10.24.0.15",
        destinationPort: 443,
        protocol: "TLS 1.3",
        action: "ALLOW",
        bytes: Math.round(inboundGbps * 12500),
        tlsCipher: "TLS_AES_256_GCM_SHA384",
        userAgentOrProcess: "envoy-edge-ingress",
        threatSignature: null
      },
      "low"
    );
    return { sample, newAlert: null, newLog, newNotification: null, cluster: this.cluster };
  }
  triggerThreatScenario(scenario) {
    const nowIso = (/* @__PURE__ */ new Date()).toISOString();
    const geoVariants = {
      ddos_volumetric: [
        { ip: "198.51.100.204", geo: "Bucharest, RO" },
        { ip: "203.0.113.92", geo: "Tokyo, JP" },
        { ip: "192.0.2.177", geo: "New York, US" }
      ],
      sqli_probe: [
        { ip: "91.214.124.88", geo: "Warsaw, PL" },
        { ip: "185.199.108.41", geo: "Frankfurt, DE" },
        { ip: "177.54.148.19", geo: "Sao Paulo, BR" }
      ],
      ssh_bruteforce: [
        { ip: "185.156.73.12", geo: "Sofia, BG" },
        { ip: "51.140.44.83", geo: "London, UK" },
        { ip: "45.155.205.61", geo: "Amsterdam, NL" }
      ],
      c2_beacon: [
        { ip: "103.214.112.55", geo: "Hong Kong, HK" },
        { ip: "103.149.28.99", geo: "Singapore, SG" },
        { ip: "202.12.27.33", geo: "Sydney, AU" }
      ],
      data_exfiltration: [
        { ip: "10.24.19.88", geo: "Internal Subnet-B" },
        { ip: "172.20.14.52", geo: "Jakarta, ID" }
      ],
      lateral_movement: [
        { ip: "10.24.44.19", geo: "Internal Dev-VPC" },
        { ip: "10.42.18.90", geo: "Internal VPC-Prod" }
      ]
    };
    const pool = geoVariants[scenario];
    const originPick = pool[this.alertCounter % pool.length];
    const scenarios = {
      ddos_volumetric: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: "edge-lb-prod-01",
        destinationPort: 443,
        protocol: "QUIC",
        packetsPerSec: 34e4,
        bytesTransferred: 48e6,
        summary: "Distributed UDP/QUIC amplification flood exceeding 340k pps edge threshold.",
        inboundSpikeGbps: 94.6,
        outboundSpikeGbps: 19.4
      },
      sqli_probe: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: "checkout-api-svc",
        destinationPort: 443,
        protocol: "HTTPS",
        packetsPerSec: 210,
        bytesTransferred: 19200,
        payloadSignature: "POST /api/orders?id=1' UNION SELECT * FROM users--",
        summary: "Crafted SQL injection payload probing customer order endpoint.",
        inboundSpikeGbps: 44.8,
        outboundSpikeGbps: 16.2
      },
      ssh_bruteforce: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: "bastion-eu-01",
        destinationPort: 22,
        protocol: "SSH",
        packetsPerSec: 2400,
        bytesTransferred: 84e4,
        summary: "Automated credential stuffing burst targeting OpenSSH administrative port.",
        inboundSpikeGbps: 52.3,
        outboundSpikeGbps: 15.8
      },
      c2_beacon: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: "worker-pod-77a",
        destinationPort: 53,
        protocol: "DNS",
        packetsPerSec: 85,
        bytesTransferred: 142e3,
        payloadSignature: "beacon-c2-exfil-txt",
        summary: "Encoded DNS TXT command-and-control beacon detected on internal pod.",
        inboundSpikeGbps: 38.9,
        outboundSpikeGbps: 28.4
      },
      data_exfiltration: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: "ext-relay-45.9.12.4",
        destinationPort: 8443,
        protocol: "TLS 1.3",
        packetsPerSec: 18500,
        bytesTransferred: 128e6,
        summary: "Unusual 128 MB encrypted outbound transfer outside business hours.",
        inboundSpikeGbps: 34.2,
        outboundSpikeGbps: 71.5
      },
      lateral_movement: {
        sourceIp: originPick.ip,
        sourceGeo: originPick.geo,
        destinationAsset: "vault-kms-02",
        destinationPort: 445,
        protocol: "TLS 1.3",
        packetsPerSec: 650,
        bytesTransferred: 41e4,
        summary: "Unauthorized SMB enumeration scan from non-privileged host toward KMS.",
        inboundSpikeGbps: 46.5,
        outboundSpikeGbps: 21
      }
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
      payloadSignature: chosen.payloadSignature
    });
    const severity = detection.severity ?? "high";
    const triggeredRules = [];
    let autoMitigated = false;
    for (const rule of this.automationRules) {
      if (rule.enabled && severityRank(severity) >= severityRank(rule.minSeverity)) {
        rule.triggerCount += 1;
        rule.lastTriggeredAt = nowIso;
        triggeredRules.push(rule.name);
        if (rule.action === "block_ip_and_notify" || rule.action === "quarantine_host") {
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
    const alert = {
      id: `ALT-${this.alertCounter++}`,
      timestamp: nowIso,
      title: detection.title ?? "Security Anomaly Detected",
      category: detection.category ?? scenario,
      severity,
      status: autoMitigated ? "blocked" : "active",
      sourceIp: chosen.sourceIp,
      sourceGeo: chosen.sourceGeo,
      destinationAsset: chosen.destinationAsset,
      destinationPort: chosen.destinationPort,
      protocol: chosen.protocol,
      packetsMatched: chosen.packetsPerSec,
      bytesTransferred: chosen.bytesTransferred,
      mitreTactic: detection.mitreTactic ?? "TA0001 \xB7 Initial Access",
      signatureId: detection.signatureId ?? "SIG-GEN-9001",
      summary: chosen.summary,
      autoMitigated,
      acknowledged: false
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
        destinationIp: "10.24.0.15",
        destinationPort: alert.destinationPort,
        protocol: alert.protocol,
        action: autoMitigated ? "DROP" : "QUARANTINE",
        bytes: alert.bytesTransferred,
        tlsCipher: "TLS_AES_256_GCM_SHA384",
        userAgentOrProcess: alert.destinationAsset,
        threatSignature: alert.signatureId
      },
      severity
    );
    const notification = {
      id: `NTF-${alert.id}`,
      timestamp: nowIso,
      title: alert.title,
      message: `${alert.sourceIp} -> ${alert.destinationAsset} (:${alert.destinationPort})${autoMitigated ? " \xB7 Auto-blocked" : ""}`,
      severity,
      read: false,
      alertId: alert.id
    };
    this.notifications.unshift(notification);
    if (this.notifications.length > 40) {
      this.notifications.length = 40;
    }
    const spikePps = Math.round(
      (chosen.inboundSpikeGbps + chosen.outboundSpikeGbps) * 7600 + chosen.packetsPerSec
    );
    const trafficSample = {
      id: `pkt-sim-${Date.now()}-${this.alertCounter}`,
      timestamp: nowIso,
      inboundGbps: chosen.inboundSpikeGbps,
      outboundGbps: chosen.outboundSpikeGbps,
      packetsPerSec: spikePps,
      blockedPacketsPerSec: Math.round(spikePps * (autoMitigated ? 0.34 : 0.14)),
      latencyMs: Number((2.8 + Math.random() * 1.6).toFixed(2)),
      anomalyScore: severity === "critical" ? 96 : severity === "high" ? 88 : 74,
      protocols: {
        "TLS 1.3": 34,
        HTTPS: 22,
        QUIC: scenario === "ddos_volumetric" ? 28 : 14,
        gRPC: 8,
        DNS: scenario === "c2_beacon" ? 14 : 6,
        SSH: scenario === "ssh_bruteforce" ? 16 : 2
      }
    };
    this.trafficHistory.push(trafficSample);
    if (this.trafficHistory.length > 60) {
      this.trafficHistory.shift();
    }
    this.cluster = calculateClusterScale(
      chosen.inboundSpikeGbps + chosen.outboundSpikeGbps,
      spikePps,
      this.cluster
    );
    this.simulation = {
      ...this.simulation,
      wavesSent: this.simulation.wavesSent + 1,
      lastTriggeredAt: nowIso
    };
    return {
      alert,
      log,
      notification,
      triggeredRules,
      trafficSample,
      cluster: this.cluster,
      simulation: this.simulation
    };
  }
  toPublicManagedUser(account) {
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
      updatedAt: account.updatedAt
    };
  }
  registerUserAccount(params) {
    this.userCounter += 1;
    const nowIso = (/* @__PURE__ */ new Date()).toISOString();
    const initialStatus = this.requireAdminApproval ? "pending" : "active";
    const id = `USR-${this.userCounter}`;
    const account = {
      id,
      fullName: params.fullName,
      email: params.email,
      department: params.department,
      role: "analyst",
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
      issueNote: "",
      approvedBy: initialStatus === "active" ? "Auto-Policy" : null,
      updatedAt: nowIso
    };
    this.users.unshift(account);
    const auditEntry = {
      id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1e3)}`,
      timestamp: nowIso,
      actorEmail: params.email,
      targetEmail: params.email,
      targetUserId: id,
      action: "user_registered",
      detail: `Registered from ${params.deviceInfo} (status: ${initialStatus})`,
      ipAddress: params.registeredIp,
      deviceInfo: params.deviceInfo
    };
    this.accountAuditLogs.unshift(auditEntry);
    if (this.accountAuditLogs.length > 200) {
      this.accountAuditLogs.length = 200;
    }
    const notification = {
      id: `NTF-REG-${id}`,
      timestamp: nowIso,
      title: `Pendaftaran Akun Baru: ${params.fullName}`,
      message: `${params.email} \xB7 ${params.deviceInfo} (${params.registeredIp}) \u2014 masuk antrean kontrol Admin`,
      severity: "medium",
      read: false,
      targetRole: "admin"
    };
    this.notifications.unshift(notification);
    if (this.notifications.length > 40) {
      this.notifications.length = 40;
    }
    this.persistAccountsToDisk();
    return {
      user: this.toPublicManagedUser(account),
      auditEntry,
      notification
    };
  }
  createUserComplaintReport(params) {
    this.complaintCounter += 1;
    const nowIso = (/* @__PURE__ */ new Date()).toISOString();
    const account = this.users.find((u) => u.id === params.userId);
    const fullName = account?.fullName || (params.userId === "ADMIN-ROOT" ? "SOC Administrator" : params.email);
    const department = account?.department || "SOC Operations";
    const report = {
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
      status: "open",
      adminNote: "",
      handledBy: null,
      createdAt: nowIso,
      updatedAt: nowIso
    };
    this.userReports.unshift(report);
    if (this.userReports.length > 200) {
      this.userReports.length = 200;
    }
    const notification = {
      id: `NTF-CMP-${report.id}`,
      timestamp: nowIso,
      title: `Keluhan Pengguna: ${report.subject}`,
      message: `${report.userFullName} (${report.userEmail}) \xB7 ${report.deviceInfo} (${report.ipAddress})`,
      severity: report.severity,
      read: false,
      reportId: report.id,
      targetRole: "admin"
    };
    this.notifications.unshift(notification);
    if (this.notifications.length > 40) {
      this.notifications.length = 40;
    }
    this.persistAccountsToDisk();
    return { report, notification };
  }
  respondToUserComplaintReport(params) {
    const report = this.userReports.find((r) => r.id === params.reportId);
    if (!report) return null;
    const nowIso = (/* @__PURE__ */ new Date()).toISOString();
    report.status = params.status;
    if (typeof params.adminNote === "string") {
      report.adminNote = params.adminNote.trim().slice(0, 600);
    }
    report.handledBy = params.adminEmail;
    report.updatedAt = nowIso;
    const statusText = params.status === "resolved" ? "Selesai" : params.status === "in_review" ? "Ditinjau Admin" : "Menunggu";
    const notification = {
      id: `NTF-CMP-RES-${report.id}-${Date.now()}`,
      timestamp: nowIso,
      title: `Pembaruan Keluhan: ${report.subject}`,
      message: `Status: ${statusText}${report.adminNote ? ` \xB7 Catatan Admin: ${report.adminNote}` : ""}`,
      severity: params.status === "resolved" ? "low" : "medium",
      read: false,
      reportId: report.id,
      targetRole: "all",
      targetUserId: report.userId
    };
    this.notifications.unshift(notification);
    if (this.notifications.length > 40) {
      this.notifications.length = 40;
    }
    this.persistAccountsToDisk();
    return { report, notification };
  }
  revokeSessionsForUser(userId) {
    let revokedCount = 0;
    for (const [token, sess] of this.sessions.entries()) {
      if (sess.userId === userId) {
        this.sessions.delete(token);
        revokedCount += 1;
      }
    }
    return revokedCount;
  }
  applyAdminUserControl(params) {
    const account = this.users.find((u) => u.id === params.userId);
    if (!account) return null;
    const nowIso = (/* @__PURE__ */ new Date()).toISOString();
    let auditAction = "issue_updated";
    let detail = "";
    let revokedSessionCount = 0;
    let shouldRevokeWs = false;
    let revokeReason = "Session updated by administrator";
    if (params.action === "activate") {
      account.status = "active";
      account.approvedBy = params.actorEmail;
      if (params.issueFlagged === false) {
        account.issueFlagged = false;
        account.issueNote = "";
      }
      auditAction = "user_activated";
      detail = `Account activated by ${params.actorEmail}`;
    } else if (params.action === "suspend") {
      account.status = "suspended";
      account.issueFlagged = true;
      if (typeof params.issueNote === "string" && params.issueNote.trim()) {
        account.issueNote = params.issueNote.trim().slice(0, 240);
      } else if (!account.issueNote) {
        account.issueNote = "Suspended by administrator during incident review";
      }
      revokedSessionCount = this.revokeSessionsForUser(account.id);
      shouldRevokeWs = true;
      revokeReason = account.issueNote;
      auditAction = "user_suspended";
      detail = `Account suspended (${account.issueNote})`;
    } else if (params.action === "block") {
      account.status = "blocked";
      account.issueFlagged = true;
      if (typeof params.issueNote === "string" && params.issueNote.trim()) {
        account.issueNote = params.issueNote.trim().slice(0, 240);
      } else if (!account.issueNote) {
        account.issueNote = "Blocked by administrator due to security policy";
      }
      revokedSessionCount = this.revokeSessionsForUser(account.id);
      shouldRevokeWs = true;
      revokeReason = account.issueNote;
      auditAction = "user_blocked";
      detail = `Account blocked (${account.issueNote})`;
    } else if (params.action === "reset_mfa") {
      account.totpSecret = generateTotpSecret();
      account.mfaConfirmed = false;
      account.backupCodeHashes = [];
      revokedSessionCount = this.revokeSessionsForUser(account.id);
      shouldRevokeWs = true;
      revokeReason = "MFA credentials reset by administrator; re-login required";
      auditAction = "mfa_reset";
      detail = "TOTP MFA reset & active sessions terminated";
    } else if (params.action === "revoke_sessions") {
      revokedSessionCount = this.revokeSessionsForUser(account.id);
      shouldRevokeWs = true;
      revokeReason = "Active sessions terminated by administrator";
      auditAction = "sessions_revoked";
      detail = `Revoked ${revokedSessionCount} active session(s)`;
    } else if (params.action === "change_role" && params.role && isValidUserRole(params.role)) {
      const prevRole = account.role;
      account.role = params.role;
      for (const sess of this.sessions.values()) {
        if (sess.userId === account.id) {
          sess.roleKey = params.role;
          sess.role = roleDisplayName(params.role);
        }
      }
      auditAction = "role_changed";
      detail = `Role changed from ${prevRole} to ${params.role}`;
    } else if (params.action === "update_issue") {
      account.issueFlagged = Boolean(params.issueFlagged);
      account.issueNote = (params.issueNote || "").trim().slice(0, 240);
      auditAction = "issue_updated";
      detail = account.issueFlagged ? `Issue flagged: ${account.issueNote || "Under investigation"}` : "Issue flag cleared by administrator";
    }
    account.updatedAt = nowIso;
    const auditEntry = {
      id: `AUD-${Date.now()}-${Math.floor(Math.random() * 1e3)}`,
      timestamp: nowIso,
      actorEmail: params.actorEmail,
      targetEmail: account.email,
      targetUserId: account.id,
      action: auditAction,
      detail,
      ipAddress: params.actorIp,
      deviceInfo: params.actorDevice
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
      revokeReason
    };
  }
  createSignedChallenge(params) {
    const expiresAt = Date.now() + (params.ttlMs ?? 5 * 6e4);
    const payload = Buffer.from(
      JSON.stringify({
        nonce: crypto3.randomBytes(12).toString("hex"),
        userId: params.userId,
        email: params.email,
        accountType: params.accountType,
        isInitialSetup: params.isInitialSetup,
        expiresAt
      }),
      "utf8"
    ).toString("base64url");
    const sig = crypto3.createHmac("sha256", this.sessionSigningSecret).update(`chal:${payload}`).digest("base64url");
    const challengeToken = `${payload}.${sig}`;
    this.challenges.set(challengeToken, {
      challengeToken,
      userId: params.userId,
      email: params.email,
      accountType: params.accountType,
      expiresAt,
      isInitialSetup: params.isInitialSetup
    });
    return challengeToken;
  }
  verifySignedChallenge(challengeToken) {
    const inMem = this.challenges.get(challengeToken);
    if (inMem) {
      if (inMem.expiresAt < Date.now()) {
        this.challenges.delete(challengeToken);
        return null;
      }
      return inMem;
    }
    const parts = challengeToken.split(".");
    if (parts.length !== 2) return null;
    const [payload, sig] = parts;
    const expectedSig = crypto3.createHmac("sha256", this.sessionSigningSecret).update(`chal:${payload}`).digest("base64url");
    const sigBuf = Buffer.from(sig);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto3.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    try {
      const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      if (!decoded.userId || !decoded.email || !decoded.accountType || !decoded.expiresAt || decoded.expiresAt < Date.now()) {
        return null;
      }
      return {
        challengeToken,
        userId: decoded.userId,
        email: decoded.email,
        accountType: decoded.accountType,
        expiresAt: decoded.expiresAt,
        isInitialSetup: Boolean(decoded.isInitialSetup)
      };
    } catch {
      return null;
    }
  }
  createSignedSession(params) {
    const id = `SES-${crypto3.randomBytes(4).toString("hex").toUpperCase()}`;
    const iat = Date.now();
    const exp = iat + 24 * 60 * 6e4;
    const payload = Buffer.from(
      JSON.stringify({
        id,
        userId: params.userId,
        email: params.email,
        roleKey: params.roleKey,
        iat,
        exp
      }),
      "utf8"
    ).toString("base64url");
    const sig = crypto3.createHmac("sha256", this.sessionSigningSecret).update(payload).digest("base64url");
    const token = `${payload}.${sig}`;
    const nowIso = (/* @__PURE__ */ new Date()).toISOString();
    const session = {
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
      ipAddress: params.ipAddress
    };
    this.sessions.set(token, session);
    return session;
  }
  revokeToken(token) {
    const existing = this.sessions.get(token);
    if (existing) {
      this.revokedSessionIds.add(existing.id);
      this.sessions.delete(token);
      return;
    }
    const parts = token.split(".");
    if (parts.length === 2) {
      try {
        const decoded = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
        if (decoded.id) {
          this.revokedSessionIds.add(decoded.id);
        }
      } catch {
      }
    }
  }
  verifyBearerToken(token) {
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length !== 2) return null;
    const [payload, sig] = parts;
    const expectedSig = crypto3.createHmac("sha256", this.sessionSigningSecret).update(payload).digest("base64url");
    const sigBuf = Buffer.from(sig);
    const expBuf = Buffer.from(expectedSig);
    if (sigBuf.length !== expBuf.length || !crypto3.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    let decoded;
    try {
      decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    } catch {
      return null;
    }
    if (!decoded.id || !decoded.userId || !decoded.email) return null;
    if (decoded.exp && decoded.exp < Date.now()) return null;
    if (this.revokedSessionIds.has(decoded.id)) return null;
    let session = this.sessions.get(token);
    if (!session) {
      const roleKey = decoded.roleKey && isValidUserRole(decoded.roleKey) ? decoded.roleKey : decoded.userId === "ADMIN-ROOT" ? "admin" : "analyst";
      const createdIso = decoded.iat ? new Date(decoded.iat).toISOString() : (/* @__PURE__ */ new Date()).toISOString();
      session = {
        token,
        id: decoded.id,
        userId: decoded.userId,
        email: decoded.email,
        role: roleDisplayName(roleKey),
        roleKey,
        mfaVerified: true,
        createdAt: createdIso,
        lastSeenAt: (/* @__PURE__ */ new Date()).toISOString(),
        userAgent: "Verified Session",
        ipAddress: "serverless-edge"
      };
      this.sessions.set(token, session);
    }
    if (session.userId !== "ADMIN-ROOT") {
      const account = this.users.find((u) => u.id === session.userId);
      if (account && account.status !== "active") {
        this.sessions.delete(token);
        return null;
      }
      if (!account && !process.env.VERCEL) {
        this.sessions.delete(token);
        return null;
      }
    }
    session.lastSeenAt = (/* @__PURE__ */ new Date()).toISOString();
    return session;
  }
  advanceLiveTelemetryIfDue() {
    const now = Date.now();
    if (now - this.lastLiveTickAt >= 1500) {
      this.lastLiveTickAt = now;
      this.generateLiveTrafficTick();
    }
    if (!this.simulation.running) {
      this.simWavesCounter = 0;
      return;
    }
    if (now - this.lastSimWaveAt >= 2600) {
      this.lastSimWaveAt = now;
      const simCategories = [
        "ddos_volumetric",
        "sqli_probe",
        "ssh_bruteforce",
        "c2_beacon",
        "data_exfiltration",
        "lateral_movement"
      ];
      const chosen = this.simulation.scenario === "mixed" ? simCategories[this.simWavesCounter % simCategories.length] : this.simulation.scenario;
      this.simWavesCounter += 1;
      if (this.simWavesCounter >= 10) {
        this.simulation.running = false;
      }
      this.triggerThreatScenario(chosen);
    }
  }
  getSnapshot(viewerSession) {
    const publicKeys = this.siemApiKeys.map(({ keyHash: _unused, ...rest }) => rest);
    const allPublicSessions = Array.from(this.sessions.values()).map(
      ({ token: _unused, ...rest }) => rest
    );
    const isAdminViewer = !viewerSession || viewerSession.roleKey === "admin";
    const visibleSessions = isAdminViewer ? allPublicSessions : allPublicSessions.filter((s) => s.userId === viewerSession.userId);
    const visibleUsers = isAdminViewer ? this.users.map((u) => this.toPublicManagedUser(u)) : [];
    const visibleAuditLogs = isAdminViewer ? this.accountAuditLogs : [];
    const visibleReports = isAdminViewer ? this.userReports : this.userReports.filter((r) => r.userId === viewerSession.userId);
    const visibleNotifications = isAdminViewer ? this.notifications : this.notifications.filter(
      (n) => !n.targetRole || n.targetRole === "all" && (!n.targetUserId || n.targetUserId === viewerSession.userId)
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
        backupCodesRemaining: this.admin?.backupCodeHashes.length ?? 0
      }
    };
  }
  nextReportId() {
    this.reportCounter += 1;
    return `RPT-W${this.reportCounter}`;
  }
};

// server/vercel-entry.ts
dotenv.config();
function getStore() {
  if (!globalThis.__sentinelGridStore) {
    globalThis.__sentinelGridStore = new SecurityWorkspaceStore();
  }
  return globalThis.__sentinelGridStore;
}
var socApp = createSocApp(getStore(), {
  wsSupported: false
});
var vercel_entry_default = socApp;
export {
  vercel_entry_default as default
};
