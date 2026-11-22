import crypto from 'node:crypto';
import express from 'express';
import {
  decryptTrafficPayload,
  generateEncryptionKeyHex,
  generateTotpSecret,
  hashApiKey,
  hashPasswordScrypt,
  verifyLogChain,
  verifyPasswordScrypt,
  verifyTotpCode,
} from '../src/lib/cryptoSecurity';
import {
  buildWeeklyReport,
  calculateClusterScale,
  formatSiemEvent,
  isSafeExternalWebhookUrl,
} from '../src/lib/securityEngine';
import type {
  ComplaintStatus,
  PortalMode,
  SeverityLevel,
  SiemFormat,
  ThreatCategory,
  UserRole,
} from '../src/lib/types';
import {
  canUserAuthenticate,
  extractClientIp,
  isValidComplaintStatus,
  isValidUserRole,
  summarizeDeviceUserAgent,
  validateComplaintInput,
  validateRegistrationInput,
} from '../src/lib/userControl';
import { SecurityWorkspaceStore, type ServerSession } from './state';

export interface SocRealtimeHooks {
  wsSupported: boolean;
  broadcastEvent?: (type: string, payload: unknown) => void;
  broadcastAdminEvent?: (type: string, payload: unknown) => void;
  sendUserEvent?: (userId: string, type: string, payload: unknown) => void;
  revokeUserSockets?: (userId: string, reason: string) => void;
}

export function generateBackupCodes(): { plain: string[]; hashes: string[] } {
  const plain: string[] = [];
  const hashes: string[] = [];
  for (let i = 0; i < 6; i += 1) {
    const code = `${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto
      .randomBytes(2)
      .toString('hex')
      .toUpperCase()}`;
    plain.push(code);
    hashes.push(hashApiKey(code));
  }
  return { plain, hashes };
}

type AuthedRequest = express.Request & { socSession?: ServerSession };

export function createSocApp(
  store: SecurityWorkspaceStore,
  hooks: SocRealtimeHooks = { wsSupported: false },
): express.Express {
  const app = express();
  app.set('trust proxy', 1);

  // Support runtimes (like Vercel Serverless) where req.body may already be pre-parsed
  app.use((req, res, next) => {
    const anyReq = req as express.Request & { _body?: boolean };
    if (req.body !== undefined) {
      if (Buffer.isBuffer(req.body)) {
        const raw = req.body.toString('utf8');
        if (req.headers['content-type']?.includes('application/json')) {
          try {
            req.body = raw ? JSON.parse(raw) : {};
          } catch {
            res.status(400).json({ error: 'Invalid JSON request body' });
            return;
          }
        }
      } else if (
        typeof req.body === 'string' &&
        req.headers['content-type']?.includes('application/json')
      ) {
        try {
          req.body = req.body ? JSON.parse(req.body) : {};
        } catch {
          res.status(400).json({ error: 'Invalid JSON request body' });
          return;
        }
      }
      anyReq._body = true;
    }
    next();
  });
  app.use(express.json({ limit: '1mb' }));

  const broadcastEvent = hooks.broadcastEvent ?? (() => {});
  const broadcastAdminEvent = hooks.broadcastAdminEvent ?? (() => {});
  const sendUserEvent = hooks.sendUserEvent ?? (() => {});
  const revokeUserSockets = hooks.revokeUserSockets ?? (() => {});

  const requireAuth: express.RequestHandler = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : undefined;
    const session = store.verifyBearerToken(token);
    if (!session) {
      res.status(401).json({ error: 'Unauthorized: valid MFA session token required' });
      return;
    }
    (req as AuthedRequest).socSession = session;
    next();
  };

  const requireAdmin: express.RequestHandler = (req, res, next) => {
    const session = (req as AuthedRequest).socSession;
    if (!session || session.roleKey !== 'admin') {
      res.status(403).json({ error: 'Forbidden: Administrator role required' });
      return;
    }
    next();
  };

  const requireOperatorOrAdmin: express.RequestHandler = (req, res, next) => {
    const session = (req as AuthedRequest).socSession;
    if (!session || (session.roleKey !== 'admin' && session.roleKey !== 'analyst')) {
      res.status(403).json({ error: 'Forbidden: Analyst or Administrator role required' });
      return;
    }
    next();
  };

  // --- Healthcheck for Vercel / CI / Monitoring ---
  app.get('/api/health', (_req, res) => {
    res.json({
      ok: true,
      service: 'SentinelGrid SOC',
      runtime: process.env.VERCEL ? 'vercel-serverless' : 'node-express',
      wsSupported: hooks.wsSupported,
      timestamp: new Date().toISOString(),
    });
  });

  // --- Public Auth & MFA Gateway Routes ---
  app.get('/api/auth/status', (_req, res) => {
    res.json({
      initialized: store.admin !== null,
      mfaEnrolled: store.admin?.mfaConfirmed ?? false,
      wsSupported: hooks.wsSupported,
      envOverrideActive: Boolean(
        process.env.ADMIN_PASSCODE && process.env.ADMIN_PASSCODE.trim().length >= 6,
      ),
    });
  });

  app.post('/api/auth/setup', (req, res) => {
    if (store.admin !== null) {
      res.status(409).json({ error: 'Admin workspace has already been initialized' });
      return;
    }
    const { email, password } = req.body as { email?: string; password?: string };
    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail || !cleanEmail.includes('@')) {
      res.status(400).json({ error: 'Valid administrator email is required' });
      return;
    }
    if (!password || password.length < 8) {
      res.status(400).json({ error: 'Password must be at least 8 characters' });
      return;
    }

    const totpSecret = generateTotpSecret();
    const backup = generateBackupCodes();
    store.admin = {
      email: cleanEmail,
      passwordHash: hashPasswordScrypt(password),
      totpSecret,
      mfaConfirmed: false,
      backupCodeHashes: backup.hashes,
    };
    store.persistAccountsToDisk();

    const challengeToken = store.createSignedChallenge({
      userId: 'ADMIN-ROOT',
      email: cleanEmail,
      accountType: 'admin',
      isInitialSetup: true,
      ttlMs: 10 * 60_000,
    });

    const otpauthUri = `otpauth://totp/SentinelGrid:${encodeURIComponent(
      cleanEmail,
    )}?secret=${totpSecret}&issuer=SentinelGrid&digits=6&period=30`;

    res.json({
      mfaRequired: true,
      isInitialSetup: true,
      challengeToken,
      totpSecret,
      otpauthUri,
      backupCodes: backup.plain,
    });
  });

  // Cross-device public registration: accounts go directly to the central store & Admin queue
  app.post('/api/auth/register', (req, res) => {
    const { fullName, email, password, department } = req.body as {
      fullName?: string;
      email?: string;
      password?: string;
      department?: string;
    };

    const validation = validateRegistrationInput({ fullName, email, password, department });
    if (!validation.valid) {
      res.status(400).json({ error: validation.error });
      return;
    }

    if (
      (store.admin && store.admin.email === validation.cleanEmail) ||
      store.users.some((u) => u.email === validation.cleanEmail)
    ) {
      res.status(409).json({ error: 'An account with this email is already registered' });
      return;
    }

    const registeredIp = extractClientIp(
      req.headers['x-forwarded-for'],
      req.socket.remoteAddress,
    );
    const deviceInfo = summarizeDeviceUserAgent(req.headers['user-agent']);

    const created = store.registerUserAccount({
      fullName: validation.cleanName,
      email: validation.cleanEmail,
      department: validation.cleanDepartment,
      password: password!,
      registeredIp,
      deviceInfo,
    });

    broadcastAdminEvent('user:registered', {
      user: created.user,
      auditEntry: created.auditEntry,
      notification: created.notification,
    });

    res.status(201).json({
      ok: true,
      user: created.user,
      requireAdminApproval: created.user.status === 'pending',
    });
  });

  app.post('/api/auth/login', (req, res) => {
    const { email, password, portal } = req.body as {
      email?: string;
      password?: string;
      portal?: PortalMode;
    };
    const cleanEmail = (email || '').trim().toLowerCase();
    if (!cleanEmail || !password) {
      res.status(400).json({ error: 'Email and password are required' });
      return;
    }

    const envPass = process.env.ADMIN_PASSCODE?.trim();
    if (store.admin && cleanEmail === store.admin.email) {
      if (portal === 'user') {
        res.status(403).json({
          error: 'Akun Administrator harus masuk melalui link Portal Admin (/admin).',
        });
        return;
      }
      const passwordValid =
        envPass && envPass.length >= 6
          ? password === envPass
          : verifyPasswordScrypt(password, store.admin.passwordHash);

      if (!passwordValid) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      const isInitialSetup = !store.admin.mfaConfirmed;
      const challengeToken = store.createSignedChallenge({
        userId: 'ADMIN-ROOT',
        email: cleanEmail,
        accountType: 'admin',
        isInitialSetup,
      });

      if (isInitialSetup) {
        const backup = generateBackupCodes();
        store.admin.backupCodeHashes = backup.hashes;
        store.persistAccountsToDisk();
        res.json({
          mfaRequired: true,
          isInitialSetup: true,
          challengeToken,
          totpSecret: store.admin.totpSecret,
          otpauthUri: `otpauth://totp/SentinelGrid:${encodeURIComponent(
            cleanEmail,
          )}?secret=${store.admin.totpSecret}&issuer=SentinelGrid&digits=6&period=30`,
          backupCodes: backup.plain,
        });
        return;
      }

      res.json({
        mfaRequired: true,
        isInitialSetup: false,
        challengeToken,
      });
      return;
    }

    const user = store.users.find((u) => u.email === cleanEmail);
    if (!user || !verifyPasswordScrypt(password, user.passwordHash)) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    if (portal === 'admin' && user.role !== 'admin') {
      res.status(403).json({
        error: 'Akun pengguna silakan masuk melalui link Portal Pengguna (/user).',
      });
      return;
    }

    const accessCheck = canUserAuthenticate(user.status);
    if (!accessCheck.allowed) {
      const errorMessage =
        accessCheck.reason === 'ACCOUNT_PENDING'
          ? 'Akun Anda terdaftar dan sedang menunggu persetujuan & aktivasi dari Admin.'
          : accessCheck.reason === 'ACCOUNT_SUSPENDED'
            ? `Akun Anda ditangguhkan sementara oleh Admin${user.issueNote ? `: ${user.issueNote}` : '.'}`
            : `Akun Anda diblokir oleh Admin${user.issueNote ? `: ${user.issueNote}` : '.'}`;
      res.status(403).json({
        error: errorMessage,
        errorCode: accessCheck.reason,
        status: user.status,
        issueNote: user.issueNote,
      });
      return;
    }

    const isInitialSetup = !user.mfaConfirmed;
    const challengeToken = store.createSignedChallenge({
      userId: user.id,
      email: user.email,
      accountType: 'user',
      isInitialSetup,
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
          user.email,
        )}?secret=${user.totpSecret}&issuer=SentinelGrid&digits=6&period=30`,
        backupCodes: backup.plain,
      });
      return;
    }

    res.json({
      mfaRequired: true,
      isInitialSetup: false,
      challengeToken,
    });
  });

  app.post('/api/auth/verify-mfa', (req, res) => {
    const { challengeToken, code } = req.body as { challengeToken?: string; code?: string };
    if (!challengeToken || !code) {
      res.status(400).json({ error: 'Challenge token and verification code are required' });
      return;
    }
    const challenge = store.verifySignedChallenge(challengeToken);
    if (!challenge) {
      res.status(401).json({ error: 'MFA challenge expired. Please sign in again.' });
      return;
    }

    const cleanCode = code.trim().toUpperCase();
    const ipAddress = extractClientIp(
      req.headers['x-forwarded-for'],
      req.socket.remoteAddress,
    );
    const deviceInfo = summarizeDeviceUserAgent(req.headers['user-agent']);

    if (challenge.accountType === 'admin') {
      if (!store.admin) {
        res.status(400).json({ error: 'Workspace not initialized' });
        return;
      }
      let verified = verifyTotpCode(store.admin.totpSecret, cleanCode);
      if (!verified) {
        const codeHash = hashApiKey(cleanCode);
        const backupIdx = store.admin.backupCodeHashes.indexOf(codeHash);
        if (backupIdx !== -1) {
          store.admin.backupCodeHashes.splice(backupIdx, 1);
          verified = true;
        }
      }
      if (!verified) {
        res.status(401).json({ error: 'Invalid 6-digit TOTP or recovery code' });
        return;
      }

      store.admin.mfaConfirmed = true;
      store.persistAccountsToDisk();
      store.challenges.delete(challengeToken);

      const session = store.createSignedSession({
        userId: 'ADMIN-ROOT',
        email: challenge.email,
        roleKey: 'admin',
        userAgent: deviceInfo,
        ipAddress,
      });

      res.json({
        token: session.token,
        session: {
          id: session.id,
          userId: session.userId,
          email: session.email,
          role: session.role,
          roleKey: session.roleKey,
          mfaVerified: session.mfaVerified,
        },
      });
      return;
    }

    const user = store.users.find((u) => u.id === challenge.userId);
    if (!user) {
      res.status(401).json({ error: 'Account not found' });
      return;
    }
    const accessCheck = canUserAuthenticate(user.status);
    if (!accessCheck.allowed) {
      store.challenges.delete(challengeToken);
      res.status(403).json({
        error: 'Account access has been restricted by Administrator.',
        errorCode: accessCheck.reason,
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
      res.status(401).json({ error: 'Invalid 6-digit TOTP or recovery code' });
      return;
    }

    user.mfaConfirmed = true;
    user.lastLoginAt = new Date().toISOString();
    store.persistAccountsToDisk();
    store.challenges.delete(challengeToken);

    const session = store.createSignedSession({
      userId: user.id,
      email: user.email,
      roleKey: user.role,
      userAgent: deviceInfo,
      ipAddress,
    });

    broadcastAdminEvent('user:updated', {
      user: store.toPublicManagedUser(user),
      sessions: Array.from(store.sessions.values()).map(({ token: _unused, ...rest }) => rest),
    });

    res.json({
      token: session.token,
      session: {
        id: session.id,
        userId: session.userId,
        email: session.email,
        role: session.role,
        roleKey: session.roleKey,
        mfaVerified: session.mfaVerified,
      },
    });
  });

  app.post('/api/auth/logout', requireAuth, (req, res) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.slice(7).trim();
    if (token) {
      store.revokeToken(token);
    }
    res.json({ ok: true });
  });

  // --- Protected SOC Workspace Endpoints ---
  app.get('/api/soc/snapshot', requireAuth, (req, res) => {
    const session = (req as AuthedRequest).socSession!;
    if (req.query.live === '1') {
      store.advanceLiveTelemetryIfDue();
    }
    res.json(store.getSnapshot(session));
  });

  // --- Admin User Control & Multi-Device Registration Monitoring Endpoints ---
  app.get('/api/admin/users', requireAuth, requireAdmin, (_req, res) => {
    const publicSessions = Array.from(store.sessions.values()).map(
      ({ token: _unused, ...rest }) => rest,
    );
    res.json({
      users: store.users.map((u) => store.toPublicManagedUser(u)),
      accountAuditLogs: store.accountAuditLogs,
      requireAdminApproval: store.requireAdminApproval,
      sessions: publicSessions,
    });
  });

  app.patch('/api/admin/settings', requireAuth, requireAdmin, (req, res) => {
    const { requireAdminApproval } = req.body as { requireAdminApproval?: boolean };
    if (typeof requireAdminApproval === 'boolean') {
      store.requireAdminApproval = requireAdminApproval;
      store.persistAccountsToDisk();
    }
    broadcastAdminEvent('admin:settings_updated', {
      requireAdminApproval: store.requireAdminApproval,
    });
    res.json({ requireAdminApproval: store.requireAdminApproval });
  });

  app.post('/api/admin/users/:id/control', requireAuth, requireAdmin, (req, res) => {
    const session = (req as AuthedRequest).socSession!;
    const { action, role, issueFlagged, issueNote } = req.body as {
      action?:
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
    };

    const validActions = [
      'activate',
      'suspend',
      'block',
      'reset_mfa',
      'revoke_sessions',
      'change_role',
      'update_issue',
    ];
    if (!action || !validActions.includes(action)) {
      res.status(400).json({ error: 'Invalid admin control action' });
      return;
    }
    if (action === 'change_role' && !isValidUserRole(role)) {
      res.status(400).json({ error: 'Invalid role selection' });
      return;
    }

    const result = store.applyAdminUserControl({
      userId: req.params.id,
      actorEmail: session.email,
      actorIp: extractClientIp(req.headers['x-forwarded-for'], req.socket.remoteAddress),
      actorDevice: summarizeDeviceUserAgent(req.headers['user-agent']),
      action,
      role,
      issueFlagged,
      issueNote,
    });

    if (!result) {
      res.status(404).json({ error: 'User account not found' });
      return;
    }

    if (result.shouldRevokeWs) {
      revokeUserSockets(result.user.id, result.revokeReason);
    }

    const publicSessions = Array.from(store.sessions.values()).map(
      ({ token: _unused, ...rest }) => rest,
    );
    broadcastAdminEvent('user:updated', {
      user: result.user,
      auditEntry: result.auditEntry,
      sessions: publicSessions,
    });

    res.json({
      user: result.user,
      auditEntry: result.auditEntry,
      revokedSessionCount: result.revokedSessionCount,
      sessions: publicSessions,
    });
  });

  // --- User Complaint / Incident Report Submission (Delivered Live to Admin Account) ---
  app.post('/api/user/reports', requireAuth, (req, res) => {
    const session = (req as AuthedRequest).socSession!;
    const { category, severity, subject, description } = req.body as {
      category?: string;
      severity?: string;
      subject?: string;
      description?: string;
    };

    const validation = validateComplaintInput({ category, severity, subject, description });
    if (!validation.valid) {
      res.status(400).json({ error: validation.error });
      return;
    }

    const ipAddress = extractClientIp(
      req.headers['x-forwarded-for'],
      req.socket.remoteAddress,
    );
    const deviceInfo = summarizeDeviceUserAgent(req.headers['user-agent']);

    const created = store.createUserComplaintReport({
      userId: session.userId,
      email: session.email,
      ipAddress,
      deviceInfo,
      category: validation.cleanCategory,
      severity: validation.cleanSeverity,
      subject: validation.cleanSubject,
      description: validation.cleanDescription,
    });

    broadcastAdminEvent('user:report_created', created);
    if (session.roleKey !== 'admin') {
      sendUserEvent(session.userId, 'user:report_created', { report: created.report });
    }

    res.status(201).json(created);
  });

  app.post('/api/admin/reports/:id/respond', requireAuth, requireAdmin, (req, res) => {
    const session = (req as AuthedRequest).socSession!;
    const { status, adminNote } = req.body as {
      status?: ComplaintStatus;
      adminNote?: string;
    };

    if (!isValidComplaintStatus(status)) {
      res.status(400).json({ error: 'Invalid complaint status' });
      return;
    }

    const updated = store.respondToUserComplaintReport({
      reportId: req.params.id,
      adminEmail: session.email,
      status,
      adminNote,
    });

    if (!updated) {
      res.status(404).json({ error: 'User report not found' });
      return;
    }

    broadcastAdminEvent('user:report_updated', { report: updated.report });
    if (updated.report.userId !== 'ADMIN-ROOT') {
      sendUserEvent(updated.report.userId, 'user:report_updated', {
        report: updated.report,
        notification: updated.notification,
      });
    }

    res.json(updated);
  });

  app.post('/api/soc/threats/simulate', requireAuth, requireOperatorOrAdmin, (req, res) => {
    const { category } = req.body as { category?: ThreatCategory };
    const validCategories: ThreatCategory[] = [
      'ddos_volumetric',
      'sqli_probe',
      'ssh_bruteforce',
      'c2_beacon',
      'data_exfiltration',
      'lateral_movement',
    ];
    const chosen: ThreatCategory =
      category && validCategories.includes(category)
        ? category
        : validCategories[Math.floor(Math.random() * validCategories.length)];

    const result = store.triggerThreatScenario(chosen);
    broadcastEvent('threat:detected', result);
    res.json(result);
  });

  app.post('/api/soc/threats/simulation-mode', requireAuth, requireOperatorOrAdmin, (req, res) => {
    const { running, scenario } = req.body as {
      running?: boolean;
      scenario?: ThreatCategory | 'mixed';
    };
    const validScenarios: Array<ThreatCategory | 'mixed'> = [
      'mixed',
      'ddos_volumetric',
      'sqli_probe',
      'ssh_bruteforce',
      'c2_beacon',
      'data_exfiltration',
      'lateral_movement',
    ];

    if (scenario && validScenarios.includes(scenario)) {
      store.simulation.scenario = scenario;
    }
    if (typeof running === 'boolean') {
      store.simulation.running = running;
    }

    let firstWave: ReturnType<typeof store.triggerThreatScenario> | null = null;
    if (store.simulation.running) {
      const cat: ThreatCategory =
        store.simulation.scenario === 'mixed'
          ? 'ddos_volumetric'
          : store.simulation.scenario;
      firstWave = store.triggerThreatScenario(cat);
      broadcastEvent('threat:detected', firstWave);
    }

    broadcastEvent('simulation:state', { simulation: store.simulation });
    res.json({ simulation: store.simulation, firstWave });
  });

  app.post('/api/soc/alerts/:id/mitigate', requireAuth, requireOperatorOrAdmin, (req, res) => {
    const { id } = req.params;
    const { action } = req.body as { action?: 'block' | 'mitigate' | 'acknowledge' };
    const alert = store.alerts.find((a) => a.id === id);
    if (!alert) {
      res.status(404).json({ error: 'Alert not found' });
      return;
    }

    if (action === 'block') {
      alert.status = 'blocked';
      alert.acknowledged = true;
    } else if (action === 'mitigate') {
      alert.status = 'mitigated';
      alert.acknowledged = true;
    } else {
      alert.acknowledged = true;
    }

    for (const notif of store.notifications) {
      if (notif.alertId === alert.id) {
        notif.read = true;
      }
    }

    broadcastEvent('alert:updated', { alert });
    res.json({ alert });
  });

  app.post('/api/soc/notifications/mark-read', requireAuth, (_req, res) => {
    store.notifications = [];
    res.json({ notifications: store.notifications });
  });

  app.post('/api/soc/logs/decrypt', requireAuth, requireOperatorOrAdmin, (req, res) => {
    const { logIds } = req.body as { logIds?: string[] };
    const targets =
      Array.isArray(logIds) && logIds.length > 0
        ? store.encryptedLogs.filter((l) => logIds.includes(l.id))
        : store.encryptedLogs.slice(0, 25);

    const decrypted: Record<string, ReturnType<typeof decryptTrafficPayload>> = {};
    for (const entry of targets) {
      const keyHex = store.encryptionKeys.get(entry.keyId);
      if (keyHex) {
        try {
          decrypted[entry.id] = decryptTrafficPayload(entry.envelope, keyHex);
        } catch {
          // Skip entries failing tag verification
        }
      }
    }

    res.json({ decrypted });
  });

  app.post('/api/soc/logs/verify-chain', requireAuth, (_req, res) => {
    const result = verifyLogChain(store.encryptedLogs);
    res.json(result);
  });

  app.post('/api/soc/logs/rotate-key', requireAuth, requireAdmin, (_req, res) => {
    const nextNum = store.encryptionKeys.size + 1;
    const newKeyId = `KEY-2026-${String(nextNum).padStart(2, '0')}`;
    store.encryptionKeys.set(newKeyId, generateEncryptionKeyHex());
    store.activeKeyId = newKeyId;
    res.json({ activeKeyId: newKeyId, totalKeysHeld: store.encryptionKeys.size });
  });

  app.post('/api/soc/siem/keys', requireAuth, requireAdmin, (req, res) => {
    const { label, scopes } = req.body as { label?: string; scopes?: string[] };
    const cleanLabel = (label || '').trim();
    if (!cleanLabel || cleanLabel.length < 3) {
      res.status(400).json({ error: 'API key label must be at least 3 characters' });
      return;
    }

    const rawSecret = `sg_live_${crypto.randomBytes(18).toString('hex')}`;
    const newKey = {
      id: `key-${Date.now()}`,
      label: cleanLabel,
      prefix: rawSecret.slice(0, 14),
      scopes: Array.isArray(scopes) && scopes.length > 0 ? scopes : ['logs:read', 'alerts:stream'],
      createdAt: new Date().toISOString(),
      lastUsedAt: null,
      revoked: false,
      keyHash: hashApiKey(rawSecret),
    };
    store.siemApiKeys.unshift(newKey);

    const { keyHash: _unused, ...publicMeta } = newKey;
    res.json({ apiKey: publicMeta, rawSecret });
  });

  app.delete('/api/soc/siem/keys/:id', requireAuth, requireAdmin, (req, res) => {
    const target = store.siemApiKeys.find((k) => k.id === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'API key not found' });
      return;
    }
    target.revoked = true;
    res.json({ ok: true, id: target.id });
  });

  app.patch('/api/soc/siem/connectors/:id', requireAuth, (req, res) => {
    const connector = store.siemConnectors.find((c) => c.id === req.params.id);
    if (!connector) {
      res.status(404).json({ error: 'SIEM connector not found' });
      return;
    }
    const { enabled, format, endpointUrl } = req.body as {
      enabled?: boolean;
      format?: SiemFormat;
      endpointUrl?: string;
    };

    if (endpointUrl !== undefined) {
      if (!isSafeExternalWebhookUrl(endpointUrl)) {
        res.status(400).json({ error: 'Invalid or restricted endpoint URL (SSRF policy)' });
        return;
      }
      connector.endpointUrl = endpointUrl.trim();
    }
    if (typeof enabled === 'boolean') {
      connector.enabled = enabled;
      connector.lastStatus = enabled ? 'healthy' : 'standby';
    }
    if (format && ['JSON', 'CEF', 'LEEF'].includes(format)) {
      connector.format = format;
    }
    res.json({ connector });
  });

  app.post('/api/soc/siem/connectors/:id/test', requireAuth, (req, res) => {
    const connector = store.siemConnectors.find((c) => c.id === req.params.id);
    if (!connector) {
      res.status(404).json({ error: 'SIEM connector not found' });
      return;
    }
    const sampleAlert = store.alerts[0];
    const formattedPayload = sampleAlert ? formatSiemEvent(sampleAlert, connector.format) : '{}';
    connector.eventsSynced += 1;
    connector.lastSyncAt = new Date().toISOString();
    connector.lastStatus = 'healthy';
    connector.enabled = true;
    res.json({
      connector,
      dispatchedPayload: formattedPayload,
      deliveryLatencyMs: connector.avgLatencyMs,
    });
  });

  app.patch('/api/soc/integrations/:id', requireAuth, (req, res) => {
    const item = store.integrations.find((i) => i.id === req.params.id);
    if (!item) {
      res.status(404).json({ error: 'Integration not found' });
      return;
    }
    const { enabled, syncMode } = req.body as { enabled?: boolean; syncMode?: 'realtime' | 'batched' };
    if (typeof enabled === 'boolean') item.enabled = enabled;
    if (syncMode === 'realtime' || syncMode === 'batched') item.syncMode = syncMode;
    res.json({ integration: item });
  });

  app.post('/api/soc/rules', requireAuth, (req, res) => {
    const { name, minSeverity, action, channels } = req.body as {
      name?: string;
      minSeverity?: SeverityLevel;
      action?: 'block_ip_and_notify' | 'quarantine_host' | 'siem_escalate' | 'pagerduty_page';
      channels?: string[];
    };
    if (!name || name.trim().length < 3) {
      res.status(400).json({ error: 'Rule name is required' });
      return;
    }
    const rule = {
      id: `rule-${Date.now()}`,
      name: name.trim(),
      minSeverity: minSeverity ?? 'high',
      action: action ?? 'block_ip_and_notify',
      channels: Array.isArray(channels) && channels.length > 0 ? channels : ['Slack #sec-ops-alerts'],
      enabled: true,
      triggerCount: 0,
      lastTriggeredAt: null,
    };
    store.automationRules.unshift(rule);
    res.json({ rule });
  });

  app.patch('/api/soc/rules/:id', requireAuth, (req, res) => {
    const rule = store.automationRules.find((r) => r.id === req.params.id);
    if (!rule) {
      res.status(404).json({ error: 'Rule not found' });
      return;
    }
    const { enabled } = req.body as { enabled?: boolean };
    if (typeof enabled === 'boolean') rule.enabled = enabled;
    res.json({ rule });
  });

  app.post('/api/soc/reports/generate', requireAuth, (_req, res) => {
    const now = new Date();
    const start = new Date(now.getTime() - 7 * 86_400_000);
    const periodLabel = `${start.toISOString().slice(0, 10)} — ${now.toISOString().slice(0, 10)}`;
    const report = buildWeeklyReport({
      id: store.nextReportId(),
      generatedAt: now.toISOString(),
      periodLabel,
      trafficHistory: store.trafficHistory,
      alerts: store.alerts,
      logs: store.encryptedLogs,
      complianceControls: store.complianceControls,
    });
    store.weeklyReports.unshift(report);
    res.json({ report });
  });

  app.patch('/api/soc/reports/schedule', requireAuth, (req, res) => {
    const { enabled, dayOfWeek, timeUtc, recipients } = req.body as {
      enabled?: boolean;
      dayOfWeek?: 'Monday' | 'Friday' | 'Sunday';
      timeUtc?: string;
      recipients?: string[];
    };
    if (typeof enabled === 'boolean') store.reportSchedule.enabled = enabled;
    if (dayOfWeek && ['Monday', 'Friday', 'Sunday'].includes(dayOfWeek)) {
      store.reportSchedule.dayOfWeek = dayOfWeek;
    }
    if (timeUtc && /^\d{2}:\d{2}$/.test(timeUtc)) {
      store.reportSchedule.timeUtc = timeUtc;
    }
    if (Array.isArray(recipients)) {
      store.reportSchedule.recipients = recipients.filter((r) => r.includes('@')).slice(0, 10);
    }
    res.json({ reportSchedule: store.reportSchedule });
  });

  app.patch('/api/soc/cluster', requireAuth, (req, res) => {
    const { autoScaleEnabled, maxNodes, targetLoadPercent, stressTestActive } = req.body as {
      autoScaleEnabled?: boolean;
      maxNodes?: number;
      targetLoadPercent?: number;
      stressTestActive?: boolean;
    };
    if (typeof autoScaleEnabled === 'boolean') store.cluster.autoScaleEnabled = autoScaleEnabled;
    if (typeof maxNodes === 'number' && maxNodes >= 4 && maxNodes <= 64) {
      store.cluster.maxNodes = maxNodes;
    }
    if (typeof targetLoadPercent === 'number' && targetLoadPercent >= 40 && targetLoadPercent <= 90) {
      store.cluster.targetLoadPercent = targetLoadPercent;
    }
    if (typeof stressTestActive === 'boolean') {
      store.cluster.stressTestActive = stressTestActive;
    }

    const latest = store.trafficHistory[store.trafficHistory.length - 1];
    const baseGbps = (latest?.inboundGbps ?? 24) + (latest?.outboundGbps ?? 14);
    const effectiveGbps = store.cluster.stressTestActive ? Math.max(92, baseGbps * 3.1) : baseGbps;
    const effectivePps = store.cluster.stressTestActive ? 880_000 : latest?.packetsPerSec ?? 240_000;
    store.cluster = calculateClusterScale(effectiveGbps, effectivePps, store.cluster);
    broadcastEvent('cluster:scaled', { cluster: store.cluster });
    res.json({ cluster: store.cluster });
  });

  app.post('/api/soc/mfa/backup-codes', requireAuth, (req, res) => {
    const session = (req as AuthedRequest).socSession!;
    const backup = generateBackupCodes();
    if (session.userId === 'ADMIN-ROOT') {
      if (!store.admin) {
        res.status(400).json({ error: 'Admin account not initialized' });
        return;
      }
      store.admin.backupCodeHashes = backup.hashes;
    } else {
      const user = store.users.find((u) => u.id === session.userId);
      if (!user) {
        res.status(404).json({ error: 'User account not found' });
        return;
      }
      user.backupCodeHashes = backup.hashes;
    }
    store.persistAccountsToDisk();
    res.json({ backupCodes: backup.plain, remaining: backup.plain.length });
  });

  app.patch('/api/soc/mfa/policy', requireAuth, requireAdmin, (req, res) => {
    const { requireMfaForDecryption, requireMfaForKeyRotation } = req.body as {
      requireMfaForDecryption?: boolean;
      requireMfaForKeyRotation?: boolean;
    };
    if (typeof requireMfaForDecryption === 'boolean') {
      store.mfaPolicy.requireMfaForDecryption = requireMfaForDecryption;
    }
    if (typeof requireMfaForKeyRotation === 'boolean') {
      store.mfaPolicy.requireMfaForKeyRotation = requireMfaForKeyRotation;
    }
    store.persistAccountsToDisk();
    res.json({
      mfaPolicy: {
        ...store.mfaPolicy,
        backupCodesRemaining: store.admin?.backupCodeHashes.length ?? 0,
      },
    });
  });

  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
  });

  app.use(
    (
      err: unknown,
      req: express.Request,
      res: express.Response,
      next: express.NextFunction,
    ) => {
      if (res.headersSent) {
        next(err);
        return;
      }
      if (req.path.startsWith('/api')) {
        const message = err instanceof Error ? err.message : 'Internal authentication server error';
        res.status(500).json({ error: message });
        return;
      }
      next(err);
    },
  );

  return app;
}
