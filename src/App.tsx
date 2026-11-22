import React, { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, MessageSquareWarning, X } from 'lucide-react';
import { AdminUsersView, type UserControlActionPayload } from './components/AdminUsersView';
import { AuthGateway, type AuthSession } from './components/AuthGateway';
import { EncryptedLogsView } from './components/EncryptedLogsView';
import { MfaSecurityView } from './components/MfaSecurityView';
import { OverviewView } from './components/OverviewView';
import { ReportsAndScaleView } from './components/ReportsAndScaleView';
import { Sidebar, type NavTabId } from './components/Sidebar';
import { SiemIntegrationsView } from './components/SiemIntegrationsView';
import { ThreatsView } from './components/ThreatsView';
import { TopBar } from './components/TopBar';
import { UserReportsView } from './components/UserReportsView';
import { TRANSLATIONS } from './i18n/translations';
import type {
  AccountControlAuditEntry,
  ActiveSessionInfo,
  AttackSimulationState,
  AutomationRule,
  ClusterConfig,
  ComplaintCategory,
  ComplaintStatus,
  DecryptedLogPayload,
  EncryptedLogEntry,
  LanguageCode,
  ManagedUserAccount,
  PortalMode,
  SecurityNotification,
  SeverityLevel,
  SiemConnector,
  SiemFormat,
  SocSnapshot,
  ThreatAlert,
  ThreatCategory,
  TrafficSample,
  UserComplaintReport,
  WeeklyReport,
  WeeklyReportSchedule,
} from './lib/types';
import { portalSessionStorageKey, resolvePortalFromPathname } from './lib/userControl';

function loadStoredPortalSession(portal: PortalMode): AuthSession | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(portalSessionStorageKey(portal));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as AuthSession;
    if (!parsed || typeof parsed.token !== 'string' || !parsed.roleKey) return null;
    if (portal === 'admin' && parsed.roleKey !== 'admin') return null;
    if (portal === 'user' && parsed.roleKey === 'admin') return null;
    return parsed;
  } catch {
    return null;
  }
}

function saveStoredPortalSession(portal: PortalMode, sess: AuthSession | null) {
  if (typeof window === 'undefined') return;
  try {
    const key = portalSessionStorageKey(portal);
    if (sess) {
      window.localStorage.setItem(key, JSON.stringify(sess));
    } else {
      window.localStorage.removeItem(key);
    }
  } catch {
    // Ignore storage quota errors
  }
}

export default function App() {
  const [lang, setLang] = useState<LanguageCode>('id');
  const [isDark, setIsDark] = useState(true);
  const [portal, setPortal] = useState<PortalMode>(() =>
    typeof window !== 'undefined' ? resolvePortalFromPathname(window.location.pathname) : 'admin',
  );
  const [authInitialized, setAuthInitialized] = useState<boolean | null>(null);
  const [session, setSession] = useState<AuthSession | null>(() =>
    loadStoredPortalSession(
      typeof window !== 'undefined' ? resolvePortalFromPathname(window.location.pathname) : 'admin',
    ),
  );
  const [activeTab, setActiveTab] = useState<NavTabId>('overview');
  const [adminUsersSubTab, setAdminUsersSubTab] = useState<'accounts' | 'complaints'>('accounts');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const [snapshot, setSnapshot] = useState<SocSnapshot | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [toastAlert, setToastAlert] = useState<ThreatAlert | null>(null);
  const [toastReport, setToastReport] = useState<UserComplaintReport | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);

  const t = TRANSLATIONS[lang];

  useEffect(() => {
    const onPopState = () => {
      const nextPortal = resolvePortalFromPathname(window.location.pathname);
      setPortal(nextPortal);
      setSnapshot(null);
      setSession(loadStoredPortalSession(nextPortal));
      setActiveTab('overview');
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  function handleSwitchPortal(nextPortal: PortalMode) {
    const targetPath = nextPortal === 'user' ? '/user' : '/admin';
    if (window.location.pathname !== targetPath) {
      window.history.pushState({}, '', targetPath);
    }
    setPortal(nextPortal);
    setAuthNotice(null);
    setSnapshot(null);
    setSession(loadStoredPortalSession(nextPortal));
    setActiveTab('overview');
  }

  useEffect(() => {
    document.documentElement.classList.toggle('dark', isDark);
  }, [isDark]);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  useEffect(() => {
    fetch('/api/auth/status')
      .then((res) => res.json())
      .then((data: { initialized: boolean }) => {
        setAuthInitialized(data.initialized);
      })
      .catch(() => {
        setAuthInitialized(false);
      });
  }, []);

  const authFetch = useCallback(
    async (url: string, init?: RequestInit) => {
      if (!session) throw new Error('Not authenticated');
      const res = await fetch(url, {
        ...init,
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`,
          ...(init?.headers || {}),
        },
      });
      if (res.status === 401) {
        saveStoredPortalSession(portal, null);
        setSession(null);
        setSnapshot(null);
        throw new Error('Session expired');
      }
      return res;
    },
    [session, portal],
  );

  const loadSnapshot = useCallback(async () => {
    if (!session) return;
    const res = await authFetch('/api/soc/snapshot');
    if (res.ok) {
      const data = (await res.json()) as SocSnapshot;
      setSnapshot(data);
    }
  }, [session, authFetch]);

  useEffect(() => {
    if (!session) return;
    loadSnapshot();

    let closedIntentionally = false;
    const connectWs = () => {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const ws = new WebSocket(`${proto}//${window.location.host}/ws`);
      wsRef.current = ws;

      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'auth', token: session.token }));
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data as string) as {
            type: string;
            payload: Record<string, unknown>;
          };

          if (msg.type === 'auth:ok') {
            setWsConnected(true);
            return;
          }

          if (msg.type === 'traffic:tick') {
            const sample = msg.payload.sample as TrafficSample;
            const newLog = msg.payload.newLog as EncryptedLogEntry;
            const cluster = msg.payload.cluster as ClusterConfig;
            const siemConnectors = msg.payload.siemConnectors as SiemConnector[];
            setSnapshot((prev) => {
              if (!prev) return prev;
              const nextHistory = [...prev.trafficHistory, sample].slice(-60);
              const nextLogs = prev.encryptedLogs.some((l) => l.id === newLog.id)
                ? prev.encryptedLogs
                : [newLog, ...prev.encryptedLogs].slice(0, 120);
              return {
                ...prev,
                trafficHistory: nextHistory,
                encryptedLogs: nextLogs,
                cluster,
                siemConnectors,
              };
            });
            return;
          }

          if (msg.type === 'threat:detected') {
            const alert = msg.payload.alert as ThreatAlert;
            const log = msg.payload.log as EncryptedLogEntry;
            const notification = msg.payload.notification as SecurityNotification;
            const trafficSample = msg.payload.trafficSample as TrafficSample | undefined;
            const cluster = msg.payload.cluster as ClusterConfig | undefined;
            const simulation = msg.payload.simulation as AttackSimulationState | undefined;
            setSnapshot((prev) => {
              if (!prev) return prev;
              const alerts = prev.alerts.some((a) => a.id === alert.id)
                ? prev.alerts
                : [alert, ...prev.alerts].slice(0, 80);
              const logs = prev.encryptedLogs.some((l) => l.id === log.id)
                ? prev.encryptedLogs
                : [log, ...prev.encryptedLogs].slice(0, 120);
              const notifications = prev.notifications.some((n) => n.id === notification.id)
                ? prev.notifications
                : [notification, ...prev.notifications].slice(0, 40);
              const trafficHistory =
                trafficSample && !prev.trafficHistory.some((s) => s.id === trafficSample.id)
                  ? [...prev.trafficHistory, trafficSample].slice(-60)
                  : prev.trafficHistory;
              return {
                ...prev,
                alerts,
                encryptedLogs: logs,
                notifications,
                trafficHistory,
                cluster: cluster ?? prev.cluster,
                simulation: simulation ?? prev.simulation,
              };
            });
            setToastAlert(alert);
            return;
          }

          if (msg.type === 'simulation:state') {
            const simulation = msg.payload.simulation as AttackSimulationState;
            setSnapshot((prev) => (prev ? { ...prev, simulation } : prev));
            return;
          }

          if (msg.type === 'alert:updated') {
            const updated = msg.payload.alert as ThreatAlert;
            setSnapshot((prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                alerts: prev.alerts.map((a) => (a.id === updated.id ? updated : a)),
              };
            });
            return;
          }

          if (msg.type === 'cluster:scaled') {
            const cluster = msg.payload.cluster as ClusterConfig;
            setSnapshot((prev) => (prev ? { ...prev, cluster } : prev));
            return;
          }

          if (msg.type === 'user:registered') {
            const user = msg.payload.user as ManagedUserAccount;
            const auditEntry = msg.payload.auditEntry as AccountControlAuditEntry;
            const notification = msg.payload.notification as SecurityNotification;
            setSnapshot((prev) => {
              if (!prev) return prev;
              const users = prev.users.some((u) => u.id === user.id)
                ? prev.users
                : [user, ...prev.users];
              const accountAuditLogs = prev.accountAuditLogs.some((a) => a.id === auditEntry.id)
                ? prev.accountAuditLogs
                : [auditEntry, ...prev.accountAuditLogs].slice(0, 200);
              const notifications = prev.notifications.some((n) => n.id === notification.id)
                ? prev.notifications
                : [notification, ...prev.notifications].slice(0, 40);
              return { ...prev, users, accountAuditLogs, notifications };
            });
            return;
          }

          if (msg.type === 'user:updated') {
            const updatedUser = msg.payload.user as ManagedUserAccount;
            const auditEntry = msg.payload.auditEntry as AccountControlAuditEntry | undefined;
            const sessions = msg.payload.sessions as ActiveSessionInfo[] | undefined;
            setSnapshot((prev) => {
              if (!prev) return prev;
              const users = prev.users.some((u) => u.id === updatedUser.id)
                ? prev.users.map((u) => (u.id === updatedUser.id ? updatedUser : u))
                : [updatedUser, ...prev.users];
              const accountAuditLogs =
                auditEntry && !prev.accountAuditLogs.some((a) => a.id === auditEntry.id)
                  ? [auditEntry, ...prev.accountAuditLogs].slice(0, 200)
                  : prev.accountAuditLogs;
              return {
                ...prev,
                users,
                accountAuditLogs,
                sessions: sessions ?? prev.sessions,
              };
            });
            return;
          }

          if (msg.type === 'user:report_created') {
            const report = msg.payload.report as UserComplaintReport;
            const notification = msg.payload.notification as SecurityNotification | undefined;
            setSnapshot((prev) => {
              if (!prev) return prev;
              const userReports = prev.userReports.some((r) => r.id === report.id)
                ? prev.userReports
                : [report, ...prev.userReports].slice(0, 200);
              const notifications =
                notification && !prev.notifications.some((n) => n.id === notification.id)
                  ? [notification, ...prev.notifications].slice(0, 40)
                  : prev.notifications;
              return { ...prev, userReports, notifications };
            });
            if (session.roleKey === 'admin') {
              setToastReport(report);
            }
            return;
          }

          if (msg.type === 'user:report_updated') {
            const updatedReport = msg.payload.report as UserComplaintReport;
            const notification = msg.payload.notification as SecurityNotification | undefined;
            setSnapshot((prev) => {
              if (!prev) return prev;
              const userReports = prev.userReports.some((r) => r.id === updatedReport.id)
                ? prev.userReports.map((r) => (r.id === updatedReport.id ? updatedReport : r))
                : [updatedReport, ...prev.userReports];
              const notifications =
                notification && !prev.notifications.some((n) => n.id === notification.id)
                  ? [notification, ...prev.notifications].slice(0, 40)
                  : prev.notifications;
              return { ...prev, userReports, notifications };
            });
            return;
          }

          if (msg.type === 'admin:settings_updated') {
            const requireAdminApproval = msg.payload.requireAdminApproval as boolean;
            setSnapshot((prev) => (prev ? { ...prev, requireAdminApproval } : prev));
            return;
          }

          if (msg.type === 'session:revoked') {
            const reason = (msg.payload.reason as string) || 'Session revoked by Administrator.';
            closedIntentionally = true;
            saveStoredPortalSession(portal, null);
            setAuthNotice(reason);
            setSession(null);
            setSnapshot(null);
          }
        } catch {
          // Ignore malformed WS payloads
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        if (!closedIntentionally) {
          reconnectTimerRef.current = window.setTimeout(connectWs, 2500);
        }
      };
    };

    connectWs();

    return () => {
      closedIntentionally = true;
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
      }
      wsRef.current?.close();
    };
  }, [session, portal, loadSnapshot]);

  async function handleLogout() {
    try {
      await authFetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // Ignore error on logout
    }
    wsRef.current?.close();
    saveStoredPortalSession(portal, null);
    setSession(null);
    setSnapshot(null);
    setAuthInitialized(true);
  }

  async function handleSimulateProbe(category?: ThreatCategory) {
    setSimulating(true);
    setActionError(null);
    try {
      const res = await authFetch('/api/soc/threats/simulate', {
        method: 'POST',
        body: JSON.stringify({ category }),
      });
      if (!res.ok) {
        const errPayload = (await res.json().catch(() => ({}))) as { error?: string };
        setActionError(errPayload.error || 'Failed to trigger attack simulation');
        return;
      }
      const data = (await res.json()) as {
        alert: ThreatAlert;
        log: EncryptedLogEntry;
        notification: SecurityNotification;
        trafficSample?: TrafficSample;
        cluster?: ClusterConfig;
        simulation?: AttackSimulationState;
      };
      setSnapshot((prev) => {
        if (!prev) return prev;
        const alerts = prev.alerts.some((a) => a.id === data.alert.id)
          ? prev.alerts
          : [data.alert, ...prev.alerts].slice(0, 80);
        const encryptedLogs = prev.encryptedLogs.some((l) => l.id === data.log.id)
          ? prev.encryptedLogs
          : [data.log, ...prev.encryptedLogs].slice(0, 120);
        const notifications = prev.notifications.some((n) => n.id === data.notification.id)
          ? prev.notifications
          : [data.notification, ...prev.notifications].slice(0, 40);
        const trafficHistory =
          data.trafficSample && !prev.trafficHistory.some((s) => s.id === data.trafficSample!.id)
            ? [...prev.trafficHistory, data.trafficSample].slice(-60)
            : prev.trafficHistory;
        return {
          ...prev,
          alerts,
          encryptedLogs,
          notifications,
          trafficHistory,
          cluster: data.cluster ?? prev.cluster,
          simulation: data.simulation ?? prev.simulation,
        };
      });
      setToastAlert(data.alert);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Simulation failed');
    } finally {
      setSimulating(false);
    }
  }

  async function handleToggleContinuousSimulation(
    running: boolean,
    scenario: ThreatCategory | 'mixed' = 'mixed',
  ) {
    setActionError(null);
    try {
      const res = await authFetch('/api/soc/threats/simulation-mode', {
        method: 'POST',
        body: JSON.stringify({ running, scenario }),
      });
      if (!res.ok) {
        const errPayload = (await res.json().catch(() => ({}))) as { error?: string };
        setActionError(errPayload.error || 'Failed to update attack drill mode');
        return;
      }
      const data = (await res.json()) as {
        simulation: AttackSimulationState;
        firstWave: {
          alert: ThreatAlert;
          log: EncryptedLogEntry;
          notification: SecurityNotification;
          trafficSample?: TrafficSample;
          cluster?: ClusterConfig;
        } | null;
      };
      setSnapshot((prev) => {
        if (!prev) return prev;
        if (!data.firstWave) {
          return { ...prev, simulation: data.simulation };
        }
        const fw = data.firstWave;
        const alerts = prev.alerts.some((a) => a.id === fw.alert.id)
          ? prev.alerts
          : [fw.alert, ...prev.alerts].slice(0, 80);
        const encryptedLogs = prev.encryptedLogs.some((l) => l.id === fw.log.id)
          ? prev.encryptedLogs
          : [fw.log, ...prev.encryptedLogs].slice(0, 120);
        const notifications = prev.notifications.some((n) => n.id === fw.notification.id)
          ? prev.notifications
          : [fw.notification, ...prev.notifications].slice(0, 40);
        const trafficHistory =
          fw.trafficSample && !prev.trafficHistory.some((s) => s.id === fw.trafficSample!.id)
            ? [...prev.trafficHistory, fw.trafficSample].slice(-60)
            : prev.trafficHistory;
        return {
          ...prev,
          alerts,
          encryptedLogs,
          notifications,
          trafficHistory,
          cluster: fw.cluster ?? prev.cluster,
          simulation: data.simulation,
        };
      });
      if (data.firstWave) {
        setToastAlert(data.firstWave.alert);
      }
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Simulation mode error');
    }
  }

  async function handleMitigateAlert(
    id: string,
    action: 'block' | 'mitigate' | 'acknowledge',
  ) {
    const res = await authFetch(`/api/soc/alerts/${id}/mitigate`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    });
    if (res.ok) {
      const { alert } = (await res.json()) as { alert: ThreatAlert };
      setSnapshot((prev) =>
        prev
          ? {
              ...prev,
              alerts: prev.alerts.map((a) => (a.id === alert.id ? alert : a)),
              notifications: prev.notifications.map((n) =>
                n.alertId === alert.id ? { ...n, read: true } : n,
              ),
            }
          : prev,
      );
    }
  }

  async function handleMarkAllRead() {
    setToastAlert(null);
    setToastReport(null);
    setSnapshot((prev) => (prev ? { ...prev, notifications: [] } : prev));
    const res = await authFetch('/api/soc/notifications/mark-read', { method: 'POST' });
    if (res.ok) {
      const { notifications } = (await res.json()) as { notifications: SecurityNotification[] };
      setSnapshot((prev) => (prev ? { ...prev, notifications } : prev));
    }
  }

  if (authInitialized === null) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center text-sm text-slate-500">
        Loading security console...
      </div>
    );
  }

  if (!session) {
    return (
      <AuthGateway
        t={t}
        lang={lang}
        onChangeLang={setLang}
        initialized={authInitialized}
        portal={portal}
        onSwitchPortal={handleSwitchPortal}
        externalNotice={authNotice}
        onAuthenticated={(auth) => {
          setAuthNotice(null);
          saveStoredPortalSession(portal, auth);
          setSession(auth);
          setAuthInitialized(true);
          if (auth.roleKey !== 'admin' && activeTab === 'users') {
            setActiveTab('overview');
          }
        }}
      />
    );
  }

  if (!snapshot) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950 flex items-center justify-center text-sm text-slate-500">
        Loading live SOC telemetry...
      </div>
    );
  }

  const activeAlertCount = snapshot.alerts.filter(
    (a) => a.status === 'active' || a.status === 'investigating',
  ).length;
  const pendingUsersCount = snapshot.users.filter((u) => u.status === 'pending').length;
  const openComplaintsCount = snapshot.userReports.filter((r) => r.status !== 'resolved').length;
  const canSimulate = session.roleKey === 'admin' || session.roleKey === 'analyst';

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      <Sidebar
        t={t}
        activeTab={activeTab}
        onSelectTab={(tab) => {
          setActiveTab(tab);
          if (tab === 'users') {
            setAdminUsersSubTab('accounts');
          }
        }}
        wsConnected={wsConnected}
        userEmail={session.email}
        userRole={session.role}
        isAdmin={session.roleKey === 'admin'}
        portal={portal}
        activeAlertCount={activeAlertCount}
        pendingUsersCount={pendingUsersCount}
        openComplaintsCount={openComplaintsCount}
        onLogout={handleLogout}
        mobileOpen={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
      />

      <div className="flex-1 min-w-0 flex flex-col">
        <TopBar
          t={t}
          activeTab={activeTab}
          portal={portal}
          lang={lang}
          onChangeLang={setLang}
          isDark={isDark}
          onToggleTheme={() => setIsDark((d) => !d)}
          notifications={snapshot.notifications}
          onMarkAllRead={handleMarkAllRead}
          onSimulateProbe={() => handleSimulateProbe()}
          simulating={simulating}
          simulationRunning={snapshot.simulation.running}
          canSimulate={canSimulate}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
        />

        {actionError && (
          <div
            role="alert"
            className="mx-4 md:mx-6 mt-4 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-2.5 flex items-center justify-between gap-3 text-xs text-amber-900 dark:text-amber-200"
          >
            <span>{actionError}</span>
            <button
              type="button"
              onClick={() => setActionError(null)}
              aria-label="Dismiss error banner"
              className="p-1 hover:opacity-75"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {toastReport && session.roleKey === 'admin' && (
          <div
            role="status"
            data-testid="admin-complaint-toast"
            className="mx-4 md:mx-6 mt-4 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 px-4 py-3 flex flex-wrap items-center justify-between gap-3"
          >
            <div className="flex items-center gap-3 min-w-0">
              <MessageSquareWarning className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0" />
              <div className="text-xs min-w-0">
                <span className="font-semibold text-amber-900 dark:text-amber-100">
                  {toastReport.subject}
                </span>
                <span className="ml-2 font-mono text-amber-800 dark:text-amber-300">
                  {toastReport.userFullName} ({toastReport.userEmail}) · {toastReport.deviceInfo}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => {
                  setAdminUsersSubTab('complaints');
                  setActiveTab('users');
                  setToastReport(null);
                }}
                className="px-2.5 py-1 rounded-md bg-amber-600 hover:bg-amber-700 text-white text-xs font-medium whitespace-nowrap"
              >
                {t.users.viewComplaintsBtn}
              </button>
              <button
                type="button"
                onClick={() => setToastReport(null)}
                aria-label="Dismiss complaint banner"
                className="p-1 text-amber-700 dark:text-amber-300 hover:opacity-75"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {toastAlert && (
          <div
            role="status"
            className="mx-4 md:mx-6 mt-4 rounded-xl border border-red-200 dark:border-red-900/70 bg-red-50 dark:bg-red-950/40 px-4 py-3 flex flex-wrap items-center justify-between gap-3"
          >
            <div className="flex items-center gap-3 min-w-0">
              <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 shrink-0" />
              <div className="text-xs min-w-0">
                <span className="font-semibold text-red-800 dark:text-red-200">
                  {toastAlert.title}
                </span>
                <span className="ml-2 font-mono text-red-700 dark:text-red-300">
                  {toastAlert.sourceIp} ({toastAlert.sourceGeo}) -&gt; {toastAlert.destinationAsset} ({toastAlert.status})
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {canSimulate && toastAlert.status !== 'blocked' && (
                <button
                  type="button"
                  onClick={async () => {
                    await handleMitigateAlert(toastAlert.id, 'block');
                    setToastAlert((prev) => (prev ? { ...prev, status: 'blocked' } : prev));
                  }}
                  className="px-2.5 py-1 rounded-md bg-red-600 hover:bg-red-700 text-white text-xs font-medium whitespace-nowrap"
                >
                  {t.threats.blockIp}
                </button>
              )}
              <button
                type="button"
                onClick={() => setActiveTab('threats')}
                className="px-2.5 py-1 rounded-md border border-red-300 dark:border-red-800 text-xs font-medium text-red-800 dark:text-red-200 hover:bg-red-100 dark:hover:bg-red-900/40 whitespace-nowrap"
              >
                {t.threats.viewDetails}
              </button>
              {canSimulate && snapshot.simulation.running && (
                <button
                  type="button"
                  onClick={() => handleToggleContinuousSimulation(false)}
                  className="px-2.5 py-1 rounded-md bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 text-xs font-medium whitespace-nowrap"
                >
                  {t.threats.stopDrill}
                </button>
              )}
              <button
                type="button"
                onClick={() => setToastAlert(null)}
                aria-label="Dismiss alert banner"
                className="p-1 text-red-600 dark:text-red-300 hover:opacity-75"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        <main className="flex-1 p-4 md:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {activeTab === 'overview' && (
            <OverviewView
              t={t}
              snapshot={snapshot}
              isDark={isDark}
              onNavigate={setActiveTab}
              onMitigateAlert={handleMitigateAlert}
            />
          )}

          {activeTab === 'threats' && (
            <ThreatsView
              t={t}
              alerts={snapshot.alerts}
              rules={snapshot.automationRules}
              simulation={snapshot.simulation}
              simulating={simulating}
              canSimulate={canSimulate}
              onSimulateScenario={(cat) => handleSimulateProbe(cat)}
              onToggleDrill={handleToggleContinuousSimulation}
              onMitigateAlert={handleMitigateAlert}
              onToggleRule={async (id, enabled) => {
                const res = await authFetch(`/api/soc/rules/${id}`, {
                  method: 'PATCH',
                  body: JSON.stringify({ enabled }),
                });
                if (res.ok) {
                  const { rule } = (await res.json()) as { rule: AutomationRule };
                  setSnapshot((prev) =>
                    prev
                      ? {
                          ...prev,
                          automationRules: prev.automationRules.map((r) =>
                            r.id === rule.id ? rule : r,
                          ),
                        }
                      : prev,
                  );
                }
              }}
              onCreateRule={async (input: {
                name: string;
                minSeverity: SeverityLevel;
                action: AutomationRule['action'];
              }) => {
                const res = await authFetch('/api/soc/rules', {
                  method: 'POST',
                  body: JSON.stringify(input),
                });
                if (res.ok) {
                  const { rule } = (await res.json()) as { rule: AutomationRule };
                  setSnapshot((prev) =>
                    prev ? { ...prev, automationRules: [rule, ...prev.automationRules] } : prev,
                  );
                }
              }}
            />
          )}

          {activeTab === 'logs' && (
            <EncryptedLogsView
              t={t}
              logs={snapshot.encryptedLogs}
              activeKeyId={snapshot.activeKeyId}
              onDecryptLogs={async (logIds) => {
                const res = await authFetch('/api/soc/logs/decrypt', {
                  method: 'POST',
                  body: JSON.stringify({ logIds }),
                });
                const data = (await res.json()) as {
                  decrypted: Record<string, DecryptedLogPayload>;
                };
                return data.decrypted;
              }}
              onVerifyChain={async () => {
                const res = await authFetch('/api/soc/logs/verify-chain', { method: 'POST' });
                return (await res.json()) as {
                  valid: boolean;
                  verifiedCount: number;
                  brokenSequence: number | null;
                };
              }}
              onRotateKey={async () => {
                const res = await authFetch('/api/soc/logs/rotate-key', { method: 'POST' });
                if (res.ok) {
                  const data = (await res.json()) as { activeKeyId: string };
                  setSnapshot((prev) =>
                    prev ? { ...prev, activeKeyId: data.activeKeyId } : prev,
                  );
                }
              }}
            />
          )}

          {activeTab === 'siem' && (
            <SiemIntegrationsView
              t={t}
              connectors={snapshot.siemConnectors}
              apiKeys={snapshot.siemApiKeys}
              integrations={snapshot.integrations}
              complianceControls={snapshot.complianceControls}
              onToggleConnector={async (id, enabled, format?: SiemFormat) => {
                const res = await authFetch(`/api/soc/siem/connectors/${id}`, {
                  method: 'PATCH',
                  body: JSON.stringify({ enabled, format }),
                });
                if (res.ok) {
                  const { connector } = (await res.json()) as { connector: SiemConnector };
                  setSnapshot((prev) =>
                    prev
                      ? {
                          ...prev,
                          siemConnectors: prev.siemConnectors.map((c) =>
                            c.id === connector.id ? connector : c,
                          ),
                        }
                      : prev,
                  );
                }
              }}
              onTestConnector={async (id) => {
                const res = await authFetch(`/api/soc/siem/connectors/${id}/test`, {
                  method: 'POST',
                });
                const data = (await res.json()) as {
                  connector: SiemConnector;
                  dispatchedPayload: string;
                  deliveryLatencyMs: number;
                };
                setSnapshot((prev) =>
                  prev
                    ? {
                        ...prev,
                        siemConnectors: prev.siemConnectors.map((c) =>
                          c.id === data.connector.id ? data.connector : c,
                        ),
                      }
                    : prev,
                );
                return data;
              }}
              onCreateApiKey={async (label) => {
                const res = await authFetch('/api/soc/siem/keys', {
                  method: 'POST',
                  body: JSON.stringify({ label }),
                });
                const data = (await res.json()) as {
                  apiKey: SocSnapshot['siemApiKeys'][number];
                  rawSecret: string;
                };
                setSnapshot((prev) =>
                  prev ? { ...prev, siemApiKeys: [data.apiKey, ...prev.siemApiKeys] } : prev,
                );
                return { rawSecret: data.rawSecret };
              }}
              onRevokeApiKey={async (id) => {
                const res = await authFetch(`/api/soc/siem/keys/${id}`, { method: 'DELETE' });
                if (res.ok) {
                  setSnapshot((prev) =>
                    prev
                      ? {
                          ...prev,
                          siemApiKeys: prev.siemApiKeys.map((k) =>
                            k.id === id ? { ...k, revoked: true } : k,
                          ),
                        }
                      : prev,
                  );
                }
              }}
              onToggleIntegration={async (id, enabled) => {
                const res = await authFetch(`/api/soc/integrations/${id}`, {
                  method: 'PATCH',
                  body: JSON.stringify({ enabled }),
                });
                if (res.ok) {
                  const { integration } = (await res.json()) as {
                    integration: SocSnapshot['integrations'][number];
                  };
                  setSnapshot((prev) =>
                    prev
                      ? {
                          ...prev,
                          integrations: prev.integrations.map((i) =>
                            i.id === integration.id ? integration : i,
                          ),
                        }
                      : prev,
                  );
                }
              }}
            />
          )}

          {activeTab === 'reports' && (
            <ReportsAndScaleView
              t={t}
              reports={snapshot.weeklyReports}
              schedule={snapshot.reportSchedule}
              cluster={snapshot.cluster}
              onGenerateReport={async () => {
                const res = await authFetch('/api/soc/reports/generate', { method: 'POST' });
                if (res.ok) {
                  const { report } = (await res.json()) as { report: WeeklyReport };
                  setSnapshot((prev) =>
                    prev ? { ...prev, weeklyReports: [report, ...prev.weeklyReports] } : prev,
                  );
                }
              }}
              onUpdateSchedule={async (next) => {
                const res = await authFetch('/api/soc/reports/schedule', {
                  method: 'PATCH',
                  body: JSON.stringify(next),
                });
                if (res.ok) {
                  const { reportSchedule } = (await res.json()) as {
                    reportSchedule: WeeklyReportSchedule;
                  };
                  setSnapshot((prev) => (prev ? { ...prev, reportSchedule } : prev));
                }
              }}
              onUpdateCluster={async (next) => {
                const res = await authFetch('/api/soc/cluster', {
                  method: 'PATCH',
                  body: JSON.stringify(next),
                });
                if (res.ok) {
                  const { cluster } = (await res.json()) as { cluster: ClusterConfig };
                  setSnapshot((prev) => (prev ? { ...prev, cluster } : prev));
                }
              }}
            />
          )}

          {activeTab === 'users' && session.roleKey === 'admin' && (
            <AdminUsersView
              t={t}
              users={snapshot.users}
              userReports={snapshot.userReports}
              auditLogs={snapshot.accountAuditLogs}
              requireAdminApproval={snapshot.requireAdminApproval}
              adminEmail={session.email}
              initialSubTab={adminUsersSubTab}
              onToggleRequireApproval={async (required) => {
                const res = await authFetch('/api/admin/settings', {
                  method: 'PATCH',
                  body: JSON.stringify({ requireAdminApproval: required }),
                });
                if (res.ok) {
                  const data = (await res.json()) as { requireAdminApproval: boolean };
                  setSnapshot((prev) =>
                    prev ? { ...prev, requireAdminApproval: data.requireAdminApproval } : prev,
                  );
                }
              }}
              onControlUser={async (userId, payload: UserControlActionPayload) => {
                const res = await authFetch(`/api/admin/users/${userId}/control`, {
                  method: 'POST',
                  body: JSON.stringify(payload),
                });
                if (res.ok) {
                  const data = (await res.json()) as {
                    user: ManagedUserAccount;
                    auditEntry: AccountControlAuditEntry;
                    sessions: ActiveSessionInfo[];
                  };
                  setSnapshot((prev) => {
                    if (!prev) return prev;
                    const users = prev.users.map((u) =>
                      u.id === data.user.id ? data.user : u,
                    );
                    const accountAuditLogs = prev.accountAuditLogs.some(
                      (a) => a.id === data.auditEntry.id,
                    )
                      ? prev.accountAuditLogs
                      : [data.auditEntry, ...prev.accountAuditLogs].slice(0, 200);
                    return {
                      ...prev,
                      users,
                      accountAuditLogs,
                      sessions: data.sessions,
                    };
                  });
                }
              }}
              onRespondReport={async (reportId, payload: { status: ComplaintStatus; adminNote?: string }) => {
                const res = await authFetch(`/api/admin/reports/${reportId}/respond`, {
                  method: 'POST',
                  body: JSON.stringify(payload),
                });
                if (res.ok) {
                  const data = (await res.json()) as { report: UserComplaintReport };
                  setSnapshot((prev) =>
                    prev
                      ? {
                          ...prev,
                          userReports: prev.userReports.map((r) =>
                            r.id === data.report.id ? data.report : r,
                          ),
                        }
                      : prev,
                  );
                }
              }}
            />
          )}

          {activeTab === 'complaints' && (
            <UserReportsView
              t={t}
              reports={snapshot.userReports}
              onSubmitReport={async (input: {
                category: ComplaintCategory;
                severity: SeverityLevel;
                subject: string;
                description: string;
              }) => {
                setActionError(null);
                const res = await authFetch('/api/user/reports', {
                  method: 'POST',
                  body: JSON.stringify(input),
                });
                if (!res.ok) {
                  const errPayload = (await res.json().catch(() => ({}))) as { error?: string };
                  setActionError(errPayload.error || 'Failed to submit complaint');
                  return false;
                }
                const data = (await res.json()) as { report: UserComplaintReport };
                setSnapshot((prev) =>
                  prev
                    ? {
                        ...prev,
                        userReports: prev.userReports.some((r) => r.id === data.report.id)
                          ? prev.userReports
                          : [data.report, ...prev.userReports],
                      }
                    : prev,
                );
                return true;
              }}
            />
          )}

          {activeTab === 'mfa' && (
            <MfaSecurityView
              t={t}
              policy={snapshot.mfaPolicy}
              sessions={snapshot.sessions}
              onTogglePolicy={async (patch) => {
                const res = await authFetch('/api/soc/mfa/policy', {
                  method: 'PATCH',
                  body: JSON.stringify(patch),
                });
                if (res.ok) {
                  const { mfaPolicy } = (await res.json()) as {
                    mfaPolicy: SocSnapshot['mfaPolicy'];
                  };
                  setSnapshot((prev) => (prev ? { ...prev, mfaPolicy } : prev));
                }
              }}
              onRegenerateBackupCodes={async () => {
                const res = await authFetch('/api/soc/mfa/backup-codes', { method: 'POST' });
                const data = (await res.json()) as { backupCodes: string[]; remaining: number };
                setSnapshot((prev) =>
                  prev
                    ? {
                        ...prev,
                        mfaPolicy: { ...prev.mfaPolicy, backupCodesRemaining: data.remaining },
                      }
                    : prev,
                );
                return data.backupCodes;
              }}
            />
          )}
        </main>
      </div>
    </div>
  );
}
