import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  MonitorSmartphone,
  PowerOff,
  Search,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  UserX,
  Users,
  MessageSquareWarning,
  Send,
} from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type {
  AccountControlAuditEntry,
  ComplaintStatus,
  ManagedUserAccount,
  UserAccountStatus,
  UserComplaintReport,
  UserRole,
} from '../lib/types';
import { filterManagedUsers, filterUserReports } from '../lib/userControl';

export interface UserControlActionPayload {
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
}

interface AdminUsersViewProps {
  t: Translations;
  users: ManagedUserAccount[];
  userReports: UserComplaintReport[];
  auditLogs: AccountControlAuditEntry[];
  requireAdminApproval: boolean;
  adminEmail: string;
  initialSubTab?: 'accounts' | 'complaints';
  onToggleRequireApproval: (required: boolean) => Promise<void>;
  onControlUser: (userId: string, payload: UserControlActionPayload) => Promise<void>;
  onRespondReport: (
    reportId: string,
    payload: { status: ComplaintStatus; adminNote?: string },
  ) => Promise<void>;
}

export function AdminUsersView({
  t,
  users,
  userReports,
  auditLogs,
  requireAdminApproval,
  adminEmail,
  initialSubTab = 'accounts',
  onToggleRequireApproval,
  onControlUser,
  onRespondReport,
}: AdminUsersViewProps) {
  const [subTab, setSubTab] = useState<'accounts' | 'complaints'>(initialSubTab);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<UserAccountStatus | 'all'>('all');
  const [reportSearch, setReportSearch] = useState('');
  const [reportFilter, setReportFilter] = useState<ComplaintStatus | 'all'>('all');
  const [reportNotes, setReportNotes] = useState<Record<string, string>>({});
  const [busyReportId, setBusyReportId] = useState<string | null>(null);
  const [editingNoteUserId, setEditingNoteUserId] = useState<string | null>(null);
  const [pendingActionType, setPendingActionType] = useState<
    'suspend' | 'block' | 'update_issue'
  >('update_issue');
  const [noteInput, setNoteInput] = useState('');
  const [busyUserId, setBusyUserId] = useState<string | null>(null);

  React.useEffect(() => {
    setSubTab(initialSubTab);
  }, [initialSubTab]);

  const filteredUsers = filterManagedUsers(users, search, statusFilter);
  const filteredReports = filterUserReports(userReports, reportSearch, reportFilter);
  const openReportsCount = userReports.filter((r) => r.status !== 'resolved').length;
  const pendingCount = users.filter((u) => u.status === 'pending').length;
  const activeCount = users.filter((u) => u.status === 'active').length;
  const restrictedCount = users.filter(
    (u) => u.status === 'suspended' || u.status === 'blocked',
  ).length;

  async function runAction(userId: string, payload: UserControlActionPayload) {
    setBusyUserId(userId);
    try {
      await onControlUser(userId, payload);
    } finally {
      setBusyUserId(null);
    }
  }

  function openNoteEditor(
    user: ManagedUserAccount,
    action: 'suspend' | 'block' | 'update_issue',
  ) {
    setEditingNoteUserId(user.id);
    setPendingActionType(action);
    setNoteInput(user.issueNote || '');
  }

  async function submitNoteEditor(userId: string) {
    await runAction(userId, {
      action: pendingActionType,
      issueFlagged: true,
      issueNote: noteInput,
    });
    setEditingNoteUserId(null);
    setNoteInput('');
  }

  const statusLabel = (status: UserAccountStatus) => {
    if (status === 'pending') return t.users.pending;
    if (status === 'active') return t.users.active;
    if (status === 'suspended') return t.users.suspended;
    return t.users.blocked;
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
            {t.users.title}
          </h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t.users.subtitle}</p>
        </div>

        <div className="text-xs font-mono text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900 px-3.5 py-2">
          Root Admin: <span className="text-slate-900 dark:text-slate-100 font-semibold">{adminEmail}</span>
        </div>
      </div>

      {/* 4-column KPI strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
            <span>{t.users.kpiTotal}</span>
            <Users className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-50">
            {users.length}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
            <span>{t.users.kpiPending}</span>
            <ShieldAlert
              className={`w-4 h-4 ${
                pendingCount > 0
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-slate-400 dark:text-slate-500'
              }`}
              aria-hidden="true"
            />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-50">
            {pendingCount}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
            <span>{t.users.kpiActive}</span>
            <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-50">
            {activeCount}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
            <span>{t.users.kpiRestricted}</span>
            <UserX
              className={`w-4 h-4 ${
                restrictedCount > 0
                  ? 'text-red-600 dark:text-red-400'
                  : 'text-slate-400 dark:text-slate-500'
              }`}
              aria-hidden="true"
            />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-50">
            {restrictedCount}
          </div>
        </div>
      </div>

      {/* Sub-navigation: User Accounts vs Incoming Complaints & Reports */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="inline-flex items-center gap-1 p-1 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
          <button
            type="button"
            data-testid="admin-accounts-tab"
            onClick={() => setSubTab('accounts')}
            className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors ${
              subTab === 'accounts'
                ? 'bg-sky-600 text-white'
                : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            <Users className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{t.users.tabAccounts}</span>
            <span className="font-mono opacity-85">({users.length})</span>
          </button>
          <button
            type="button"
            data-testid="admin-complaints-tab"
            onClick={() => setSubTab('complaints')}
            className={`inline-flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors ${
              subTab === 'complaints'
                ? 'bg-sky-600 text-white'
                : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            <MessageSquareWarning className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{t.users.tabComplaints}</span>
            <span className="font-mono opacity-85">
              ({openReportsCount}/{userReports.length})
            </span>
          </button>
        </div>
      </div>

      {subTab === 'complaints' ? (
        <div
          data-testid="admin-complaints-panel"
          className="space-y-4"
        >
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 flex flex-wrap items-center justify-between gap-3">
            <div className="relative flex-1 min-w-[240px]">
              <Search
                className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2"
                aria-hidden="true"
              />
              <input
                type="search"
                value={reportSearch}
                onChange={(e) => setReportSearch(e.target.value)}
                placeholder={t.users.searchPlaceholder}
                aria-label={t.users.searchPlaceholder}
                className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
              />
            </div>

            <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Complaint Status Filter">
              {(
                [
                  ['all', t.users.all],
                  ['open', t.complaints.statusOpen],
                  ['in_review', t.complaints.statusInReview],
                  ['resolved', t.complaints.statusResolved],
                ] as const
              ).map(([val, label]) => (
                <button
                  key={val}
                  type="button"
                  onClick={() => setReportFilter(val)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
                    reportFilter === val
                      ? 'bg-sky-600 text-white'
                      : 'border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 divide-y divide-slate-200 dark:divide-slate-800">
            {filteredReports.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-500 dark:text-slate-400">
                {t.users.complaintsEmpty}
              </div>
            ) : (
              filteredReports.map((report) => {
                const draftNote = reportNotes[report.id] ?? report.adminNote ?? '';
                const isBusy = busyReportId === report.id;
                return (
                  <div
                    key={report.id}
                    data-testid={`admin-report-item-${report.id}`}
                    className="p-5 space-y-3"
                  >
                    <div className="flex flex-wrap items-start justify-between gap-3">
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                            {report.subject}
                          </span>
                          <span
                            className={`font-mono text-[11px] uppercase font-semibold ${
                              report.severity === 'critical'
                                ? 'text-red-600 dark:text-red-400'
                                : report.severity === 'high'
                                  ? 'text-amber-600 dark:text-amber-400'
                                  : 'text-sky-600 dark:text-sky-400'
                            }`}
                          >
                            {report.severity}
                          </span>
                        </div>
                        <div className="mt-1 text-xs text-slate-600 dark:text-slate-400 flex flex-wrap items-center gap-2">
                          <span className="font-medium text-slate-800 dark:text-slate-200">
                            {report.userFullName} ({report.userEmail})
                          </span>
                          <span>· {report.department}</span>
                          <span className="font-mono">
                            · {report.deviceInfo} ({report.ipAddress})
                          </span>
                          <span className="font-mono">
                            · {report.createdAt.slice(0, 19).replace('T', ' ')} UTC
                          </span>
                        </div>
                      </div>

                      <span
                        data-testid={`admin-report-status-${report.id}`}
                        className={`px-2.5 py-1 rounded-md text-xs font-medium ${
                          report.status === 'resolved'
                            ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                            : report.status === 'in_review'
                              ? 'bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300'
                              : 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300'
                        }`}
                      >
                        {report.status === 'resolved'
                          ? t.complaints.statusResolved
                          : report.status === 'in_review'
                            ? t.complaints.statusInReview
                            : t.complaints.statusOpen}
                      </span>
                    </div>

                    <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap">
                      {report.description}
                    </p>

                    {report.handledBy && (
                      <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                        {t.users.handledByLabel}: {report.handledBy}
                      </div>
                    )}

                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      <input
                        type="text"
                        data-testid={`admin-report-note-${report.id}`}
                        value={draftNote}
                        onChange={(e) =>
                          setReportNotes((prev) => ({ ...prev, [report.id]: e.target.value }))
                        }
                        placeholder={t.users.respondNotePlaceholder}
                        className="flex-1 min-w-[220px] px-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                      />
                      {report.status !== 'in_review' && (
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={async () => {
                            setBusyReportId(report.id);
                            try {
                              await onRespondReport(report.id, {
                                status: 'in_review',
                                adminNote: draftNote,
                              });
                            } finally {
                              setBusyReportId(null);
                            }
                          }}
                          className="px-3 py-1.5 rounded-lg border border-sky-300 dark:border-sky-800 bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 text-xs font-medium whitespace-nowrap"
                        >
                          {t.users.markInReviewBtn}
                        </button>
                      )}
                      {report.status !== 'resolved' && (
                        <button
                          type="button"
                          disabled={isBusy}
                          onClick={async () => {
                            setBusyReportId(report.id);
                            try {
                              await onRespondReport(report.id, {
                                status: 'resolved',
                                adminNote: draftNote,
                              });
                            } finally {
                              setBusyReportId(null);
                            }
                          }}
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium whitespace-nowrap"
                        >
                          <Send className="w-3 h-3" aria-hidden="true" />
                          <span>{t.users.markResolvedBtn}</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      ) : (
        <>
          {/* Registration Policy + Filter Bar */}
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-200 dark:border-slate-800">
          <div>
            <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              {t.users.requireApprovalLabel}
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {t.users.requireApprovalHint}
            </div>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={requireAdminApproval}
            onClick={() => onToggleRequireApproval(!requireAdminApproval)}
            className={`px-3.5 py-2 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
              requireAdminApproval
                ? 'bg-sky-600 text-white hover:bg-sky-700'
                : 'border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            {requireAdminApproval ? 'Approval Gate: ON' : 'Auto-Activate: ON'}
          </button>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="relative flex-1 min-w-[240px]">
            <Search
              className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2"
              aria-hidden="true"
            />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t.users.searchPlaceholder}
              aria-label={t.users.searchPlaceholder}
              className="w-full pl-9 pr-3 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Status Filter">
            {(['all', 'pending', 'active', 'suspended', 'blocked'] as const).map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => setStatusFilter(status)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
                  statusFilter === status
                    ? 'bg-sky-600 text-white'
                    : 'border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                }`}
              >
                {t.users[status]}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Registered Users Control Table */}
      <div
        data-testid="admin-users-table"
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-500 dark:text-slate-400">
                <th className="py-3.5 px-6">{t.users.userColumn}</th>
                <th className="py-3.5 px-4">{t.users.deviceColumn}</th>
                <th className="py-3.5 px-4">{t.users.roleColumn}</th>
                <th className="py-3.5 px-4">{t.users.statusColumn}</th>
                <th className="py-3.5 px-6 text-right">{t.users.controlsColumn}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {filteredUsers.length === 0 ? (
                <tr>
                  <td
                    colSpan={5}
                    className="py-10 px-6 text-center text-sm text-slate-500 dark:text-slate-400"
                  >
                    {t.users.emptyState}
                  </td>
                </tr>
              ) : (
                filteredUsers.map((user) => {
                  const isBusy = busyUserId === user.id;
                  const isEditingNote = editingNoteUserId === user.id;
                  return (
                    <React.Fragment key={user.id}>
                      <tr
                        data-testid={`managed-user-row-${user.email}`}
                        className="hover:bg-slate-50 dark:hover:bg-slate-800/40 align-top"
                      >
                        <td className="py-4 px-6">
                          <div className="font-medium text-slate-900 dark:text-slate-100">
                            {user.fullName}
                          </div>
                          <div className="text-xs font-mono text-slate-600 dark:text-slate-400 mt-0.5">
                            {user.email}
                          </div>
                          <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                            {user.department} · <span className="font-mono">{user.id}</span>
                          </div>
                          {user.issueFlagged && (
                            <div className="mt-2 flex items-start gap-1.5 text-xs text-amber-700 dark:text-amber-300">
                              <AlertTriangle className="w-3.5 h-3.5 mt-0.5 shrink-0" aria-hidden="true" />
                              <span>{user.issueNote || 'Flagged for Admin Review'}</span>
                            </div>
                          )}
                        </td>

                        <td className="py-4 px-4 text-xs text-slate-700 dark:text-slate-300">
                          <div className="flex items-center gap-1.5 font-medium">
                            <MonitorSmartphone className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400 shrink-0" aria-hidden="true" />
                            <span>{user.deviceInfo}</span>
                          </div>
                          <div className="font-mono text-slate-500 dark:text-slate-400 mt-0.5">
                            IP: {user.registeredIp}
                          </div>
                          <div className="font-mono text-slate-500 dark:text-slate-400 mt-0.5">
                            {user.registeredAt.slice(0, 19).replace('T', ' ')} UTC
                          </div>
                        </td>

                        <td className="py-4 px-4">
                          <label htmlFor={`role-select-${user.id}`} className="sr-only">
                            {t.users.roleColumn}
                          </label>
                          <select
                            id={`role-select-${user.id}`}
                            value={user.role}
                            disabled={isBusy}
                            onChange={(e) =>
                              runAction(user.id, {
                                action: 'change_role',
                                role: e.target.value as UserRole,
                              })
                            }
                            className="px-2.5 py-1.5 text-xs font-medium rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                          >
                            <option value="analyst">SOC Analyst</option>
                            <option value="viewer">Security Viewer</option>
                            <option value="admin">Admin</option>
                          </select>
                        </td>

                        <td className="py-4 px-4">
                          <div className="flex items-center gap-1.5 text-xs font-mono font-semibold uppercase">
                            {user.status === 'active' ? (
                              <CheckCircle2
                                className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400"
                                aria-hidden="true"
                              />
                            ) : user.status === 'pending' ? (
                              <ShieldAlert
                                className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400"
                                aria-hidden="true"
                              />
                            ) : (
                              <UserX
                                className="w-3.5 h-3.5 text-red-600 dark:text-red-400"
                                aria-hidden="true"
                              />
                            )}
                            <span
                              data-testid={`user-status-${user.email}`}
                              className={
                                user.status === 'active'
                                  ? 'text-emerald-600 dark:text-emerald-400'
                                  : user.status === 'pending'
                                    ? 'text-amber-600 dark:text-amber-400'
                                    : 'text-red-600 dark:text-red-400'
                              }
                            >
                              {statusLabel(user.status)}
                            </span>
                          </div>
                          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                            {user.mfaEnrolled ? t.users.mfaEnrolled : t.users.mfaPending}
                          </div>
                          <div className="mt-0.5 text-xs font-mono text-slate-500 dark:text-slate-400 tabular-nums">
                            {user.activeSessionCount} {t.users.activeSessions}
                          </div>
                        </td>

                        <td className="py-4 px-6 text-right">
                          <div className="inline-flex flex-wrap justify-end gap-1.5">
                            {user.status !== 'active' && (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() =>
                                  runAction(user.id, { action: 'activate', issueFlagged: false })
                                }
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-700 disabled:opacity-60 text-white text-xs font-medium whitespace-nowrap"
                              >
                                <UserCheck className="w-3.5 h-3.5" aria-hidden="true" />
                                <span>{t.users.activateBtn}</span>
                              </button>
                            )}

                            {user.status !== 'suspended' && (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() => openNoteEditor(user, 'suspend')}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-300 hover:bg-amber-100 dark:hover:bg-amber-900/50 text-xs font-medium whitespace-nowrap"
                              >
                                <span>{t.users.suspendBtn}</span>
                              </button>
                            )}

                            {user.status !== 'blocked' && (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() => openNoteEditor(user, 'block')}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md bg-red-600 hover:bg-red-700 disabled:opacity-60 text-white text-xs font-medium whitespace-nowrap"
                              >
                                <span>{t.users.blockBtn}</span>
                              </button>
                            )}

                            <button
                              type="button"
                              disabled={isBusy}
                              onClick={() => runAction(user.id, { action: 'reset_mfa' })}
                              title={t.users.resetMfaBtn}
                              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-medium whitespace-nowrap"
                            >
                              <KeyRound className="w-3.5 h-3.5" aria-hidden="true" />
                              <span>{t.users.resetMfaBtn}</span>
                            </button>

                            {user.activeSessionCount > 0 && (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() => runAction(user.id, { action: 'revoke_sessions' })}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-medium whitespace-nowrap"
                              >
                                <PowerOff className="w-3.5 h-3.5" aria-hidden="true" />
                                <span>{t.users.revokeSessionsBtn}</span>
                              </button>
                            )}

                            {user.issueFlagged ? (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() =>
                                  runAction(user.id, {
                                    action: 'update_issue',
                                    issueFlagged: false,
                                    issueNote: '',
                                  })
                                }
                                className="px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-medium whitespace-nowrap"
                              >
                                {t.users.resolveIssueBtn}
                              </button>
                            ) : (
                              <button
                                type="button"
                                disabled={isBusy}
                                onClick={() => openNoteEditor(user, 'update_issue')}
                                className="px-2.5 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-medium whitespace-nowrap"
                              >
                                {t.users.flagIssueBtn}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>

                      {isEditingNote && (
                        <tr className="bg-slate-50/70 dark:bg-slate-800/40">
                          <td colSpan={5} className="px-6 py-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <input
                                type="text"
                                value={noteInput}
                                onChange={(e) => setNoteInput(e.target.value)}
                                placeholder={t.users.issueNotePlaceholder}
                                className="flex-1 min-w-[220px] px-3 py-1.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                              />
                              <button
                                type="button"
                                onClick={() => submitNoteEditor(user.id)}
                                className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-700 text-white text-xs font-medium whitespace-nowrap"
                              >
                                {pendingActionType === 'suspend'
                                  ? t.users.suspendBtn
                                  : pendingActionType === 'block'
                                    ? t.users.blockBtn
                                    : t.users.saveIssueBtn}
                              </button>
                              <button
                                type="button"
                                onClick={() => {
                                  setEditingNoteUserId(null);
                                  setNoteInput('');
                                }}
                                className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
                              >
                                {t.users.cancelBtn}
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Admin Control Audit Log */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
            {t.users.auditTitle}
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {t.users.auditSubtitle}
          </p>
        </div>

        <div className="divide-y divide-slate-200 dark:divide-slate-800 max-h-72 overflow-y-auto">
          {auditLogs.length === 0 ? (
            <div className="p-6 text-xs text-slate-500 dark:text-slate-400">
              {t.users.emptyState}
            </div>
          ) : (
            auditLogs.slice(0, 25).map((entry) => (
              <div
                key={entry.id}
                className="px-6 py-3 flex flex-wrap items-center justify-between gap-2 text-xs"
              >
                <div className="min-w-0">
                  <span className="font-mono font-semibold text-sky-600 dark:text-sky-400 uppercase mr-2">
                    {entry.action}
                  </span>
                  <span className="font-medium text-slate-900 dark:text-slate-100">
                    {entry.targetEmail}
                  </span>
                  <span className="text-slate-500 dark:text-slate-400 ml-2">
                    — {entry.detail}
                  </span>
                </div>
                <div className="font-mono text-slate-500 dark:text-slate-400 whitespace-nowrap">
                  {entry.ipAddress} · {entry.timestamp.slice(0, 19).replace('T', ' ')} UTC
                </div>
              </div>
            ))
          )}
        </div>
      </div>
        </>
      )}
    </div>
  );
}
