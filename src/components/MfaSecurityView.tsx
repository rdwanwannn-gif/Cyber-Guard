import React, { useState } from 'react';
import { CheckCircle2, KeyRound, RefreshCw, ShieldCheck } from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type { ActiveSessionInfo } from '../lib/types';

interface MfaSecurityViewProps {
  t: Translations;
  policy: {
    requireMfaForDecryption: boolean;
    requireMfaForKeyRotation: boolean;
    backupCodesRemaining: number;
  };
  sessions: ActiveSessionInfo[];
  onTogglePolicy: (patch: {
    requireMfaForDecryption?: boolean;
    requireMfaForKeyRotation?: boolean;
  }) => Promise<void>;
  onRegenerateBackupCodes: () => Promise<string[]>;
}

export function MfaSecurityView({
  t,
  policy,
  sessions,
  onTogglePolicy,
  onRegenerateBackupCodes,
}: MfaSecurityViewProps) {
  const [newCodes, setNewCodes] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);

  async function handleRegenerate() {
    setBusy(true);
    try {
      const codes = await onRegenerateBackupCodes();
      setNewCodes(codes);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
          {t.mfa.title}
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t.mfa.subtitle}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
                {t.mfa.statusTitle}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">{t.mfa.totpStandard}</p>
            </div>
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
              <ShieldCheck className="w-4 h-4" aria-hidden="true" />
              <span>{t.mfa.mfaActiveLabel}</span>
            </span>
          </div>

          <div className="divide-y divide-slate-200 dark:divide-slate-800 border-t border-slate-200 dark:border-slate-800">
            <div className="py-4 flex items-center justify-between gap-4">
              <span className="text-sm text-slate-700 dark:text-slate-300">
                {t.mfa.policyDecryption}
              </span>
              <button
                type="button"
                role="switch"
                aria-checked={policy.requireMfaForDecryption}
                onClick={() =>
                  onTogglePolicy({ requireMfaForDecryption: !policy.requireMfaForDecryption })
                }
                className={`px-3 py-1 rounded-md text-xs font-medium border whitespace-nowrap ${
                  policy.requireMfaForDecryption
                    ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-300 dark:border-slate-700 text-slate-500'
                }`}
              >
                {policy.requireMfaForDecryption ? 'Enforced' : 'Optional'}
              </button>
            </div>

            <div className="py-4 flex items-center justify-between gap-4">
              <span className="text-sm text-slate-700 dark:text-slate-300">
                {t.mfa.policyKeyRotation}
              </span>
              <button
                type="button"
                role="switch"
                aria-checked={policy.requireMfaForKeyRotation}
                onClick={() =>
                  onTogglePolicy({ requireMfaForKeyRotation: !policy.requireMfaForKeyRotation })
                }
                className={`px-3 py-1 rounded-md text-xs font-medium border whitespace-nowrap ${
                  policy.requireMfaForKeyRotation
                    ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-300 dark:border-slate-700 text-slate-500'
                }`}
              >
                {policy.requireMfaForKeyRotation ? 'Enforced' : 'Optional'}
              </button>
            </div>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
                {t.mfa.backupCodesTitle}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono tabular-nums">
                {t.mfa.backupRemaining}: {policy.backupCodesRemaining}
              </p>
            </div>
            <button
              type="button"
              onClick={handleRegenerate}
              disabled={busy}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 text-white text-xs font-medium whitespace-nowrap"
            >
              <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{t.mfa.regenerateBackupBtn}</span>
            </button>
          </div>

          {newCodes.length > 0 && (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2">
              {newCodes.map((code) => (
                <code
                  key={code}
                  className="px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-xs text-center text-slate-900 dark:text-slate-100"
                >
                  {code}
                </code>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Active Sessions Audit Table */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
            {t.mfa.sessionsTitle}
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-500 dark:text-slate-400">
                <th className="py-3 px-6">{t.mfa.sessionEmail}</th>
                <th className="py-3 px-4">{t.mfa.sessionRole}</th>
                <th className="py-3 px-4">Session ID</th>
                <th className="py-3 px-6">{t.mfa.sessionVerified}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {sessions.map((ses) => (
                <tr key={ses.id}>
                  <td className="py-3.5 px-6 font-medium text-slate-900 dark:text-slate-100">
                    {ses.email}
                  </td>
                  <td className="py-3.5 px-4 text-slate-600 dark:text-slate-400">{ses.role}</td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-500 dark:text-slate-400">
                    {ses.id}
                  </td>
                  <td className="py-3.5 px-6">
                    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-600 dark:text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>TOTP Verified</span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
