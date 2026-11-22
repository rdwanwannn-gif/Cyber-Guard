import React, { useState } from 'react';
import { CheckCircle2, KeyRound, Lock, RefreshCw, ShieldCheck, Unlock } from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type { DecryptedLogPayload, EncryptedLogEntry } from '../lib/types';

interface EncryptedLogsViewProps {
  t: Translations;
  logs: EncryptedLogEntry[];
  activeKeyId: string;
  onDecryptLogs: (logIds: string[]) => Promise<Record<string, DecryptedLogPayload>>;
  onVerifyChain: () => Promise<{ valid: boolean; verifiedCount: number; brokenSequence: number | null }>;
  onRotateKey: () => Promise<void>;
}

export function EncryptedLogsView({
  t,
  logs,
  activeKeyId,
  onDecryptLogs,
  onVerifyChain,
  onRotateKey,
}: EncryptedLogsViewProps) {
  const [vaultUnlocked, setVaultUnlocked] = useState(false);
  const [decryptedMap, setDecryptedMap] = useState<Record<string, DecryptedLogPayload>>({});
  const [chainResult, setChainResult] = useState<{
    valid: boolean;
    verifiedCount: number;
    brokenSequence: number | null;
  } | null>(null);
  const [busyAction, setBusyAction] = useState<string | null>(null);

  const hasDecryptedAny = vaultUnlocked || Object.keys(decryptedMap).length > 0;

  React.useEffect(() => {
    if (!vaultUnlocked) return;
    const missing = logs
      .slice(0, 20)
      .map((l) => l.id)
      .filter((id) => !decryptedMap[id]);
    if (missing.length === 0) return;
    let cancelled = false;
    onDecryptLogs(missing).then((res) => {
      if (!cancelled && res) {
        setDecryptedMap((prev) => ({ ...prev, ...res }));
      }
    });
    return () => {
      cancelled = true;
    };
  }, [vaultUnlocked, logs, decryptedMap, onDecryptLogs]);

  async function handleToggleDecryptAll() {
    if (hasDecryptedAny) {
      setVaultUnlocked(false);
      setDecryptedMap({});
      return;
    }
    setBusyAction('decrypt');
    try {
      const targetIds = logs.slice(0, 20).map((l) => l.id);
      const result = await onDecryptLogs(targetIds);
      setDecryptedMap(result);
      setVaultUnlocked(true);
    } finally {
      setBusyAction(null);
    }
  }

  async function handleVerifyChain() {
    setBusyAction('verify');
    try {
      const res = await onVerifyChain();
      setChainResult(res);
    } finally {
      setBusyAction(null);
    }
  }

  async function handleRotateKey() {
    setBusyAction('rotate');
    try {
      await onRotateKey();
    } finally {
      setBusyAction(null);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
            {t.logs.title}
          </h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t.logs.subtitle}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={handleVerifyChain}
            disabled={busyAction !== null}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
          >
            <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
            <span>{t.logs.verifyChain}</span>
          </button>

          <button
            type="button"
            onClick={handleRotateKey}
            disabled={busyAction !== null}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
          >
            <RefreshCw className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
            <span>{t.logs.rotateKey}</span>
          </button>

          <button
            type="button"
            onClick={handleToggleDecryptAll}
            disabled={busyAction !== null}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 text-white text-xs font-medium whitespace-nowrap"
          >
            {hasDecryptedAny ? (
              <Lock className="w-4 h-4" aria-hidden="true" />
            ) : (
              <Unlock className="w-4 h-4" aria-hidden="true" />
            )}
            <span>{hasDecryptedAny ? t.logs.hidePlaintext : t.logs.decryptAll}</span>
          </button>
        </div>
      </div>

      {/* Key Metadata Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">{t.logs.activeKey}</div>
          <div className="mt-1 flex items-center gap-2 font-mono text-sm font-semibold text-slate-900 dark:text-slate-50">
            <KeyRound className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
            <span>{activeKeyId}</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">{t.logs.algorithm}</div>
          <div className="mt-1 font-mono text-sm font-semibold text-slate-900 dark:text-slate-50">
            AES-256-GCM + SHA-256 Chain
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
          <div className="text-xs text-slate-500 dark:text-slate-400">Hash Chain Status</div>
          <div className="mt-1 text-sm font-medium">
            {chainResult ? (
              chainResult.valid ? (
                <span className="inline-flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
                  <CheckCircle2 className="w-4 h-4" aria-hidden="true" />
                  <span>
                    {t.logs.chainVerifiedOk} ({chainResult.verifiedCount})
                  </span>
                </span>
              ) : (
                <span className="text-red-600 dark:text-red-400">
                  {t.logs.chainBroken} #{chainResult.brokenSequence}
                </span>
              )
            ) : (
              <span className="font-mono text-slate-600 dark:text-slate-300">
                {logs.length} sealed records
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Encrypted Vault Table */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 font-medium text-slate-500 dark:text-slate-400">
                <th className="py-3 px-4">{t.logs.sequence}</th>
                <th className="py-3 px-4">{t.logs.timestamp}</th>
                <th className="py-3 px-4">{t.logs.endpoint}</th>
                <th className="py-3 px-4">{t.logs.ciphertextPreview}</th>
                <th className="py-3 px-4">{t.logs.integrityHash}</th>
                <th className="py-3 px-4">{t.logs.payloadStatus}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800 font-mono">
              {logs.slice(0, 20).map((entry) => {
                const plain = decryptedMap[entry.id];
                return (
                  <tr key={entry.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="py-3 px-4 tabular-nums text-slate-500 dark:text-slate-400">
                      #{entry.sequence}
                    </td>
                    <td className="py-3 px-4 tabular-nums text-slate-700 dark:text-slate-300 whitespace-nowrap">
                      {entry.timestamp.slice(11, 19)} UTC
                    </td>
                    <td className="py-3 px-4 text-slate-800 dark:text-slate-200 whitespace-nowrap">
                      {entry.sourceIp} :{entry.destinationPort} · {entry.protocol}
                    </td>
                    <td className="py-3 px-4 text-slate-500 dark:text-slate-400 max-w-[200px] truncate">
                      {entry.envelope.ciphertext.slice(0, 28)}...
                    </td>
                    <td className="py-3 px-4 text-slate-500 dark:text-slate-400">
                      {entry.integrityHash.slice(0, 14)}...
                    </td>
                    <td className="py-3 px-4 font-sans">
                      {plain ? (
                        <div className="space-y-0.5 text-emerald-700 dark:text-emerald-300">
                          <div className="font-semibold">
                            {plain.action} · {plain.bytes.toLocaleString()} B ·{' '}
                            {plain.userAgentOrProcess}
                          </div>
                          {plain.threatSignature && (
                            <div className="font-mono text-[11px] text-amber-600 dark:text-amber-400">
                              {plain.threatSignature} · {plain.tlsCipher}
                            </div>
                          )}
                        </div>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-slate-500 dark:text-slate-400">
                          <Lock className="w-3 h-3" aria-hidden="true" />
                          <span>
                            {t.logs.encryptedLabel} · {entry.keyId}
                          </span>
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
