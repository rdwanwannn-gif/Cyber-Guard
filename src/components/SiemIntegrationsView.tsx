import React, { useState } from 'react';
import {
  CheckCircle2,
  Copy,
  KeyRound,
  Plus,
  Send,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type {
  ComplianceControl,
  SiemApiKey,
  SiemConnector,
  SiemFormat,
  ThirdPartyIntegration,
} from '../lib/types';

interface SiemIntegrationsViewProps {
  t: Translations;
  connectors: SiemConnector[];
  apiKeys: SiemApiKey[];
  integrations: ThirdPartyIntegration[];
  complianceControls: ComplianceControl[];
  onToggleConnector: (id: string, enabled: boolean, format?: SiemFormat) => Promise<void>;
  onTestConnector: (id: string) => Promise<{ dispatchedPayload: string; deliveryLatencyMs: number }>;
  onCreateApiKey: (label: string) => Promise<{ rawSecret: string }>;
  onRevokeApiKey: (id: string) => Promise<void>;
  onToggleIntegration: (id: string, enabled: boolean) => Promise<void>;
}

export function SiemIntegrationsView({
  t,
  connectors,
  apiKeys,
  integrations,
  complianceControls,
  onToggleConnector,
  onTestConnector,
  onCreateApiKey,
  onRevokeApiKey,
  onToggleIntegration,
}: SiemIntegrationsViewProps) {
  const [newKeyLabel, setNewKeyLabel] = useState('');
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const [lastPayload, setLastPayload] = useState<{
    vendor: string;
    latency: number;
    payload: string;
  } | null>(null);
  const [creatingKey, setCreatingKey] = useState(false);

  async function handleCreateKey(e: React.FormEvent) {
    e.preventDefault();
    if (newKeyLabel.trim().length < 3) return;
    setCreatingKey(true);
    try {
      const res = await onCreateApiKey(newKeyLabel.trim());
      setRevealedSecret(res.rawSecret);
      setNewKeyLabel('');
    } finally {
      setCreatingKey(false);
    }
  }

  async function handleTestSync(connector: SiemConnector) {
    const res = await onTestConnector(connector.id);
    setLastPayload({
      vendor: connector.vendor,
      latency: res.deliveryLatencyMs,
      payload: res.dispatchedPayload,
    });
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
          {t.siem.title}
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t.siem.subtitle}</p>
      </div>

      {/* SIEM Connectors Grid */}
      <div className="space-y-4">
        <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
          {t.siem.connectorsTitle}
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {connectors.map((c) => (
            <div
              key={c.id}
              className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 space-y-4"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-display text-sm font-semibold text-slate-900 dark:text-slate-50">
                    {c.name}
                  </div>
                  <div className="text-xs font-mono text-slate-500 dark:text-slate-400 mt-0.5 break-all">
                    {c.endpointUrl}
                  </div>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={c.enabled}
                  onClick={() => onToggleConnector(c.id, !c.enabled)}
                  className={`px-2.5 py-1 rounded-md text-xs font-medium border whitespace-nowrap ${
                    c.enabled
                      ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                      : 'border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400'
                  }`}
                >
                  {c.enabled ? 'Active' : 'Standby'}
                </button>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-slate-200 dark:border-slate-800 text-xs">
                <div className="font-mono tabular-nums text-slate-600 dark:text-slate-300">
                  {c.eventsSynced.toLocaleString()} {t.siem.eventsSynced} · {c.avgLatencyMs}ms
                </div>

                <div className="flex items-center gap-2">
                  <label htmlFor={`fmt-${c.id}`} className="sr-only">
                    Payload Format
                  </label>
                  <select
                    id={`fmt-${c.id}`}
                    value={c.format}
                    onChange={(e) =>
                      onToggleConnector(c.id, c.enabled, e.target.value as SiemFormat)
                    }
                    className="px-2 py-1 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 font-mono text-xs"
                  >
                    <option value="JSON">JSON</option>
                    <option value="CEF">CEF</option>
                    <option value="LEEF">LEEF</option>
                  </select>

                  <button
                    type="button"
                    onClick={() => handleTestSync(c)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-sky-600 hover:bg-sky-700 text-white text-xs font-medium whitespace-nowrap"
                  >
                    <Send className="w-3 h-3" aria-hidden="true" />
                    <span>{t.siem.testSync}</span>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>

        {lastPayload && (
          <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
            <div className="flex items-center justify-between text-xs mb-2">
              <span className="font-semibold text-slate-900 dark:text-slate-100">
                {t.siem.payloadPreview} · {lastPayload.vendor}
              </span>
              <span className="font-mono text-emerald-600 dark:text-emerald-400">
                200 OK · {lastPayload.latency}ms
              </span>
            </div>
            <pre className="p-3 rounded-lg bg-slate-950 text-slate-100 font-mono text-xs overflow-x-auto">
              {lastPayload.payload}
            </pre>
          </div>
        )}
      </div>

      {/* SIEM Ingestion API Keys */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
            {t.siem.apiKeysTitle}
          </h2>
        </div>

        <form onSubmit={handleCreateKey} className="flex flex-col sm:flex-row gap-3">
          <label htmlFor="siem-key-label" className="sr-only">
            {t.siem.keyLabelPlaceholder}
          </label>
          <input
            id="siem-key-label"
            type="text"
            required
            minLength={3}
            value={newKeyLabel}
            onChange={(e) => setNewKeyLabel(e.target.value)}
            placeholder={t.siem.keyLabelPlaceholder}
            className="flex-1 px-3.5 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100"
          />
          <button
            type="submit"
            disabled={creatingKey}
            className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 text-white text-sm font-medium whitespace-nowrap"
          >
            <Plus className="w-4 h-4" aria-hidden="true" />
            <span>{t.siem.createKeyBtn}</span>
          </button>
        </form>

        {revealedSecret && (
          <div className="rounded-lg border border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/30 p-3.5 text-xs space-y-2">
            <div className="font-medium text-emerald-800 dark:text-emerald-300">
              {t.siem.copyOnceWarning}
            </div>
            <div className="flex items-center justify-between gap-2 font-mono bg-white dark:bg-slate-950 px-3 py-2 rounded border border-emerald-200 dark:border-emerald-900">
              <span className="break-all text-slate-900 dark:text-slate-100">{revealedSecret}</span>
              <button
                type="button"
                onClick={() => navigator.clipboard?.writeText(revealedSecret)}
                aria-label="Copy API key"
                className="p-1 text-slate-500 hover:text-slate-900 dark:hover:text-slate-100 shrink-0"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        <div className="divide-y divide-slate-200 dark:divide-slate-800 border-t border-slate-200 dark:border-slate-800">
          {apiKeys.map((k) => (
            <div key={k.id} className="py-3 flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <KeyRound className="w-4 h-4 text-slate-400 shrink-0" aria-hidden="true" />
                <div>
                  <div className="text-sm font-medium text-slate-900 dark:text-slate-100">
                    {k.label}
                  </div>
                  <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                    {k.prefix}... · Scopes: {k.scopes.join(', ')}
                  </div>
                </div>
              </div>

              {k.revoked ? (
                <span className="font-mono text-xs text-red-600 dark:text-red-400">Revoked</span>
              ) : (
                <button
                  type="button"
                  onClick={() => onRevokeApiKey(k.id)}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-300 dark:border-slate-700 text-xs font-medium text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 whitespace-nowrap"
                >
                  <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>{t.siem.revokeBtn}</span>
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Third-Party Platforms & Industry Compliance */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
            {t.siem.thirdPartyTitle}
          </h2>
          <div className="divide-y divide-slate-200 dark:divide-slate-800">
            {integrations.map((item) => (
              <div key={item.id} className="py-3.5 flex items-start justify-between gap-4">
                <div>
                  <div className="text-sm font-medium text-slate-900 dark:text-slate-100">
                    {item.name}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                    {item.description}
                  </div>
                  <div className="text-xs font-mono text-slate-400 dark:text-slate-500 mt-1 tabular-nums">
                    {item.syncMode} · {item.eventsDispatched.toLocaleString()} dispatched
                  </div>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={item.enabled}
                  onClick={() => onToggleIntegration(item.id, !item.enabled)}
                  className={`px-3 py-1 rounded-md text-xs font-medium border whitespace-nowrap shrink-0 ${
                    item.enabled
                      ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                      : 'border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400'
                  }`}
                >
                  {item.enabled ? 'Connected' : 'Disabled'}
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
            {t.siem.complianceTitle}
          </h2>
          <div className="divide-y divide-slate-200 dark:divide-slate-800">
            {complianceControls.map((ctrl) => (
              <div key={ctrl.framework} className="py-3.5 flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 text-sm font-medium text-slate-900 dark:text-slate-100">
                    <ShieldCheck
                      className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0"
                      aria-hidden="true"
                    />
                    <span>{ctrl.framework}</span>
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                    {ctrl.evidenceSummary}
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <div className="font-mono text-sm font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">
                    {ctrl.coveragePercent}%
                  </div>
                  <div className="inline-flex items-center gap-1 text-[11px] text-slate-500 dark:text-slate-400">
                    <CheckCircle2 className="w-3 h-3 text-emerald-500" aria-hidden="true" />
                    <span className="capitalize">{ctrl.status}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
