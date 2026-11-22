import React, { useState } from 'react';
import {
  AlertOctagon,
  CheckCircle2,
  Plus,
  Search,
  ShieldBan,
  Zap,
} from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type {
  AttackSimulationState,
  AutomationRule,
  SeverityLevel,
  ThreatAlert,
  ThreatCategory,
} from '../lib/types';

interface ThreatsViewProps {
  t: Translations;
  alerts: ThreatAlert[];
  rules: AutomationRule[];
  simulation: AttackSimulationState;
  simulating?: boolean;
  canSimulate?: boolean;
  onSimulateScenario: (category: ThreatCategory) => void;
  onToggleDrill: (running: boolean, scenario?: ThreatCategory | 'mixed') => Promise<void>;
  onMitigateAlert: (id: string, action: 'block' | 'mitigate' | 'acknowledge') => void;
  onToggleRule: (id: string, enabled: boolean) => void;
  onCreateRule: (input: {
    name: string;
    minSeverity: SeverityLevel;
    action: AutomationRule['action'];
  }) => Promise<void>;
}

export function ThreatsView({
  t,
  alerts,
  rules,
  simulation,
  simulating = false,
  canSimulate = true,
  onSimulateScenario,
  onToggleDrill,
  onMitigateAlert,
  onToggleRule,
  onCreateRule,
}: ThreatsViewProps) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<'all' | SeverityLevel>('all');
  const [ruleName, setRuleName] = useState('');
  const [ruleMinSev, setRuleMinSev] = useState<SeverityLevel>('high');
  const [ruleAction, setRuleAction] = useState<AutomationRule['action']>('block_ip_and_notify');
  const [savingRule, setSavingRule] = useState(false);

  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      a.sourceIp.toLowerCase().includes(q) ||
      a.destinationAsset.toLowerCase().includes(q) ||
      a.title.toLowerCase().includes(q) ||
      a.signatureId.toLowerCase().includes(q)
    );
  });

  const scenarios: Array<{ id: ThreatCategory; label: string }> = [
    { id: 'ddos_volumetric', label: 'DDoS Flood' },
    { id: 'sqli_probe', label: 'SQL Injection' },
    { id: 'ssh_bruteforce', label: 'SSH Brute Force' },
    { id: 'c2_beacon', label: 'DNS C2 Beacon' },
    { id: 'data_exfiltration', label: 'Data Exfiltration' },
    { id: 'lateral_movement', label: 'Lateral Movement' },
  ];

  async function handleRuleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (ruleName.trim().length < 3) return;
    setSavingRule(true);
    try {
      await onCreateRule({
        name: ruleName.trim(),
        minSeverity: ruleMinSev,
        action: ruleAction,
      });
      setRuleName('');
    } finally {
      setSavingRule(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
            {t.threats.title}
          </h1>
          <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t.threats.subtitle}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
            {t.threats.triggerScenario}
          </span>
          {scenarios.map((sc) => (
            <button
              key={sc.id}
              type="button"
              disabled={simulating || !canSimulate}
              onClick={() => onSimulateScenario(sc.id)}
              className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 text-xs font-medium text-slate-700 dark:text-slate-200 transition-colors whitespace-nowrap"
            >
              <Zap className="w-3 h-3 text-amber-500" aria-hidden="true" />
              <span>{sc.label}</span>
            </button>
          ))}
          <button
            type="button"
            data-testid="toggle-continuous-drill"
            disabled={!canSimulate}
            onClick={() => onToggleDrill(!simulation.running, 'mixed')}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors whitespace-nowrap disabled:opacity-50 ${
              simulation.running
                ? 'bg-red-600 hover:bg-red-700 text-white'
                : 'bg-sky-600 hover:bg-sky-700 text-white'
            }`}
          >
            {simulation.running && (
              <span className="w-2 h-2 rounded-full bg-white animate-pulse" aria-hidden="true" />
            )}
            <span>{simulation.running ? t.threats.stopDrill : t.threats.startDrill}</span>
          </button>
        </div>
      </div>

      {(simulation.running || simulation.wavesSent > 0) && (
        <div
          data-testid="simulation-status-pill"
          className={`rounded-xl border px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs ${
            simulation.running
              ? 'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 text-amber-900 dark:text-amber-200'
              : 'border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300'
          }`}
        >
          <div className="flex items-center gap-2 font-medium">
            <span
              className={`w-2 h-2 rounded-full ${
                simulation.running ? 'bg-red-500 animate-pulse' : 'bg-emerald-500'
              }`}
              aria-hidden="true"
            />
            <span>
              {simulation.running ? t.threats.drillRunning : t.threats.triggerScenario}
            </span>
          </div>
          <div className="font-mono tabular-nums">
            {simulation.wavesSent} {t.threats.wavesExecuted}
            {simulation.lastTriggeredAt
              ? ` · ${simulation.lastTriggeredAt.slice(11, 19)} UTC`
              : ''}
          </div>
        </div>
      )}

      {/* Filter & Search Toolbar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search
            className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2"
            aria-hidden="true"
          />
          <label htmlFor="threat-search" className="sr-only">
            {t.threats.searchPlaceholder}
          </label>
          <input
            id="threat-search"
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t.threats.searchPlaceholder}
            className="w-full pl-9 pr-3.5 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
          />
        </div>

        <div
          role="group"
          aria-label={t.threats.severity}
          className="inline-flex items-center gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-800"
        >
          {(
            [
              ['all', t.threats.all],
              ['critical', t.threats.critical],
              ['high', t.threats.high],
              ['medium', t.threats.medium],
              ['low', t.threats.low],
            ] as const
          ).map(([val, label]) => (
            <button
              key={val}
              type="button"
              onClick={() => setSeverityFilter(val)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                severityFilter === val
                  ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-50 shadow-sm'
                  : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Table */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
            {t.threats.incidentTable}
          </h2>
          <span className="font-mono text-xs tabular-nums text-slate-500 dark:text-slate-400">
            {filteredAlerts.length} incidents
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-xs font-medium text-slate-500 dark:text-slate-400">
                <th className="py-3 px-6">{t.threats.vectorTactic}</th>
                <th className="py-3 px-4">{t.threats.sourceAsset}</th>
                <th className="py-3 px-4">{t.threats.severity}</th>
                <th className="py-3 px-4">{t.threats.status}</th>
                <th className="py-3 px-6 text-right">{t.threats.actions}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 px-6 text-center text-sm text-slate-500">
                    No matching threat incidents found.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                    <td className="py-3.5 px-6 max-w-md">
                      <div className="font-medium text-slate-900 dark:text-slate-100">
                        {alert.title}
                      </div>
                      <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                        {alert.summary}
                      </div>
                      <div className="text-xs font-mono text-slate-400 dark:text-slate-500 mt-1">
                        {alert.mitreTactic} · {alert.signatureId} ·{' '}
                        {alert.timestamp.slice(11, 19)} UTC
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-xs text-slate-700 dark:text-slate-300">
                      <div>
                        {alert.sourceIp}{' '}
                        <span className="text-slate-400 dark:text-slate-500">
                          ({alert.sourceGeo})
                        </span>
                      </div>
                      <div className="text-slate-500 dark:text-slate-400 mt-0.5">
                        -&gt; {alert.destinationAsset}:{alert.destinationPort} ({alert.protocol})
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`font-mono text-xs font-semibold uppercase ${
                          alert.severity === 'critical'
                            ? 'text-red-600 dark:text-red-400'
                            : alert.severity === 'high'
                              ? 'text-amber-600 dark:text-amber-400'
                              : 'text-sky-600 dark:text-sky-400'
                        }`}
                      >
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-700 dark:text-slate-300">
                        {alert.status === 'blocked' || alert.status === 'mitigated' ? (
                          <CheckCircle2
                            className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400"
                            aria-hidden="true"
                          />
                        ) : (
                          <AlertOctagon
                            className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400"
                            aria-hidden="true"
                          />
                        )}
                        <span className="capitalize">{alert.status}</span>
                      </span>
                    </td>
                    <td className="py-3.5 px-6 text-right">
                      <div className="inline-flex items-center gap-2">
                        {alert.status !== 'blocked' && (
                          <button
                            type="button"
                            onClick={() => onMitigateAlert(alert.id, 'block')}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-red-600 hover:bg-red-700 text-white text-xs font-medium whitespace-nowrap"
                          >
                            <ShieldBan className="w-3 h-3" aria-hidden="true" />
                            <span>{t.threats.blockIp}</span>
                          </button>
                        )}
                        {alert.status !== 'mitigated' && alert.status !== 'blocked' && (
                          <button
                            type="button"
                            onClick={() => onMitigateAlert(alert.id, 'mitigate')}
                            className="px-2.5 py-1 rounded-md border border-slate-300 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
                          >
                            {t.threats.resolve}
                          </button>
                        )}
                        {!alert.acknowledged && (
                          <button
                            type="button"
                            onClick={() => onMitigateAlert(alert.id, 'acknowledge')}
                            className="px-2.5 py-1 rounded-md text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
                          >
                            {t.threats.acknowledge}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Automated Notification & Response Rules */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
        <div>
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
            {t.threats.automationRulesTitle}
          </h2>
        </div>

        <form onSubmit={handleRuleSubmit} className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-5">
            <label htmlFor="rule-name-input" className="sr-only">
              {t.threats.ruleNamePlaceholder}
            </label>
            <input
              id="rule-name-input"
              type="text"
              required
              minLength={3}
              value={ruleName}
              onChange={(e) => setRuleName(e.target.value)}
              placeholder={t.threats.ruleNamePlaceholder}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100"
            />
          </div>
          <div className="md:col-span-2">
            <label htmlFor="rule-severity-select" className="sr-only">
              {t.threats.minSeverity}
            </label>
            <select
              id="rule-severity-select"
              value={ruleMinSev}
              onChange={(e) => setRuleMinSev(e.target.value as SeverityLevel)}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>
          <div className="md:col-span-3">
            <label htmlFor="rule-action-select" className="sr-only">
              {t.threats.ruleAction}
            </label>
            <select
              id="rule-action-select"
              value={ruleAction}
              onChange={(e) => setRuleAction(e.target.value as AutomationRule['action'])}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100"
            >
              <option value="block_ip_and_notify">Auto-Block IP + Notify</option>
              <option value="quarantine_host">Quarantine Host</option>
              <option value="siem_escalate">Escalate to SIEM</option>
              <option value="pagerduty_page">Page On-Call Team</option>
            </select>
          </div>
          <div className="md:col-span-2">
            <button
              type="submit"
              disabled={savingRule}
              className="w-full inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 text-white text-sm font-medium transition-colors whitespace-nowrap"
            >
              <Plus className="w-4 h-4" aria-hidden="true" />
              <span>{t.threats.saveRule}</span>
            </button>
          </div>
        </form>

        <div className="divide-y divide-slate-200 dark:divide-slate-800 border-t border-slate-200 dark:border-slate-800">
          {rules.map((rule) => (
            <div key={rule.id} className="py-3.5 flex flex-wrap items-center justify-between gap-4">
              <div>
                <div className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {rule.name}
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono">
                  Min: {rule.minSeverity.toUpperCase()} · Channels: {rule.channels.join(', ')} ·
                  Triggered {rule.triggerCount}x
                </div>
              </div>
              <button
                type="button"
                role="switch"
                aria-checked={rule.enabled}
                onClick={() => onToggleRule(rule.id, !rule.enabled)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors whitespace-nowrap ${
                  rule.enabled
                    ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400'
                }`}
              >
                {rule.enabled ? 'Enabled' : 'Paused'}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
