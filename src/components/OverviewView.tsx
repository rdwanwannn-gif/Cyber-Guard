import React, { useState } from 'react';
import {
  Activity,
  AlertOctagon,
  CheckCircle2,
  Lock,
  Server,
  ShieldBan,
  ArrowRight,
} from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type { SocSnapshot } from '../lib/types';
import type { NavTabId } from './Sidebar';
import { LiveThreatGlobe } from './LiveThreatGlobe';

interface OverviewViewProps {
  t: Translations;
  snapshot: SocSnapshot;
  isDark: boolean;
  onNavigate: (tab: NavTabId) => void;
  onMitigateAlert: (id: string, action: 'block' | 'mitigate') => void;
}

export function OverviewView({
  t,
  snapshot,
  isDark,
  onNavigate,
  onMitigateAlert,
}: OverviewViewProps) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const history = snapshot.trafficHistory.slice(-30);
  const latest = history[history.length - 1];
  const totalGbps = latest ? (latest.inboundGbps + latest.outboundGbps).toFixed(1) : '0.0';
  const activeThreatsCount = snapshot.alerts.filter(
    (a) => a.status === 'active' || a.status === 'investigating',
  ).length;
  const enabledRulesCount = snapshot.automationRules.filter((r) => r.enabled).length;

  // Chart geometry
  const width = 760;
  const height = 220;
  const padL = 42;
  const padR = 14;
  const padT = 16;
  const padB = 28;
  const plotW = width - padL - padR;
  const plotH = height - padT - padB;

  const maxGbps = Math.max(
    45,
    ...history.map((s) => Math.max(s.inboundGbps, s.outboundGbps) * 1.15),
  );

  const buildPath = (accessor: (s: (typeof history)[number]) => number) => {
    if (history.length === 0) return '';
    return history
      .map((pt, i) => {
        const x = padL + (i / Math.max(1, history.length - 1)) * plotW;
        const y = padT + plotH - (accessor(pt) / maxGbps) * plotH;
        return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  };

  const inboundPath = buildPath((s) => s.inboundGbps);
  const outboundPath = buildPath((s) => s.outboundGbps);
  const inboundArea =
    history.length > 0
      ? `${inboundPath} L${(padL + plotW).toFixed(1)},${(padT + plotH).toFixed(1)} L${padL},${(
          padT + plotH
        ).toFixed(1)} Z`
      : '';

  const hoveredSample = hoverIdx !== null && history[hoverIdx] ? history[hoverIdx] : latest;

  const protocolEntries = latest
    ? Object.entries(latest.protocols).sort((a, b) => b[1] - a[1])
    : [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
          {t.overview.title}
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t.overview.subtitle}</p>
      </div>

      {/* 4-column KPI strip */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
            <span>{t.overview.kpiThroughput}</span>
            <Activity className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-50">
            {totalGbps} Gbps
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
            {latest ? latest.packetsPerSec.toLocaleString() : '0'} pkt/s · {latest?.latencyMs ?? 0} ms
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
            <span>{t.overview.kpiThreats}</span>
            <AlertOctagon
              className={`w-4 h-4 ${
                activeThreatsCount > 0
                  ? 'text-red-600 dark:text-red-400'
                  : 'text-emerald-600 dark:text-emerald-400'
              }`}
              aria-hidden="true"
            />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-50">
            {snapshot.alerts.length}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
            {activeThreatsCount} active · {enabledRulesCount} {t.overview.automatedCount}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
            <span>{t.overview.kpiEncryptedLogs}</span>
            <Lock className="w-4 h-4 text-emerald-600 dark:text-emerald-400" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-50">
            {snapshot.encryptedLogs.length}
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono">
            AES-256-GCM · {snapshot.activeKeyId}
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5">
          <div className="flex items-center justify-between text-xs font-medium text-slate-500 dark:text-slate-400">
            <span>{t.overview.kpiClusterCapacity}</span>
            <Server className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
          </div>
          <div className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-900 dark:text-slate-50">
            {snapshot.cluster.maxCapacityGbps} Gbps
          </div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400 font-mono tabular-nums">
            {snapshot.cluster.activeNodes} / {snapshot.cluster.maxNodes} nodes ·{' '}
            {snapshot.cluster.kafkaBufferPercent}% buffer
          </div>
        </div>
      </div>

      {/* Main Chart + Live Rotating Earth Threat Globe */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col justify-between">
          <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
                {t.overview.chartTitle}
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                {t.overview.chartSubtitle}
              </p>
            </div>
            {hoveredSample && (
              <div className="flex flex-wrap items-center gap-4 text-xs font-mono tabular-nums">
                <span className="text-sky-600 dark:text-sky-400">
                  {t.overview.inbound}: {hoveredSample.inboundGbps} Gbps
                </span>
                <span className="text-emerald-600 dark:text-emerald-400">
                  {t.overview.outbound}: {hoveredSample.outboundGbps} Gbps
                </span>
                <span className="text-amber-600 dark:text-amber-400">
                  {t.overview.blockedPps}: {hoveredSample.blockedPacketsPerSec.toLocaleString()}/s
                </span>
              </div>
            )}
          </div>

          <div className="w-full overflow-hidden">
            <svg
              viewBox={`0 0 ${width} ${height}`}
              className="w-full h-56 select-none"
              role="img"
              aria-label={t.overview.chartTitle}
              onMouseLeave={() => setHoverIdx(null)}
            >
              <defs>
                <linearGradient id="sgInboundGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#0284c7" stopOpacity="0.24" />
                  <stop offset="100%" stopColor="#0284c7" stopOpacity="0.0" />
                </linearGradient>
              </defs>

              {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
                const y = padT + plotH * (1 - ratio);
                const label = Math.round(maxGbps * ratio);
                return (
                  <g key={ratio}>
                    <line
                      x1={padL}
                      y1={y}
                      x2={padL + plotW}
                      y2={y}
                      stroke="currentColor"
                      className="text-slate-200 dark:text-slate-800"
                      strokeDasharray="3 3"
                    />
                    <text
                      x={padL - 8}
                      y={y + 4}
                      textAnchor="end"
                      className="fill-slate-400 dark:fill-slate-500 text-[10px] font-mono"
                    >
                      {label}
                    </text>
                  </g>
                );
              })}

              {inboundArea && <path d={inboundArea} fill="url(#sgInboundGrad)" />}
              {inboundPath && (
                <path
                  d={inboundPath}
                  fill="none"
                  stroke="#0284c7"
                  strokeWidth="2"
                  strokeLinejoin="round"
                />
              )}
              {outboundPath && (
                <path
                  d={outboundPath}
                  fill="none"
                  stroke="#10b981"
                  strokeWidth="1.75"
                  strokeDasharray="4 2"
                  strokeLinejoin="round"
                />
              )}

              {history.map((pt, i) => {
                const x = padL + (i / Math.max(1, history.length - 1)) * plotW;
                const y = padT + plotH - (pt.inboundGbps / maxGbps) * plotH;
                const sliceW = plotW / Math.max(1, history.length);
                return (
                  <g key={pt.id}>
                    {hoverIdx === i && (
                      <>
                        <line
                          x1={x}
                          y1={padT}
                          x2={x}
                          y2={padT + plotH}
                          stroke="#64748b"
                          strokeWidth="1"
                        />
                        <circle cx={x} cy={y} r="4" fill="#0284c7" />
                      </>
                    )}
                    <rect
                      x={x - sliceW / 2}
                      y={padT}
                      width={sliceW}
                      height={plotH}
                      fill="transparent"
                      onMouseEnter={() => setHoverIdx(i)}
                    />
                  </g>
                );
              })}

              {history.length > 0 && (
                <>
                  <text
                    x={padL}
                    y={height - 6}
                    className="fill-slate-400 dark:fill-slate-500 text-[10px] font-mono"
                  >
                    {history[0].timestamp.slice(11, 19)} UTC
                  </text>
                  <text
                    x={padL + plotW}
                    y={height - 6}
                    textAnchor="end"
                    className="fill-slate-400 dark:fill-slate-500 text-[10px] font-mono"
                  >
                    {history[history.length - 1].timestamp.slice(11, 19)} UTC
                  </text>
                </>
              )}
            </svg>
          </div>
        </div>

        <div className="lg:col-span-5">
          <LiveThreatGlobe t={t} alerts={snapshot.alerts} isDark={isDark} />
        </div>
      </div>

      {/* Protocol Breakdown + Recent Threats Table */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 flex flex-col justify-between">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
              {t.overview.protocolMix}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              DPI Layer-7 inspection distribution
            </p>
            <div className="mt-5 space-y-3.5">
              {protocolEntries.map(([proto, pct]) => (
                <div key={proto}>
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-mono font-medium text-slate-700 dark:text-slate-300">
                      {proto}
                    </span>
                    <span className="font-mono tabular-nums text-slate-500 dark:text-slate-400">
                      {pct}%
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-slate-100 dark:bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-sky-600 dark:bg-sky-500 rounded-full"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800 text-xs text-slate-500 dark:text-slate-400 flex items-center justify-between">
            <span>SIEM Sync Pipeline</span>
            <span className="font-mono text-emerald-600 dark:text-emerald-400 font-medium">
              {snapshot.siemConnectors.filter((c) => c.enabled).length} /{' '}
              {snapshot.siemConnectors.length} Active
            </span>
          </div>
        </div>

        {/* Recent Threats Table */}
        <div className="lg:col-span-8 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-4">
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
              {t.overview.recentThreats}
            </h2>
          <button
            type="button"
            onClick={() => onNavigate('threats')}
            className="flex items-center gap-1.5 text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
          >
            <span>{t.overview.viewAllThreats}</span>
            <ArrowRight className="w-3.5 h-3.5" aria-hidden="true" />
          </button>
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
              {snapshot.alerts.slice(0, 5).map((alert) => (
                <tr key={alert.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40">
                  <td className="py-3.5 px-6">
                    <div className="font-medium text-slate-900 dark:text-slate-100">
                      {alert.title}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      {alert.mitreTactic} · {alert.signatureId}
                    </div>
                  </td>
                  <td className="py-3.5 px-4 font-mono text-xs text-slate-700 dark:text-slate-300">
                    <div>{alert.sourceIp}</div>
                    <div className="text-slate-500 dark:text-slate-400">
                      {alert.destinationAsset}:{alert.destinationPort}
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
                    {alert.status === 'active' || alert.status === 'investigating' ? (
                      <div className="inline-flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => onMitigateAlert(alert.id, 'block')}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md bg-red-600 hover:bg-red-700 text-white text-xs font-medium whitespace-nowrap"
                        >
                          <ShieldBan className="w-3 h-3" aria-hidden="true" />
                          <span>{t.overview.blockIp}</span>
                        </button>
                        <button
                          type="button"
                          onClick={() => onMitigateAlert(alert.id, 'mitigate')}
                          className="px-2.5 py-1 rounded-md border border-slate-300 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
                        >
                          {t.overview.mitigate}
                        </button>
                      </div>
                    ) : (
                      <span className="text-xs font-mono text-slate-400 dark:text-slate-500">
                        Resolved
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </div>
      </div>
    </div>
  );
}
