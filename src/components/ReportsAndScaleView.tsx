import React, { useState } from 'react';
import { Download, FileText, Flame, Server } from 'lucide-react';
import type { Translations } from '../i18n/translations';
import { reportToCsv } from '../lib/securityEngine';
import type { ClusterConfig, WeeklyReport, WeeklyReportSchedule } from '../lib/types';

interface ReportsAndScaleViewProps {
  t: Translations;
  reports: WeeklyReport[];
  schedule: WeeklyReportSchedule;
  cluster: ClusterConfig;
  onGenerateReport: () => Promise<void>;
  onUpdateSchedule: (next: Partial<WeeklyReportSchedule>) => Promise<void>;
  onUpdateCluster: (next: {
    autoScaleEnabled?: boolean;
    maxNodes?: number;
    targetLoadPercent?: number;
    stressTestActive?: boolean;
  }) => Promise<void>;
}

export function ReportsAndScaleView({
  t,
  reports,
  schedule,
  cluster,
  onGenerateReport,
  onUpdateSchedule,
  onUpdateCluster,
}: ReportsAndScaleViewProps) {
  const [generating, setGenerating] = useState(false);
  const [day, setDay] = useState(schedule.dayOfWeek);
  const [timeUtc, setTimeUtc] = useState(schedule.timeUtc);
  const [recipientsRaw, setRecipientsRaw] = useState(schedule.recipients.join(', '));
  const [savedNotice, setSavedNotice] = useState(false);

  async function handleGenerate() {
    setGenerating(true);
    try {
      await onGenerateReport();
    } finally {
      setGenerating(false);
    }
  }

  async function handleSaveSchedule(e: React.FormEvent) {
    e.preventDefault();
    const recipients = recipientsRaw
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.includes('@'));
    await onUpdateSchedule({
      enabled: schedule.enabled,
      dayOfWeek: day,
      timeUtc,
      recipients,
    });
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  }

  function triggerDownload(filename: string, content: string, mimeType: string) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
          {t.reports.title}
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t.reports.subtitle}</p>
      </div>

      {/* Weekly Reports & Automated Schedule */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
              {t.reports.weeklyReportsTitle}
            </h2>
            <button
              type="button"
              onClick={handleGenerate}
              disabled={generating}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-60 text-white text-xs font-medium whitespace-nowrap"
            >
              <FileText className="w-3.5 h-3.5" aria-hidden="true" />
              <span>{t.reports.generateNow}</span>
            </button>
          </div>

          <div className="divide-y divide-slate-200 dark:divide-slate-800">
            {reports.map((rep) => (
              <div key={rep.id} className="py-4 space-y-3">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="font-mono text-sm font-semibold text-slate-900 dark:text-slate-100">
                      {rep.id} · {rep.periodLabel}
                    </div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                      {rep.summaryNote}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() =>
                        triggerDownload(`${rep.id}.csv`, reportToCsv(rep), 'text/csv;charset=utf-8')
                      }
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-300 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
                    >
                      <Download className="w-3 h-3" aria-hidden="true" />
                      <span>{t.reports.downloadCsv}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        triggerDownload(
                          `${rep.id}.json`,
                          JSON.stringify(rep, null, 2),
                          'application/json',
                        )
                      }
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-300 dark:border-slate-700 text-xs font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 whitespace-nowrap"
                    >
                      <Download className="w-3 h-3" aria-hidden="true" />
                      <span>{t.reports.downloadJson}</span>
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono tabular-nums pt-1">
                  <div>
                    <div className="text-slate-500 dark:text-slate-400 font-sans">Packets</div>
                    <div className="font-semibold text-slate-900 dark:text-slate-100">
                      {rep.totalPacketsAnalyzed}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400 font-sans">MTTR</div>
                    <div className="font-semibold text-slate-900 dark:text-slate-100">
                      {rep.meanTimeToRespondSec}s
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400 font-sans">E2E Sealed</div>
                    <div className="font-semibold text-emerald-600 dark:text-emerald-400">
                      {rep.e2eLogEncryptionPercent}%
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-500 dark:text-slate-400 font-sans">Compliance</div>
                    <div className="font-semibold text-emerald-600 dark:text-emerald-400">
                      {rep.complianceScorePercent}%
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        <form
          onSubmit={handleSaveSchedule}
          className="lg:col-span-5 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4 h-fit"
        >
          <div className="flex items-center justify-between gap-3">
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
              {t.reports.scheduleTitle}
            </h2>
            <button
              type="button"
              role="switch"
              aria-checked={schedule.enabled}
              onClick={() => onUpdateSchedule({ enabled: !schedule.enabled })}
              className={`px-2.5 py-1 rounded-md text-xs font-medium border whitespace-nowrap ${
                schedule.enabled
                  ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                  : 'border-slate-300 dark:border-slate-700 text-slate-500'
              }`}
            >
              {schedule.enabled ? 'Active' : 'Paused'}
            </button>
          </div>

          <div>
            <label
              htmlFor="schedule-day"
              className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1"
            >
              {t.reports.dayLabel}
            </label>
            <select
              id="schedule-day"
              value={day}
              onChange={(e) => setDay(e.target.value as WeeklyReportSchedule['dayOfWeek'])}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            >
              <option value="Monday">Monday</option>
              <option value="Friday">Friday</option>
              <option value="Sunday">Sunday</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="schedule-time"
              className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1"
            >
              {t.reports.timeUtcLabel}
            </label>
            <input
              id="schedule-time"
              type="time"
              value={timeUtc}
              onChange={(e) => setTimeUtc(e.target.value)}
              className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>

          <div>
            <label
              htmlFor="schedule-recipients"
              className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1"
            >
              {t.reports.recipientsLabel}
            </label>
            <input
              id="schedule-recipients"
              type="text"
              value={recipientsRaw}
              onChange={(e) => setRecipientsRaw(e.target.value)}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950"
            />
          </div>

          <button
            type="submit"
            className="w-full py-2 px-4 rounded-lg bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 text-sm font-medium hover:opacity-90 transition-opacity"
          >
            {savedNotice ? 'Saved' : t.reports.saveSchedule}
          </button>
        </form>
      </div>

      {/* High-Scalability Cluster Telemetry & Controls */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
              {t.reports.scalabilityTitle}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 font-mono tabular-nums">
              {t.reports.activeNodes}: {cluster.activeNodes}/{cluster.maxNodes} ·{' '}
              {t.reports.kafkaBuffer}: {cluster.kafkaBufferPercent}% · {t.reports.headroom}:{' '}
              {cluster.maxCapacityGbps} Gbps
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              role="switch"
              aria-checked={cluster.autoScaleEnabled}
              onClick={() => onUpdateCluster({ autoScaleEnabled: !cluster.autoScaleEnabled })}
              className={`px-3 py-2 rounded-lg text-xs font-medium border whitespace-nowrap ${
                cluster.autoScaleEnabled
                  ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                  : 'border-slate-300 dark:border-slate-700 text-slate-500'
              }`}
            >
              {t.reports.autoScaleToggle}
            </button>

            <button
              type="button"
              onClick={() => onUpdateCluster({ stressTestActive: !cluster.stressTestActive })}
              className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-medium transition-colors whitespace-nowrap ${
                cluster.stressTestActive
                  ? 'bg-red-600 hover:bg-red-700 text-white'
                  : 'bg-sky-600 hover:bg-sky-700 text-white'
              }`}
            >
              <Flame className="w-3.5 h-3.5" aria-hidden="true" />
              <span>
                {cluster.stressTestActive
                  ? t.reports.stressTestStop
                  : t.reports.stressTestStart}
              </span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 pt-2 border-t border-slate-200 dark:border-slate-800">
          <div>
            <div className="flex items-center justify-between text-xs mb-1.5">
              <label htmlFor="max-nodes-range" className="font-medium text-slate-700 dark:text-slate-300">
                {t.reports.maxNodesLabel}
              </label>
              <span className="font-mono tabular-nums text-slate-600 dark:text-slate-300">
                {cluster.maxNodes} nodes
              </span>
            </div>
            <input
              id="max-nodes-range"
              type="range"
              min={4}
              max={32}
              step={2}
              value={cluster.maxNodes}
              onChange={(e) => onUpdateCluster({ maxNodes: Number(e.target.value) })}
              className="w-full accent-sky-600"
            />
          </div>

          <div>
            <div className="flex items-center justify-between text-xs mb-1.5">
              <label htmlFor="target-load-range" className="font-medium text-slate-700 dark:text-slate-300">
                {t.reports.targetLoadLabel}
              </label>
              <span className="font-mono tabular-nums text-slate-600 dark:text-slate-300">
                {cluster.targetLoadPercent}%
              </span>
            </div>
            <input
              id="target-load-range"
              type="range"
              min={45}
              max={85}
              step={5}
              value={cluster.targetLoadPercent}
              onChange={(e) => onUpdateCluster({ targetLoadPercent: Number(e.target.value) })}
              className="w-full accent-sky-600"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-px bg-slate-200 dark:bg-slate-800 rounded-lg overflow-hidden">
          {cluster.nodes.map((node) => (
            <div
              key={node.id}
              className="bg-slate-50 dark:bg-slate-950 p-3.5 text-xs space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <span className="inline-flex items-center gap-1.5 font-mono font-semibold text-slate-900 dark:text-slate-100">
                  <Server className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" aria-hidden="true" />
                  <span>{node.id}</span>
                </span>
                <span className="font-mono text-[11px] text-emerald-600 dark:text-emerald-400">
                  {node.region}
                </span>
              </div>
              <div className="font-mono tabular-nums text-slate-500 dark:text-slate-400">
                CPU {node.cpuPercent}% · MEM {node.memoryPercent}%
              </div>
              <div className="font-mono tabular-nums text-slate-700 dark:text-slate-300">
                {node.ingestGbps} Gbps · {node.eventsPerSec.toLocaleString()} ev/s
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
