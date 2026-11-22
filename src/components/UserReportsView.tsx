import React, { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  MessageSquarePlus,
  MonitorSmartphone,
  Send,
  ShieldAlert,
} from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type {
  ComplaintCategory,
  SeverityLevel,
  UserComplaintReport,
} from '../lib/types';

interface UserReportsViewProps {
  t: Translations;
  reports: UserComplaintReport[];
  onSubmitReport: (input: {
    category: ComplaintCategory;
    severity: SeverityLevel;
    subject: string;
    description: string;
  }) => Promise<boolean>;
}

export function UserReportsView({ t, reports, onSubmitReport }: UserReportsViewProps) {
  const [category, setCategory] = useState<ComplaintCategory>('access_mfa');
  const [severity, setSeverity] = useState<SeverityLevel>('high');
  const [subject, setSubject] = useState('');
  const [description, setDescription] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [submittedNotice, setSubmittedNotice] = useState(false);

  const categoryLabels: Record<ComplaintCategory, string> = {
    access_mfa: t.complaints.catAccessMfa,
    security_incident: t.complaints.catSecurityIncident,
    performance_bug: t.complaints.catPerformanceBug,
    policy_request: t.complaints.catPolicyRequest,
    other: t.complaints.catOther,
  };

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (subject.trim().length < 3 || description.trim().length < 10) return;
    setSubmitting(true);
    setSubmittedNotice(false);
    try {
      const ok = await onSubmitReport({
        category,
        severity,
        subject: subject.trim(),
        description: description.trim(),
      });
      if (ok) {
        setSubject('');
        setDescription('');
        setSubmittedNotice(true);
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
          {t.complaints.title}
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">{t.complaints.subtitle}</p>
      </div>

      {submittedNotice && (
        <div
          role="status"
          data-testid="complaint-submitted-banner"
          className="rounded-xl border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/30 px-4 py-3 flex items-center gap-2.5 text-sm text-emerald-800 dark:text-emerald-200"
        >
          <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
          <span>{t.complaints.submittedBanner}</span>
        </div>
      )}

      {/* Submission Form */}
      <form
        onSubmit={handleSubmit}
        className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 space-y-4"
      >
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
          <MessageSquarePlus className="w-4 h-4 text-sky-600 dark:text-sky-400" aria-hidden="true" />
          <span>{t.complaints.submitBtn}</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label
              htmlFor="complaint-category"
              className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5"
            >
              {t.complaints.categoryLabel}
            </label>
            <select
              id="complaint-category"
              value={category}
              onChange={(e) => setCategory(e.target.value as ComplaintCategory)}
              className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
            >
              <option value="access_mfa">{t.complaints.catAccessMfa}</option>
              <option value="security_incident">{t.complaints.catSecurityIncident}</option>
              <option value="performance_bug">{t.complaints.catPerformanceBug}</option>
              <option value="policy_request">{t.complaints.catPolicyRequest}</option>
              <option value="other">{t.complaints.catOther}</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="complaint-severity"
              className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5"
            >
              {t.complaints.severityLabel}
            </label>
            <select
              id="complaint-severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
              className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
        </div>

        <div>
          <label
            htmlFor="complaint-subject"
            className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5"
          >
            {t.complaints.subjectLabel}
          </label>
          <input
            id="complaint-subject"
            type="text"
            required
            minLength={3}
            maxLength={140}
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder={t.complaints.subjectPlaceholder}
            className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
          />
        </div>

        <div>
          <label
            htmlFor="complaint-description"
            className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1.5"
          >
            {t.complaints.descriptionLabel}
          </label>
          <textarea
            id="complaint-description"
            required
            minLength={10}
            maxLength={1200}
            rows={4}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder={t.complaints.descriptionPlaceholder}
            className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
          />
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            data-testid="submit-complaint-btn"
            disabled={submitting}
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-60 text-white text-sm font-medium transition-colors whitespace-nowrap"
          >
            <Send className="w-4 h-4" aria-hidden="true" />
            <span>{t.complaints.submitBtn}</span>
          </button>
        </div>
      </form>

      {/* Submitted Reports History */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3">
          <h2 className="font-display text-base font-semibold text-slate-900 dark:text-slate-50">
            {t.complaints.myHistoryTitle}
          </h2>
          <span className="font-mono text-xs tabular-nums text-slate-500 dark:text-slate-400">
            {reports.length}
          </span>
        </div>

        <div className="divide-y divide-slate-200 dark:divide-slate-800">
          {reports.length === 0 ? (
            <div className="p-6 text-sm text-slate-500 dark:text-slate-400">
              {t.complaints.emptyHistory}
            </div>
          ) : (
            reports.map((report) => (
              <div
                key={report.id}
                data-testid={`user-report-card-${report.id}`}
                className="p-5 space-y-2.5"
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold text-sm text-slate-900 dark:text-slate-100">
                        {report.subject}
                      </span>
                      <span className="font-mono text-[11px] uppercase font-semibold text-sky-600 dark:text-sky-400">
                        {categoryLabels[report.category]}
                      </span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-3 text-xs font-mono text-slate-500 dark:text-slate-400">
                      <span className="inline-flex items-center gap-1">
                        <MonitorSmartphone className="w-3.5 h-3.5" aria-hidden="true" />
                        {report.deviceInfo} ({report.ipAddress})
                      </span>
                      <span>{report.createdAt.slice(0, 19).replace('T', ' ')} UTC</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <span
                      className={`font-mono text-xs uppercase font-semibold ${
                        report.severity === 'critical'
                          ? 'text-red-600 dark:text-red-400'
                          : report.severity === 'high'
                            ? 'text-amber-600 dark:text-amber-400'
                            : 'text-sky-600 dark:text-sky-400'
                      }`}
                    >
                      {report.severity}
                    </span>
                    <span
                      className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium ${
                        report.status === 'resolved'
                          ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300'
                          : report.status === 'in_review'
                            ? 'bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300'
                            : 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300'
                      }`}
                    >
                      {report.status === 'resolved' ? (
                        <CheckCircle2 className="w-3.5 h-3.5" aria-hidden="true" />
                      ) : report.status === 'in_review' ? (
                        <ShieldAlert className="w-3.5 h-3.5" aria-hidden="true" />
                      ) : (
                        <Clock className="w-3.5 h-3.5" aria-hidden="true" />
                      )}
                      <span>
                        {report.status === 'resolved'
                          ? t.complaints.statusResolved
                          : report.status === 'in_review'
                            ? t.complaints.statusInReview
                            : t.complaints.statusOpen}
                      </span>
                    </span>
                  </div>
                </div>

                <p className="text-sm text-slate-700 dark:text-slate-300 whitespace-pre-wrap">
                  {report.description}
                </p>

                {report.adminNote && (
                  <div className="rounded-lg border border-sky-200 dark:border-sky-900/60 bg-sky-50/60 dark:bg-sky-950/30 px-3.5 py-2.5 text-xs text-slate-800 dark:text-slate-200">
                    <span className="font-semibold text-sky-700 dark:text-sky-300">
                      {t.complaints.adminReplyLabel} ({report.handledBy || 'Admin'}):{' '}
                    </span>
                    <span>{report.adminNote}</span>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
