import React, { useState } from 'react';
import {
  Shield,
  Lock,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  Globe,
  UserPlus,
} from 'lucide-react';
import type { Translations } from '../i18n/translations';
import { generateBrowserTotpFromEnrollmentSecret } from '../lib/clientTotp';
import type { LanguageCode, PortalMode, UserRole } from '../lib/types';

export interface AuthSession {
  token: string;
  userId: string;
  email: string;
  role: string;
  roleKey: UserRole;
  mfaVerified: boolean;
}

interface AuthGatewayProps {
  t: Translations;
  lang: LanguageCode;
  onChangeLang: (lang: LanguageCode) => void;
  initialized: boolean;
  portal: PortalMode;
  onSwitchPortal: (nextPortal: PortalMode) => void;
  externalNotice?: string | null;
  onAuthenticated: (session: AuthSession) => void;
}

export function AuthGateway({
  t,
  lang,
  onChangeLang,
  initialized,
  portal,
  onSwitchPortal,
  externalNotice,
  onAuthenticated,
}: AuthGatewayProps) {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [step, setStep] = useState<'credentials' | 'mfa'>('credentials');
  const [fullName, setFullName] = useState('');
  const [department, setDepartment] = useState('SOC Operations');
  const [email, setEmail] = useState(
    !initialized && portal === 'admin' ? 'ridwan26abengwan@gmail.com' : '',
  );
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [challengeToken, setChallengeToken] = useState('');
  const [enrollSecret, setEnrollSecret] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(externalNotice ?? null);
  React.useEffect(() => {
    if (externalNotice) {
      setError(externalNotice);
    }
  }, [externalNotice]);
  const [registerSuccess, setRegisterSuccess] = useState<{
    email: string;
    requireAdminApproval: boolean;
  } | null>(null);
  const [loading, setLoading] = useState(false);

  async function readJsonSafely<T>(res: Response): Promise<T & { error?: string }> {
    const raw = await res.text();
    if (!raw) return {} as T & { error?: string };
    try {
      return JSON.parse(raw) as T & { error?: string };
    } catch {
      const stripped = raw.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      return {
        error: `Server error HTTP ${res.status}${stripped ? `: ${stripped.slice(0, 140)}` : ''}`,
      } as T & { error?: string };
    }
  }

  async function handleCredentialsSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const endpoint = initialized ? '/api/auth/login' : '/api/auth/setup';
      const bodyPayload = initialized ? { email, password, portal } : { email, password };
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyPayload),
      });
      const data = await readJsonSafely<{
        challengeToken?: string;
        totpSecret?: string;
        backupCodes?: string[];
      }>(res);
      if (!res.ok) {
        setError(data.error || `Authentication failed (HTTP ${res.status})`);
        return;
      }
      setChallengeToken(data.challengeToken || '');
      setEnrollSecret(data.totpSecret || null);
      setBackupCodes(data.backupCodes || []);
      setStep('mfa');
    } catch (err) {
      setError(
        err instanceof Error && err.message
          ? `Network error while contacting authentication server (${err.message})`
          : 'Network error while contacting authentication server',
      );
    } finally {
      setLoading(false);
    }
  }

  async function handleRegisterSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setRegisterSuccess(null);
    setLoading(true);
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fullName, email, password, department }),
      });
      const data = await readJsonSafely<{
        requireAdminApproval?: boolean;
        user?: { email: string };
      }>(res);
      if (!res.ok) {
        setError(data.error || `Registration failed (HTTP ${res.status})`);
        return;
      }
      setRegisterSuccess({
        email: data.user?.email || email,
        requireAdminApproval: Boolean(data.requireAdminApproval),
      });
      setPassword('');
    } catch {
      setError('Network error while submitting registration');
    } finally {
      setLoading(false);
    }
  }

  async function handleMfaSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/auth/verify-mfa', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeToken, code: mfaCode }),
      });
      const data = await readJsonSafely<{
        token?: string;
        session?: {
          userId: string;
          email: string;
          role: string;
          roleKey: UserRole;
          mfaVerified: boolean;
        };
      }>(res);
      if (!res.ok || !data.token || !data.session) {
        setError(data.error || `MFA verification failed (HTTP ${res.status})`);
        return;
      }
      onAuthenticated({
        token: data.token,
        userId: data.session.userId,
        email: data.session.email,
        role: data.session.role,
        roleKey: data.session.roleKey,
        mfaVerified: data.session.mfaVerified,
      });
    } catch {
      setError('Network error during MFA verification');
    } finally {
      setLoading(false);
    }
  }

  async function handleFillTotpFromEnrollment() {
    if (!enrollSecret) return;
    const code = await generateBrowserTotpFromEnrollmentSecret(enrollSecret);
    setMfaCode(code);
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col justify-between p-6 md:p-10">
      <header className="max-w-5xl w-full mx-auto flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <Shield className="w-6 h-6 text-sky-600 dark:text-sky-400" aria-hidden="true" />
          <span className="font-display text-lg font-semibold tracking-tight whitespace-nowrap">
            {t.brandName}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-slate-500 dark:text-slate-400" aria-hidden="true" />
          <label htmlFor="auth-lang-select" className="sr-only">
            Language
          </label>
          <select
            id="auth-lang-select"
            value={lang}
            onChange={(e) => onChangeLang(e.target.value as LanguageCode)}
            className="px-3 py-1.5 text-sm rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
          >
            <option value="id">Bahasa Indonesia</option>
            <option value="en">English</option>
            <option value="ja">日本語</option>
            <option value="de">Deutsch</option>
          </select>
        </div>
      </header>

      <main className="max-w-md w-full mx-auto my-8 space-y-3">
        {/* Distinct Portal Switcher (/admin vs /user) */}
        <div
          data-testid="portal-link-switcher"
          className="grid grid-cols-2 gap-1.5 p-1 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900"
        >
          <a
            href="/admin"
            data-testid="portal-link-admin"
            onClick={(e) => {
              e.preventDefault();
              setMode('login');
              setStep('credentials');
              setError(null);
              if (!initialized) setEmail('ridwan26abengwan@gmail.com');
              else setEmail('');
              onSwitchPortal('admin');
            }}
            className={`text-center py-2 px-3 rounded-lg text-xs font-medium transition-colors ${
              portal === 'admin'
                ? 'bg-sky-600 text-white'
                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            {t.portal.adminPortalBadge}
          </a>
          <a
            href="/user"
            data-testid="portal-link-user"
            onClick={(e) => {
              e.preventDefault();
              setMode('login');
              setStep('credentials');
              setError(null);
              setEmail('');
              onSwitchPortal('user');
            }}
            className={`text-center py-2 px-3 rounded-lg text-xs font-medium transition-colors ${
              portal === 'user'
                ? 'bg-sky-600 text-white'
                : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800'
            }`}
          >
            {t.portal.userPortalBadge}
          </a>
        </div>

        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-8">
          {step === 'credentials' && initialized && portal === 'user' && (
            <div className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 mb-6">
              <button
                type="button"
                data-testid="auth-tab-login"
                onClick={() => {
                  setMode('login');
                  setError(null);
                  setRegisterSuccess(null);
                }}
                className={`py-2 px-3 rounded-md text-xs font-medium transition-colors ${
                  mode === 'login'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-50 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {t.auth.tabSignIn}
              </button>
              <button
                type="button"
                data-testid="auth-tab-register"
                onClick={() => {
                  setMode('register');
                  setError(null);
                  setRegisterSuccess(null);
                }}
                className={`py-2 px-3 rounded-md text-xs font-medium transition-colors ${
                  mode === 'register'
                    ? 'bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-50 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {t.auth.tabRegister}
              </button>
            </div>
          )}

          <div className="mb-6">
            <div className="flex items-center gap-2 text-xs font-medium text-sky-600 dark:text-sky-400 mb-2">
              {step === 'mfa' ? (
                <KeyRound className="w-4 h-4" aria-hidden="true" />
              ) : mode === 'register' && portal === 'user' ? (
                <UserPlus className="w-4 h-4" aria-hidden="true" />
              ) : (
                <Lock className="w-4 h-4" aria-hidden="true" />
              )}
              <span>
                {portal === 'admin' ? t.portal.adminPortalBadge : t.portal.userPortalBadge} · TOTP
              </span>
            </div>
            <h1 className="font-display text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
              {step === 'mfa'
                ? t.auth.mfaTitle
                : portal === 'user'
                  ? mode === 'register'
                    ? t.auth.registerTitle
                    : t.portal.userPortalTitle
                  : initialized
                    ? t.auth.loginTitle
                    : t.auth.setupTitle}
            </h1>
            <p className="mt-2 text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
              {step === 'mfa'
                ? t.auth.mfaSubtitle
                : portal === 'user'
                  ? mode === 'register'
                    ? t.auth.registerSubtitle
                    : t.portal.separateSessionHint
                  : initialized
                    ? t.auth.loginSubtitle
                    : t.auth.setupSubtitle}
            </p>
          </div>

          {error && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-2.5 rounded-lg border border-red-200 dark:border-red-900/60 bg-red-50 dark:bg-red-950/40 px-3.5 py-3 text-sm text-red-700 dark:text-red-300"
            >
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          {portal === 'user' && !initialized ? (
            <div className="rounded-lg border border-amber-200 dark:border-amber-900/60 bg-amber-50 dark:bg-amber-950/30 p-4 text-sm text-amber-900 dark:text-amber-200 space-y-3">
              <p>{t.portal.userPortalWaitAdmin}</p>
              <a
                href="/admin"
                onClick={(e) => {
                  e.preventDefault();
                  onSwitchPortal('admin');
                }}
                className="inline-flex items-center px-3 py-2 rounded-lg bg-sky-600 hover:bg-sky-700 text-white text-xs font-medium"
              >
                {t.portal.openAdminPortal}
              </a>
            </div>
          ) : step === 'credentials' && portal === 'user' && mode === 'register' ? (
            registerSuccess ? (
              <div
                data-testid="register-success-card"
                className="space-y-4 rounded-lg border border-emerald-200 dark:border-emerald-900/60 bg-emerald-50 dark:bg-emerald-950/30 p-4 text-sm text-emerald-900 dark:text-emerald-200"
              >
                <div className="flex items-start gap-2.5">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-semibold">{t.auth.registerSuccessTitle}</div>
                    <p className="mt-1 text-xs leading-relaxed opacity-90">
                      {t.auth.registerSuccessDesc}
                    </p>
                    <div className="mt-2 font-mono text-xs">{registerSuccess.email}</div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setMode('login');
                    setEmail(registerSuccess.email);
                    setRegisterSuccess(null);
                  }}
                  className="w-full py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-medium transition-colors"
                >
                  {t.auth.backToSignIn}
                </button>
              </div>
            ) : (
              <form onSubmit={handleRegisterSubmit} className="space-y-4">
                <div>
                  <label
                    htmlFor="reg-fullname"
                    className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                  >
                    {t.auth.fullNameLabel}
                  </label>
                  <input
                    id="reg-fullname"
                    type="text"
                    required
                    minLength={2}
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Budi Santoso"
                    className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                  />
                </div>

                <div>
                  <label
                    htmlFor="reg-department"
                    className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                  >
                    {t.auth.departmentLabel}
                  </label>
                  <input
                    id="reg-department"
                    type="text"
                    required
                    value={department}
                    onChange={(e) => setDepartment(e.target.value)}
                    className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                  />
                </div>

                <div>
                  <label
                    htmlFor="reg-email"
                    className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                  >
                    {t.auth.accountEmailLabel}
                  </label>
                  <input
                    id="reg-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="operator@perusahaan.id"
                    className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                  />
                </div>

                <div>
                  <label
                    htmlFor="reg-password"
                    className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                  >
                    {t.auth.passwordLabel}
                  </label>
                  <input
                    id="reg-password"
                    type="password"
                    required
                    minLength={8}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 px-4 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-60 text-white text-sm font-medium transition-colors whitespace-nowrap"
                >
                  {t.auth.registerBtn}
                </button>
              </form>
            )
          ) : step === 'credentials' ? (
            <form onSubmit={handleCredentialsSubmit} className="space-y-4">
              <div>
                <label
                  htmlFor="auth-email"
                  className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                >
                  {initialized ? t.auth.accountEmailLabel : t.auth.emailLabel}
                </label>
                <input
                  id="auth-email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                />
              </div>

              <div>
                <label
                  htmlFor="auth-password"
                  className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                >
                  {t.auth.passwordLabel}
                </label>
                <input
                  id="auth-password"
                  type="password"
                  required
                  minLength={8}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full px-3.5 py-2.5 text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full py-2.5 px-4 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-60 text-white text-sm font-medium transition-colors whitespace-nowrap"
              >
                {initialized ? t.auth.signInBtn : t.auth.createAdminBtn}
              </button>
            </form>
          ) : (
            <form onSubmit={handleMfaSubmit} className="space-y-5">
              {enrollSecret && (
                <div className="space-y-3 border-b border-slate-200 dark:border-slate-800 pb-4">
                  <div>
                    <div className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">
                      {t.auth.enrollSecretLabel}
                    </div>
                    <code className="block w-full px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 font-mono text-xs text-slate-900 dark:text-slate-100 break-all">
                      {enrollSecret}
                    </code>
                  </div>

                  {backupCodes.length > 0 && (
                    <div>
                      <div className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1">
                        {t.auth.backupCodesLabel}
                      </div>
                      <div className="grid grid-cols-2 gap-1.5 font-mono text-xs text-slate-700 dark:text-slate-300">
                        {backupCodes.map((c) => (
                          <span
                            key={c}
                            className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800"
                          >
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <button
                    type="button"
                    onClick={handleFillTotpFromEnrollment}
                    className="w-full py-2 px-3 rounded-lg border border-sky-300 dark:border-sky-800 bg-sky-50 dark:bg-sky-950/40 text-sky-700 dark:text-sky-300 text-xs font-medium hover:bg-sky-100 dark:hover:bg-sky-900/50 transition-colors"
                  >
                    {t.auth.generateHelperBtn}
                  </button>
                </div>
              )}

              <div>
                <label
                  htmlFor="auth-mfa"
                  className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1.5"
                >
                  {t.auth.mfaCodeLabel}
                </label>
                <input
                  id="auth-mfa"
                  type="text"
                  required
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="123456"
                  className="w-full px-3.5 py-2.5 text-sm font-mono tracking-widest rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
                />
              </div>

              <div className="space-y-2">
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 px-4 rounded-lg bg-sky-600 hover:bg-sky-700 disabled:opacity-60 text-white text-sm font-medium transition-colors"
                >
                  {t.auth.verifyMfaBtn}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setStep('credentials');
                    setMfaCode('');
                    setError(null);
                  }}
                  className="w-full py-2 px-4 rounded-lg text-xs font-medium text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100"
                >
                  {t.auth.backToLogin}
                </button>
              </div>
            </form>
          )}

          <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-800 space-y-2 text-xs text-slate-500 dark:text-slate-400">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400 shrink-0" />
              <span>{t.auth.mfaProtectedNote}</span>
            </div>
            {initialized && (
              <div className="flex items-center justify-between gap-2 pt-1">
                <span>
                  {portal === 'admin'
                    ? t.portal.registerHintUserPortal
                    : t.portal.separateSessionHint}
                </span>
                <a
                  href={portal === 'admin' ? '/user' : '/admin'}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sky-600 dark:text-sky-400 font-medium hover:underline whitespace-nowrap shrink-0"
                >
                  {portal === 'admin' ? t.portal.switchToUserLink : t.portal.switchToAdminLink}
                </a>
              </div>
            )}
          </div>
        </div>
      </main>

      <footer className="max-w-5xl w-full mx-auto text-center text-xs text-slate-500 dark:text-slate-400">
        SentinelGrid Enterprise Security Operations
      </footer>
    </div>
  );
}
