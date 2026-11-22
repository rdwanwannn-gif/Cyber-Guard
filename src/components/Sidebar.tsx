import React from 'react';
import {
  Activity,
  ShieldAlert,
  Lock,
  Network,
  FileBarChart2,
  KeyRound,
  Shield,
  LogOut,
  Wifi,
  WifiOff,
  X,
  Users,
  MessageSquareWarning,
  ExternalLink,
} from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type { PortalMode } from '../lib/types';

export type NavTabId =
  | 'overview'
  | 'threats'
  | 'logs'
  | 'siem'
  | 'reports'
  | 'mfa'
  | 'users'
  | 'complaints';

interface SidebarProps {
  t: Translations;
  activeTab: NavTabId;
  onSelectTab: (tab: NavTabId) => void;
  wsConnected: boolean;
  userEmail: string;
  userRole: string;
  isAdmin: boolean;
  portal: PortalMode;
  activeAlertCount: number;
  pendingUsersCount: number;
  openComplaintsCount: number;
  onLogout: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export function Sidebar({
  t,
  activeTab,
  onSelectTab,
  wsConnected,
  userEmail,
  userRole,
  isAdmin,
  portal,
  activeAlertCount,
  pendingUsersCount,
  openComplaintsCount,
  onLogout,
  mobileOpen,
  onCloseMobile,
}: SidebarProps) {
  const adminActionCount = pendingUsersCount + openComplaintsCount;
  const navItems: Array<{
    id: NavTabId;
    label: string;
    icon: React.ComponentType<{ className?: string }>;
    count?: number;
  }> = [
    { id: 'overview', label: t.nav.overview, icon: Activity },
    { id: 'threats', label: t.nav.threats, icon: ShieldAlert, count: activeAlertCount },
    { id: 'logs', label: t.nav.logs, icon: Lock },
    ...(isAdmin
      ? [
          { id: 'siem' as NavTabId, label: t.nav.siem, icon: Network },
          { id: 'reports' as NavTabId, label: t.nav.reports, icon: FileBarChart2 },
          {
            id: 'users' as NavTabId,
            label: t.nav.users,
            icon: Users,
            count: adminActionCount,
          },
        ]
      : [
          {
            id: 'complaints' as NavTabId,
            label: t.nav.complaints,
            icon: MessageSquareWarning,
            count: openComplaintsCount,
          },
        ]),
    { id: 'mfa', label: t.nav.mfa, icon: KeyRound },
  ];

  const sidebarBody = (
    <div className="flex flex-col h-full bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 w-64 shrink-0">
      <div className="h-16 px-5 flex items-center justify-between border-b border-slate-200 dark:border-slate-800">
        <div className="flex items-center gap-2.5">
          <Shield className="w-5 h-5 text-sky-600 dark:text-sky-400 shrink-0" aria-hidden="true" />
          <span className="font-display text-base font-semibold tracking-tight text-slate-900 dark:text-slate-50 whitespace-nowrap">
            {t.brandName}
          </span>
        </div>
        <button
          type="button"
          onClick={onCloseMobile}
          aria-label="Close navigation menu"
          className="lg:hidden p-1.5 rounded-md text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <nav aria-label="Primary Navigation" className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => {
                onSelectTab(item.id);
                onCloseMobile();
              }}
              aria-current={active ? 'page' : undefined}
              className={`w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors whitespace-nowrap ${
                active
                  ? 'bg-sky-50 dark:bg-sky-950/60 text-sky-700 dark:text-sky-300'
                  : 'text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800/70 hover:text-slate-900 dark:hover:text-slate-100'
              }`}
            >
              <span className="flex items-center gap-2.5 min-w-0">
                <Icon className="w-4 h-4 shrink-0" aria-hidden="true" />
                <span className="truncate">{item.label}</span>
              </span>
              {typeof item.count === 'number' && item.count > 0 && (
                <span className="font-mono text-xs tabular-nums text-red-600 dark:text-red-400">
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="p-4 border-t border-slate-200 dark:border-slate-800 space-y-3">
        <a
          href={portal === 'admin' ? '/user' : '/admin'}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="sidebar-other-portal-link"
          className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-medium text-sky-600 dark:text-sky-400 transition-colors"
        >
          <span className="truncate">
            {portal === 'admin' ? t.portal.openUserPortal : t.portal.openAdminPortal}
          </span>
          <ExternalLink className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        </a>

        <div className="flex items-center gap-2 text-xs">
          {wsConnected ? (
            <Wifi className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 shrink-0" aria-hidden="true" />
          ) : (
            <WifiOff className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400 shrink-0" aria-hidden="true" />
          )}
          <span
            className={
              wsConnected
                ? 'text-emerald-700 dark:text-emerald-400 font-medium'
                : 'text-amber-700 dark:text-amber-400 font-medium'
            }
          >
            {wsConnected ? t.topbar.wsConnected : t.topbar.wsReconnecting}
          </span>
        </div>

        <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-xs font-medium text-slate-900 dark:text-slate-100 truncate">
              {userEmail}
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400 truncate">{userRole}</div>
          </div>
          <button
            type="button"
            onClick={onLogout}
            aria-label={t.topbar.signOut}
            title={t.topbar.signOut}
            className="p-2 rounded-lg text-slate-500 hover:text-red-600 dark:text-slate-400 dark:hover:text-red-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors shrink-0"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <aside className="hidden lg:flex h-screen sticky top-0">{sidebarBody}</aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-slate-950/60"
            onClick={onCloseMobile}
            aria-hidden="true"
          />
          <div className="relative z-10 h-full">{sidebarBody}</div>
        </div>
      )}
    </>
  );
}
