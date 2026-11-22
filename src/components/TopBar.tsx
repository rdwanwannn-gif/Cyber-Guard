import React, { useEffect, useRef, useState } from 'react';
import { Bell, Menu, Moon, Sun, Zap, CheckCheck } from 'lucide-react';
import type { Translations } from '../i18n/translations';
import type { LanguageCode, PortalMode, SecurityNotification } from '../lib/types';
import type { NavTabId } from './Sidebar';

interface TopBarProps {
  t: Translations;
  activeTab: NavTabId;
  portal: PortalMode;
  lang: LanguageCode;
  onChangeLang: (lang: LanguageCode) => void;
  isDark: boolean;
  onToggleTheme: () => void;
  notifications: SecurityNotification[];
  onMarkAllRead: () => void;
  onSimulateProbe: () => void;
  simulating: boolean;
  simulationRunning?: boolean;
  canSimulate?: boolean;
  onOpenMobileMenu: () => void;
}

export function TopBar({
  t,
  activeTab,
  portal,
  lang,
  onChangeLang,
  isDark,
  onToggleTheme,
  notifications,
  onMarkAllRead,
  onSimulateProbe,
  simulating,
  simulationRunning = false,
  canSimulate = true,
  onOpenMobileMenu,
}: TopBarProps) {
  const [notifOpen, setNotifOpen] = useState(false);
  const [openedSessionItems, setOpenedSessionItems] = useState<SecurityNotification[]>([]);
  const notifContainerRef = useRef<HTMLDivElement | null>(null);
  const unreadNotifications = notifications.filter((n) => !n.read);
  const unreadCount = unreadNotifications.length;

  useEffect(() => {
    if (!notifOpen) return;

    function handlePointerDown(event: MouseEvent) {
      if (
        notifContainerRef.current &&
        !notifContainerRef.current.contains(event.target as Node)
      ) {
        setNotifOpen(false);
        setOpenedSessionItems([]);
      }
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setNotifOpen(false);
        setOpenedSessionItems([]);
      }
    }

    document.addEventListener('mousedown', handlePointerDown);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handlePointerDown);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [notifOpen]);

  function handleToggleNotifications() {
    if (!notifOpen) {
      if (unreadNotifications.length > 0) {
        setOpenedSessionItems(unreadNotifications);
        onMarkAllRead();
      } else {
        setOpenedSessionItems([]);
      }
      setNotifOpen(true);
    } else {
      setNotifOpen(false);
      setOpenedSessionItems([]);
    }
  }

  function handleClearAndClose() {
    setOpenedSessionItems([]);
    setNotifOpen(false);
    onMarkAllRead();
  }

  const displayedNotifications =
    openedSessionItems.length > 0 ? openedSessionItems : unreadNotifications;

  const sectionTitleMap: Record<NavTabId, string> = {
    overview: t.nav.overview,
    threats: t.nav.threats,
    logs: t.nav.logs,
    siem: t.nav.siem,
    reports: t.nav.reports,
    users: t.nav.users,
    complaints: t.nav.complaints,
    mfa: t.nav.mfa,
  };

  return (
    <header className="h-16 sticky top-0 z-30 bg-white/95 dark:bg-slate-900/95 backdrop-blur border-b border-slate-200 dark:border-slate-800 px-3 sm:px-6 flex items-center justify-between gap-2 sm:gap-4">
      <div className="flex items-center gap-2.5 min-w-0 shrink-0">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation menu"
          className="lg:hidden p-2 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 shrink-0"
        >
          <Menu className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-2 text-sm min-w-0">
          <span
            data-testid="active-portal-badge"
            className="font-mono text-[11px] font-medium px-2 py-0.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 text-sky-600 dark:text-sky-400 whitespace-nowrap hidden md:inline"
          >
            {portal === 'admin' ? t.portal.adminPortalBadge : t.portal.userPortalBadge}
          </span>
          <span className="font-display font-semibold text-slate-900 dark:text-slate-50 truncate hidden sm:inline max-w-[180px] md:max-w-none">
            {sectionTitleMap[activeTab]}
          </span>
        </div>
      </div>

      <div className="flex items-center gap-1.5 sm:gap-2.5 shrink-0">
        <label htmlFor="topbar-lang-select" className="sr-only">
          Language
        </label>
        <select
          id="topbar-lang-select"
          value={lang}
          onChange={(e) => onChangeLang(e.target.value as LanguageCode)}
          className="px-2 sm:px-2.5 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-950 text-slate-700 dark:text-slate-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500"
        >
          <option value="id">ID</option>
          <option value="en">EN</option>
          <option value="ja">JA</option>
          <option value="de">DE</option>
        </select>

        <button
          type="button"
          onClick={onToggleTheme}
          aria-label={isDark ? t.topbar.lightMode : t.topbar.darkMode}
          title={isDark ? t.topbar.lightMode : t.topbar.darkMode}
          className="p-2 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors shrink-0"
        >
          {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        <div ref={notifContainerRef} className="relative shrink-0">
          <button
            type="button"
            onClick={handleToggleNotifications}
            aria-label={t.topbar.notifications}
            aria-expanded={notifOpen}
            className="relative p-2 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span
                data-testid="unread-notification-badge"
                className="absolute -top-1 -right-1 min-w-[18px] h-[18px] px-1 rounded-full bg-red-600 text-white font-mono text-[10px] font-semibold flex items-center justify-center tabular-nums"
              >
                {unreadCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div
              role="region"
              aria-label={t.topbar.notifications}
              className="absolute right-0 mt-2 w-72 sm:w-96 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-lg z-40"
            >
              <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-slate-900 dark:text-slate-50">
                  {t.topbar.notifications}
                </span>
                <button
                  type="button"
                  onClick={handleClearAndClose}
                  className="flex items-center gap-1 text-xs font-medium text-sky-600 dark:text-sky-400 hover:underline whitespace-nowrap"
                >
                  <CheckCheck className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>{t.topbar.markAllRead}</span>
                </button>
              </div>
              <div className="max-h-72 overflow-y-auto divide-y divide-slate-200 dark:divide-slate-800">
                {displayedNotifications.length === 0 ? (
                  <div className="p-4 text-xs text-slate-500 dark:text-slate-400">
                    {t.topbar.noNotifications}
                  </div>
                ) : (
                  displayedNotifications.slice(0, 8).map((n) => (
                    <div
                      key={n.id}
                      className="px-4 py-3 text-xs bg-sky-50/40 dark:bg-sky-950/20"
                    >
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="font-semibold text-slate-900 dark:text-slate-100">
                          {n.title}
                        </span>
                        <span
                          className={`font-mono uppercase text-[10px] font-semibold ${
                            n.severity === 'critical'
                              ? 'text-red-600 dark:text-red-400'
                              : n.severity === 'high'
                                ? 'text-amber-600 dark:text-amber-400'
                                : 'text-sky-600 dark:text-sky-400'
                          }`}
                        >
                          {n.severity}
                        </span>
                      </div>
                      <div className="text-slate-600 dark:text-slate-400 font-mono">{n.message}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        <button
          type="button"
          data-testid="topbar-simulate-btn"
          onClick={onSimulateProbe}
          disabled={simulating || !canSimulate}
          title={!canSimulate ? t.topbar.viewerReadOnlyTip : undefined}
          className={`flex items-center gap-1.5 px-3 sm:px-3.5 py-2 rounded-lg text-white text-xs font-medium transition-colors whitespace-nowrap shrink-0 disabled:opacity-60 ${
            simulationRunning
              ? 'bg-red-600 hover:bg-red-700'
              : 'bg-sky-600 hover:bg-sky-700'
          }`}
        >
          {simulationRunning ? (
            <span className="w-2 h-2 rounded-full bg-white animate-pulse" aria-hidden="true" />
          ) : (
            <Zap className="w-3.5 h-3.5" aria-hidden="true" />
          )}
          <span>{simulationRunning ? t.topbar.simulatingLabel : t.topbar.simulateProbe}</span>
        </button>
      </div>
    </header>
  );
}
