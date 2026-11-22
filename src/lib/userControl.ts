import type {
  ComplaintCategory,
  ComplaintStatus,
  ManagedUserAccount,
  PortalMode,
  SeverityLevel,
  UserAccountStatus,
  UserComplaintReport,
  UserRole,
} from './types';

export function resolvePortalFromPathname(pathname: string): PortalMode {
  const normalized = (pathname || '/').trim().toLowerCase();
  if (
    normalized === '/user' ||
    normalized.startsWith('/user/') ||
    normalized === '/pengguna' ||
    normalized.startsWith('/pengguna/')
  ) {
    return 'user';
  }
  return 'admin';
}

export function portalSessionStorageKey(portal: PortalMode): string {
  return portal === 'user' ? 'sentinelgrid_session_user' : 'sentinelgrid_session_admin';
}

const VALID_COMPLAINT_CATEGORIES: ComplaintCategory[] = [
  'access_mfa',
  'security_incident',
  'performance_bug',
  'policy_request',
  'other',
];

const VALID_COMPLAINT_STATUSES: ComplaintStatus[] = ['open', 'in_review', 'resolved'];
const VALID_SEVERITIES: SeverityLevel[] = ['critical', 'high', 'medium', 'low'];

export function isValidComplaintCategory(value: unknown): value is ComplaintCategory {
  return typeof value === 'string' && VALID_COMPLAINT_CATEGORIES.includes(value as ComplaintCategory);
}

export function isValidComplaintStatus(value: unknown): value is ComplaintStatus {
  return typeof value === 'string' && VALID_COMPLAINT_STATUSES.includes(value as ComplaintStatus);
}

export function validateComplaintInput(input: {
  category?: unknown;
  severity?: unknown;
  subject?: string;
  description?: string;
}): {
  valid: boolean;
  error?: string;
  cleanCategory: ComplaintCategory;
  cleanSeverity: SeverityLevel;
  cleanSubject: string;
  cleanDescription: string;
} {
  const cleanCategory: ComplaintCategory = isValidComplaintCategory(input.category)
    ? input.category
    : 'other';
  const cleanSeverity: SeverityLevel =
    typeof input.severity === 'string' && VALID_SEVERITIES.includes(input.severity as SeverityLevel)
      ? (input.severity as SeverityLevel)
      : 'medium';
  const cleanSubject = (input.subject || '').trim().slice(0, 140);
  const cleanDescription = (input.description || '').trim().slice(0, 1200);

  if (cleanSubject.length < 3) {
    return {
      valid: false,
      error: 'Subject must be at least 3 characters',
      cleanCategory,
      cleanSeverity,
      cleanSubject,
      cleanDescription,
    };
  }
  if (cleanDescription.length < 10) {
    return {
      valid: false,
      error: 'Description must be at least 10 characters',
      cleanCategory,
      cleanSeverity,
      cleanSubject,
      cleanDescription,
    };
  }

  return {
    valid: true,
    cleanCategory,
    cleanSeverity,
    cleanSubject,
    cleanDescription,
  };
}

export function filterUserReports(
  reports: UserComplaintReport[],
  search: string,
  statusFilter: ComplaintStatus | 'all',
): UserComplaintReport[] {
  const q = search.trim().toLowerCase();
  return reports.filter((report) => {
    if (statusFilter !== 'all' && report.status !== statusFilter) {
      return false;
    }
    if (!q) return true;
    return (
      report.subject.toLowerCase().includes(q) ||
      report.description.toLowerCase().includes(q) ||
      report.userFullName.toLowerCase().includes(q) ||
      report.userEmail.toLowerCase().includes(q) ||
      report.deviceInfo.toLowerCase().includes(q) ||
      report.ipAddress.toLowerCase().includes(q) ||
      report.adminNote.toLowerCase().includes(q)
    );
  });
}

export interface RegistrationValidationResult {
  valid: boolean;
  error?: string;
  cleanName: string;
  cleanEmail: string;
  cleanDepartment: string;
}

const VALID_ROLES: UserRole[] = ['admin', 'analyst', 'viewer'];
const VALID_STATUSES: UserAccountStatus[] = ['pending', 'active', 'suspended', 'blocked'];

export function isValidUserRole(value: unknown): value is UserRole {
  return typeof value === 'string' && VALID_ROLES.includes(value as UserRole);
}

export function isValidUserStatus(value: unknown): value is UserAccountStatus {
  return typeof value === 'string' && VALID_STATUSES.includes(value as UserAccountStatus);
}

export function validateRegistrationInput(input: {
  fullName?: string;
  email?: string;
  password?: string;
  department?: string;
}): RegistrationValidationResult {
  const cleanName = (input.fullName || '').trim().slice(0, 80);
  const cleanEmail = (input.email || '').trim().toLowerCase().slice(0, 120);
  const cleanDepartment = (input.department || 'SOC Operations').trim().slice(0, 60) || 'SOC Operations';
  const password = input.password || '';

  if (cleanName.length < 2) {
    return {
      valid: false,
      error: 'Full name must be at least 2 characters',
      cleanName,
      cleanEmail,
      cleanDepartment,
    };
  }

  if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
    return {
      valid: false,
      error: 'Valid email address is required',
      cleanName,
      cleanEmail,
      cleanDepartment,
    };
  }

  if (password.length < 8) {
    return {
      valid: false,
      error: 'Password must be at least 8 characters',
      cleanName,
      cleanEmail,
      cleanDepartment,
    };
  }

  return {
    valid: true,
    cleanName,
    cleanEmail,
    cleanDepartment,
  };
}

const SAMSUNG_PREFIX_MAP: Array<[RegExp, string]> = [
  [/^SM-S928/i, 'Samsung Galaxy S24 Ultra'],
  [/^SM-S926/i, 'Samsung Galaxy S24+'],
  [/^SM-S921/i, 'Samsung Galaxy S24'],
  [/^SM-S918/i, 'Samsung Galaxy S23 Ultra'],
  [/^SM-S916/i, 'Samsung Galaxy S23+'],
  [/^SM-S911/i, 'Samsung Galaxy S23'],
  [/^SM-S908/i, 'Samsung Galaxy S22 Ultra'],
  [/^SM-A556/i, 'Samsung Galaxy A55'],
  [/^SM-A546/i, 'Samsung Galaxy A54'],
  [/^SM-A536/i, 'Samsung Galaxy A53'],
  [/^SM-A356/i, 'Samsung Galaxy A35'],
  [/^SM-A346/i, 'Samsung Galaxy A34'],
  [/^SM-A155/i, 'Samsung Galaxy A15'],
  [/^SM-F956/i, 'Samsung Galaxy Z Fold6'],
  [/^SM-F741/i, 'Samsung Galaxy Z Flip6'],
];

const GENERIC_UA_TOKENS = new Set([
  'k',
  'u',
  'wv',
  'mobile',
  'tablet',
  'android',
  'linux',
  'x11',
  'win64',
  'x64',
  'wow64',
]);

export function formatDeviceModelName(rawModel: string | undefined): string | null {
  const cleaned = (rawModel || '')
    .replace(/^["']|["']$/g, '')
    .replace(/\bBuild\/.*$/i, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);

  if (!cleaned) return null;
  if (GENERIC_UA_TOKENS.has(cleaned.toLowerCase())) return null;
  if (/^[a-z]{2}(?:-[A-Z]{2})?$/.test(cleaned)) return null; // locale token e.g. en-US
  if (/^Android\s+\d+/i.test(cleaned)) return null;

  for (const [pattern, friendly] of SAMSUNG_PREFIX_MAP) {
    if (pattern.test(cleaned)) {
      return `${friendly} (${cleaned})`;
    }
  }
  if (/^SM-[A-Z0-9]+/i.test(cleaned)) {
    return `Samsung ${cleaned}`;
  }
  if (/^Pixel\s+/i.test(cleaned)) {
    return cleaned.startsWith('Google ') ? cleaned : `Google ${cleaned}`;
  }
  if (/^(Redmi|POCO|Mi\s)/i.test(cleaned)) {
    return `Xiaomi ${cleaned}`;
  }
  if (/^CPH\d+/i.test(cleaned)) {
    return `OPPO ${cleaned}`;
  }
  if (/^RMX\d+/i.test(cleaned)) {
    return `realme ${cleaned}`;
  }
  if (/^V2\d{3}/i.test(cleaned)) {
    return `vivo ${cleaned}`;
  }
  if (/^ASUS_/i.test(cleaned)) {
    return `ASUS ${cleaned}`;
  }

  return cleaned;
}

export function extractDeviceModelFromUserAgent(uaRaw: string | undefined): string | null {
  const ua = (uaRaw || '').trim();
  if (!ua) return null;

  const androidMatch = ua.match(/\(Linux;\s*(?:U;\s*)?Android[^;)]*;\s*([^)]+)\)/i);
  if (androidMatch?.[1]) {
    const segments = androidMatch[1]
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean);
    for (let i = segments.length - 1; i >= 0; i -= 1) {
      const candidate = formatDeviceModelName(segments[i]);
      if (candidate) return candidate;
    }
  }

  if (/ipad/i.test(ua)) return 'Apple iPad';
  if (/iphone/i.test(ua)) return 'Apple iPhone';
  if (/cros/i.test(ua)) return 'Chromebook';
  if (/macintosh|mac os x/i.test(ua)) return 'Apple Mac';
  if (/windows nt 10\.0|windows nt 11/i.test(ua)) return 'Windows PC';
  if (/windows/i.test(ua)) return 'Windows Workstation';
  if (/linux/i.test(ua) && !/android/i.test(ua)) return 'Linux Workstation';

  return null;
}

export function summarizeDeviceUserAgent(
  uaRaw: string | undefined,
  deviceHintRaw?: string | undefined,
): string {
  const ua = (uaRaw || '').trim();
  const explicitModel = formatDeviceModelName(deviceHintRaw);
  const uaModel = extractDeviceModelFromUserAgent(ua);
  const deviceModel = explicitModel || uaModel;

  if (!ua && !deviceModel) return 'Unknown Device';

  let os = 'Unknown OS';
  if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ios/i.test(ua)) os = 'iOS';
  else if (/cros/i.test(ua)) os = 'ChromeOS';
  else if (/windows/i.test(ua)) os = 'Windows';
  else if (/mac os x|macintosh/i.test(ua)) os = 'macOS';
  else if (/linux/i.test(ua)) os = 'Linux';

  let browser = 'Browser';
  if (/edg(?:a|ios)?\//i.test(ua)) browser = 'Edge';
  else if (/opr\/|opera/i.test(ua)) browser = 'Opera';
  else if (/samsungbrowser\//i.test(ua)) browser = 'Samsung Internet';
  else if (/chrome|crios/i.test(ua)) browser = 'Chrome';
  else if (/firefox|fxios/i.test(ua)) browser = 'Firefox';
  else if (/safari/i.test(ua)) browser = 'Safari';
  else if (/curl|postman|node|playwright/i.test(ua)) browser = 'API / Automation';

  if (deviceModel) {
    return `${deviceModel} · ${browser} · ${os}`;
  }
  return `${browser} · ${os}`;
}

export function splitDeviceSummary(deviceInfo: string | undefined): {
  deviceName: string;
  platformSummary: string;
} {
  const raw = (deviceInfo || '').trim();
  if (!raw) {
    return { deviceName: 'Unknown Device', platformSummary: 'Unknown Platform' };
  }
  const parts = raw.split('·').map((p) => p.trim()).filter(Boolean);
  if (parts.length >= 3) {
    return {
      deviceName: parts[0],
      platformSummary: parts.slice(1).join(' · '),
    };
  }
  if (parts.length === 2) {
    const osPart = parts[1].toLowerCase();
    const fallbackName =
      osPart === 'android'
        ? 'Android Smartphone'
        : osPart === 'ios'
          ? 'Apple iOS Device'
          : osPart === 'windows'
            ? 'Windows PC'
            : osPart === 'macos'
              ? 'Apple Mac'
              : osPart === 'linux'
                ? 'Linux Workstation'
                : 'Client Device';
    return {
      deviceName: fallbackName,
      platformSummary: raw,
    };
  }
  return {
    deviceName: raw,
    platformSummary: raw,
  };
}

export function extractClientIp(forwardedFor: string | string[] | undefined, remoteAddr: string | undefined): string {
  const raw = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
  if (raw && raw.trim().length > 0) {
    return raw.split(',')[0].trim().slice(0, 64);
  }
  const cleanRemote = (remoteAddr || '127.0.0.1').replace(/^::ffff:/, '');
  return cleanRemote.slice(0, 64);
}

export function canUserAuthenticate(status: UserAccountStatus): {
  allowed: boolean;
  reason?: string;
} {
  if (status === 'active') return { allowed: true };
  if (status === 'pending') {
    return {
      allowed: false,
      reason: 'ACCOUNT_PENDING',
    };
  }
  if (status === 'suspended') {
    return {
      allowed: false,
      reason: 'ACCOUNT_SUSPENDED',
    };
  }
  return {
    allowed: false,
    reason: 'ACCOUNT_BLOCKED',
  };
}

export function filterManagedUsers(
  users: ManagedUserAccount[],
  search: string,
  statusFilter: UserAccountStatus | 'all',
): ManagedUserAccount[] {
  const q = search.trim().toLowerCase();
  return users.filter((user) => {
    if (statusFilter !== 'all' && user.status !== statusFilter) {
      return false;
    }
    if (!q) return true;
    return (
      user.fullName.toLowerCase().includes(q) ||
      user.email.toLowerCase().includes(q) ||
      user.department.toLowerCase().includes(q) ||
      user.deviceInfo.toLowerCase().includes(q) ||
      user.registeredIp.toLowerCase().includes(q) ||
      user.issueNote.toLowerCase().includes(q)
    );
  });
}

export function roleDisplayName(role: UserRole): string {
  if (role === 'admin') return 'SOC Lead Administrator';
  if (role === 'analyst') return 'SOC Security Analyst';
  return 'Security Viewer';
}
