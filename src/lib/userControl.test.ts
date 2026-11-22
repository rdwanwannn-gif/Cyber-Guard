import assert from 'node:assert/strict';
import test from 'node:test';
import type { ManagedUserAccount, UserComplaintReport } from './types';
import {
  canUserAuthenticate,
  extractClientIp,
  filterManagedUsers,
  filterUserReports,
  isValidComplaintCategory,
  isValidComplaintStatus,
  isValidUserRole,
  isValidUserStatus,
  portalSessionStorageKey,
  resolvePortalFromPathname,
  summarizeDeviceUserAgent,
  validateComplaintInput,
  validateRegistrationInput,
} from './userControl';

test('validateRegistrationInput accepts valid fields and rejects invalid email or short password', () => {
  const ok = validateRegistrationInput({
    fullName: 'Budi Santoso',
    email: 'BUDI@Enterprise.id',
    password: 'StrongPassword123!',
    department: 'Blue Team',
  });
  assert.equal(ok.valid, true);
  assert.equal(ok.cleanEmail, 'budi@enterprise.id');
  assert.equal(ok.cleanName, 'Budi Santoso');

  const badEmail = validateRegistrationInput({
    fullName: 'Budi',
    email: 'not-an-email',
    password: 'StrongPassword123!',
  });
  assert.equal(badEmail.valid, false);

  const shortPass = validateRegistrationInput({
    fullName: 'Budi',
    email: 'budi@enterprise.id',
    password: '123',
  });
  assert.equal(shortPass.valid, false);
});

test('summarizeDeviceUserAgent and extractClientIp format remote device metadata cleanly', () => {
  assert.equal(
    summarizeDeviceUserAgent('Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126.0 Mobile'),
    'Chrome · Android',
  );
  assert.equal(
    summarizeDeviceUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Safari/604.1'),
    'Safari · iOS',
  );
  assert.equal(extractClientIp('203.0.113.45, 10.0.0.2', '::ffff:127.0.0.1'), '203.0.113.45');
  assert.equal(extractClientIp(undefined, '::ffff:192.168.1.50'), '192.168.1.50');
});

test('canUserAuthenticate allows only active accounts and blocks pending/suspended/blocked', () => {
  assert.deepEqual(canUserAuthenticate('active'), { allowed: true });
  assert.deepEqual(canUserAuthenticate('pending'), { allowed: false, reason: 'ACCOUNT_PENDING' });
  assert.deepEqual(canUserAuthenticate('suspended'), { allowed: false, reason: 'ACCOUNT_SUSPENDED' });
  assert.deepEqual(canUserAuthenticate('blocked'), { allowed: false, reason: 'ACCOUNT_BLOCKED' });
});

test('filterManagedUsers filters by search query and account status', () => {
  const sampleUsers: ManagedUserAccount[] = [
    {
      id: 'USR-1',
      fullName: 'Siti Rahma',
      email: 'siti@corp.id',
      department: 'IR Team',
      role: 'analyst',
      status: 'pending',
      mfaEnrolled: false,
      registeredAt: '2026-11-22T01:00:00Z',
      registeredIp: '182.253.44.10',
      deviceInfo: 'Chrome · Android',
      lastLoginAt: null,
      activeSessionCount: 0,
      issueFlagged: false,
      issueNote: '',
      approvedBy: null,
      updatedAt: '2026-11-22T01:00:00Z',
    },
    {
      id: 'USR-2',
      fullName: 'Andi Wijaya',
      email: 'andi@corp.id',
      department: 'Network Ops',
      role: 'viewer',
      status: 'suspended',
      mfaEnrolled: true,
      registeredAt: '2026-11-21T10:00:00Z',
      registeredIp: '103.11.22.33',
      deviceInfo: 'Safari · iOS',
      lastLoginAt: '2026-11-22T00:00:00Z',
      activeSessionCount: 0,
      issueFlagged: true,
      issueNote: 'Anomali login berulang',
      approvedBy: 'admin@corp.id',
      updatedAt: '2026-11-22T00:30:00Z',
    },
  ];

  assert.equal(filterManagedUsers(sampleUsers, '', 'all').length, 2);
  assert.equal(filterManagedUsers(sampleUsers, '', 'pending').length, 1);
  assert.equal(filterManagedUsers(sampleUsers, 'android', 'all')[0].id, 'USR-1');
  assert.equal(filterManagedUsers(sampleUsers, 'anomali', 'all')[0].id, 'USR-2');
  assert.equal(isValidUserRole('analyst'), true);
  assert.equal(isValidUserRole('superroot'), false);
  assert.equal(isValidUserStatus('blocked'), true);
  assert.equal(isValidUserStatus('deleted'), false);
});

test('resolvePortalFromPathname & portalSessionStorageKey separate admin and user portals cleanly', () => {
  assert.equal(resolvePortalFromPathname('/'), 'admin');
  assert.equal(resolvePortalFromPathname('/admin'), 'admin');
  assert.equal(resolvePortalFromPathname('/admin/users'), 'admin');
  assert.equal(resolvePortalFromPathname('/user'), 'user');
  assert.equal(resolvePortalFromPathname('/user/reports'), 'user');
  assert.equal(resolvePortalFromPathname('/pengguna'), 'user');
  assert.notEqual(portalSessionStorageKey('admin'), portalSessionStorageKey('user'));
});

test('validateComplaintInput & filterUserReports enforce bounds and filter complaints accurately', () => {
  const valid = validateComplaintInput({
    category: 'access_mfa',
    severity: 'high',
    subject: 'Kendala kode TOTP saat login',
    description: 'Token autentikator selalu ditolak meskipun jam perangkat sudah sinkron.',
  });
  assert.equal(valid.valid, true);
  assert.equal(valid.cleanCategory, 'access_mfa');
  assert.equal(valid.cleanSeverity, 'high');

  const shortDesc = validateComplaintInput({
    category: 'other',
    severity: 'low',
    subject: 'Test',
    description: 'Pendek',
  });
  assert.equal(shortDesc.valid, false);
  assert.equal(isValidComplaintCategory('security_incident'), true);
  assert.equal(isValidComplaintCategory('invalid_cat'), false);
  assert.equal(isValidComplaintStatus('in_review'), true);
  assert.equal(isValidComplaintStatus('archived'), false);

  const reports: UserComplaintReport[] = [
    {
      id: 'RPT-USR-1',
      userId: 'USR-1',
      userFullName: 'Siti Rahma',
      userEmail: 'siti@corp.id',
      department: 'IR Team',
      deviceInfo: 'Chrome · Android',
      ipAddress: '182.253.44.10',
      category: 'access_mfa',
      severity: 'high',
      subject: 'Kendala MFA Android',
      description: 'Kode MFA gagal saat login.',
      status: 'open',
      adminNote: '',
      handledBy: null,
      createdAt: '2026-11-22T01:00:00Z',
      updatedAt: '2026-11-22T01:00:00Z',
    },
    {
      id: 'RPT-USR-2',
      userId: 'USR-2',
      userFullName: 'Andi Wijaya',
      userEmail: 'andi@corp.id',
      department: 'Ops',
      deviceInfo: 'Safari · iOS',
      ipAddress: '103.11.22.33',
      category: 'security_incident',
      severity: 'critical',
      subject: 'Lonjakan IP Asing',
      description: 'Terlihat scan port 22 berulang.',
      status: 'resolved',
      adminNote: 'Sudah diblokir WAF',
      handledBy: 'admin@corp.id',
      createdAt: '2026-11-22T00:00:00Z',
      updatedAt: '2026-11-22T00:30:00Z',
    },
  ];
  assert.equal(filterUserReports(reports, '', 'open').length, 1);
  assert.equal(filterUserReports(reports, 'android', 'all')[0].id, 'RPT-USR-1');
  assert.equal(filterUserReports(reports, 'waf', 'resolved')[0].id, 'RPT-USR-2');
});
