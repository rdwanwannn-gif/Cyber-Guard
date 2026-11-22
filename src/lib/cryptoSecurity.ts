import crypto from 'node:crypto';
import type { DecryptedLogPayload, EncryptedEnvelope, EncryptedLogEntry } from './types';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateEncryptionKeyHex(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function encryptTrafficPayload(
  payload: DecryptedLogPayload,
  keyHex: string,
  keyId: string,
): EncryptedEnvelope {
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) {
    throw new Error('AES-256-GCM requires a 32-byte (64 hex chars) key');
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    keyId,
    algorithm: 'AES-256-GCM',
  };
}

export function decryptTrafficPayload(
  envelope: EncryptedEnvelope,
  keyHex: string,
): DecryptedLogPayload {
  const key = Buffer.from(keyHex, 'hex');
  if (key.length !== 32) {
    throw new Error('AES-256-GCM requires a 32-byte (64 hex chars) key');
  }
  const iv = Buffer.from(envelope.iv, 'base64');
  const authTag = Buffer.from(envelope.authTag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8')) as DecryptedLogPayload;
}

export function computeLogIntegrityHash(
  prevHash: string,
  fields: {
    sequence: number;
    timestamp: string;
    sourceIp: string;
    destinationPort: number;
    ciphertext: string;
    keyId: string;
  },
): string {
  const canonical = `${prevHash}|${fields.sequence}|${fields.timestamp}|${fields.sourceIp}|${fields.destinationPort}|${fields.keyId}|${fields.ciphertext}`;
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

export function verifyLogChain(logs: EncryptedLogEntry[]): {
  valid: boolean;
  verifiedCount: number;
  brokenSequence: number | null;
} {
  if (logs.length === 0) {
    return { valid: true, verifiedCount: 0, brokenSequence: null };
  }
  const ordered = [...logs].sort((a, b) => a.sequence - b.sequence);
  for (let i = 0; i < ordered.length; i += 1) {
    const entry = ordered[i];
    if (i > 0 && entry.prevHash !== ordered[i - 1].integrityHash) {
      return { valid: false, verifiedCount: i, brokenSequence: entry.sequence };
    }
    const expectedHash = computeLogIntegrityHash(entry.prevHash, {
      sequence: entry.sequence,
      timestamp: entry.timestamp,
      sourceIp: entry.sourceIp,
      destinationPort: entry.destinationPort,
      ciphertext: entry.envelope.ciphertext,
      keyId: entry.keyId,
    });
    if (expectedHash !== entry.integrityHash) {
      return { valid: false, verifiedCount: i, brokenSequence: entry.sequence };
    }
  }
  return { valid: true, verifiedCount: ordered.length, brokenSequence: null };
}

export function generateTotpSecret(byteLength = 20): string {
  const bytes = crypto.randomBytes(byteLength);
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

export function base32Decode(secret: string): Buffer {
  const cleaned = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const char of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function computeTotpCode(secretBase32: string, timeMs = Date.now(), stepSeconds = 30): string {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(timeMs / 1000 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1_000_000;
  return otp.toString().padStart(6, '0');
}

export function verifyTotpCode(
  secretBase32: string,
  submittedCode: string,
  timeMs = Date.now(),
  windowSteps = 1,
): boolean {
  const normalized = submittedCode.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) {
    return false;
  }

  const submittedBuf = Buffer.from(normalized, 'utf8');
  for (let delta = -windowSteps; delta <= windowSteps; delta += 1) {
    const candidate = computeTotpCode(secretBase32, timeMs + delta * 30_000);
    const candidateBuf = Buffer.from(candidate, 'utf8');
    if (crypto.timingSafeEqual(submittedBuf, candidateBuf)) {
      return true;
    }
  }
  return false;
}

export function hashPasswordScrypt(password: string, saltHex?: string): string {
  const salt = saltHex ?? crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPasswordScrypt(password: string, storedHash: string): boolean {
  const parts = storedHash.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  if (!salt || !expectedHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

export function hashApiKey(rawKey: string): string {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

export function generateNumericOtp(digits = 6): string {
  const min = 10 ** (digits - 1);
  const max = 10 ** digits;
  return String(crypto.randomInt(min, max)).padStart(digits, '0');
}

export function createStatelessEmailOtpChallenge(params: {
  email: string;
  otp: string;
  signingSecret: string;
  ttlMs?: number;
  nowMs?: number;
}): { challengeToken: string; expiresAt: number } {
  const cleanEmail = params.email.trim().toLowerCase();
  const cleanOtp = params.otp.replace(/\s+/g, '');
  const now = params.nowMs ?? Date.now();
  const expiresAt = now + (params.ttlMs ?? 10 * 60_000);
  const nonce = crypto.randomBytes(12).toString('hex');
  const otpHash = crypto
    .createHmac('sha256', params.signingSecret)
    .update(`otp:${nonce}:${cleanEmail}:${cleanOtp}`)
    .digest('base64url');

  const payload = Buffer.from(
    JSON.stringify({
      nonce,
      email: cleanEmail,
      accountType: 'admin',
      otpHash,
      expiresAt,
    }),
    'utf8',
  ).toString('base64url');

  const sig = crypto
    .createHmac('sha256', params.signingSecret)
    .update(`email-otp:${payload}`)
    .digest('base64url');

  return {
    challengeToken: `${payload}.${sig}`,
    expiresAt,
  };
}

export function verifyStatelessEmailOtpChallenge(
  challengeToken: string,
  submittedOtp: string,
  signingSecret: string,
  nowMs = Date.now(),
): { valid: boolean; email?: string; nonce?: string; reason?: string } {
  const parts = (challengeToken || '').split('.');
  if (parts.length !== 2) {
    return { valid: false, reason: 'Invalid OTP challenge token' };
  }
  const [payload, sig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', signingSecret)
    .update(`email-otp:${payload}`)
    .digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return { valid: false, reason: 'Invalid OTP challenge signature' };
  }

  let decoded: {
    nonce?: string;
    email?: string;
    accountType?: string;
    otpHash?: string;
    expiresAt?: number;
  };
  try {
    decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'Malformed OTP challenge' };
  }

  if (
    !decoded.nonce ||
    !decoded.email ||
    decoded.accountType !== 'admin' ||
    !decoded.otpHash ||
    !decoded.expiresAt
  ) {
    return { valid: false, reason: 'Incomplete OTP challenge' };
  }

  if (decoded.expiresAt < nowMs) {
    return { valid: false, reason: 'Kode OTP sudah kedaluwarsa. Silakan kirim ulang kode OTP baru.' };
  }

  const normalizedOtp = (submittedOtp || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalizedOtp)) {
    return { valid: false, reason: 'Kode OTP harus berupa 6 digit angka.' };
  }

  const candidateHash = crypto
    .createHmac('sha256', signingSecret)
    .update(`otp:${decoded.nonce}:${decoded.email}:${normalizedOtp}`)
    .digest('base64url');

  const hashBuf = Buffer.from(decoded.otpHash);
  const candBuf = Buffer.from(candidateHash);
  if (hashBuf.length !== candBuf.length || !crypto.timingSafeEqual(hashBuf, candBuf)) {
    return { valid: false, reason: 'Kode OTP email tidak sesuai.' };
  }

  return { valid: true, email: decoded.email, nonce: decoded.nonce };
}

