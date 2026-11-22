import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeLogIntegrityHash,
  computeTotpCode,
  decryptTrafficPayload,
  encryptTrafficPayload,
  generateEncryptionKeyHex,
  generateTotpSecret,
  hashPasswordScrypt,
  verifyLogChain,
  verifyPasswordScrypt,
  verifyTotpCode,
} from './cryptoSecurity';
import type { DecryptedLogPayload, EncryptedLogEntry } from './types';

test('AES-256-GCM encrypts and decrypts traffic log payload', () => {
  const keyHex = generateEncryptionKeyHex();
  const payload: DecryptedLogPayload = {
    eventId: 'evt-001',
    timestamp: '2026-11-22T09:00:00.000Z',
    sourceIp: '198.51.100.42',
    destinationIp: '10.20.4.18',
    destinationPort: 443,
    protocol: 'TLS 1.3',
    action: 'DROP',
    bytes: 4096,
    tlsCipher: 'TLS_AES_256_GCM_SHA384',
    userAgentOrProcess: 'curl/8.5.0',
    threatSignature: 'SIG-WAF-2104',
  };

  const envelope = encryptTrafficPayload(payload, keyHex, 'KEY-2026-01');
  assert.equal(envelope.algorithm, 'AES-256-GCM');
  assert.ok(envelope.ciphertext.length > 10);

  const decrypted = decryptTrafficPayload(envelope, keyHex);
  assert.deepEqual(decrypted, payload);

  const wrongKey = generateEncryptionKeyHex();
  assert.throws(() => decryptTrafficPayload(envelope, wrongKey));
});

test('SHA-256 log integrity chain detects tampering', () => {
  const keyHex = generateEncryptionKeyHex();
  const makeEntry = (seq: number, prevHash: string, ip: string): EncryptedLogEntry => {
    const timestamp = `2026-11-22T09:0${seq}:00.000Z`;
    const envelope = encryptTrafficPayload(
      {
        eventId: `evt-${seq}`,
        timestamp,
        sourceIp: ip,
        destinationIp: '10.0.1.5',
        destinationPort: 443,
        protocol: 'HTTPS',
        action: 'ALLOW',
        bytes: 1200,
        tlsCipher: 'TLS_AES_256_GCM_SHA384',
        userAgentOrProcess: 'nginx-ingress',
        threatSignature: null,
      },
      keyHex,
      'KEY-1',
    );
    const integrityHash = computeLogIntegrityHash(prevHash, {
      sequence: seq,
      timestamp,
      sourceIp: ip,
      destinationPort: 443,
      ciphertext: envelope.ciphertext,
      keyId: 'KEY-1',
    });
    return {
      id: `log-${seq}`,
      sequence: seq,
      timestamp,
      sourceIp: ip,
      destinationPort: 443,
      protocol: 'HTTPS',
      severity: 'low',
      keyId: 'KEY-1',
      prevHash,
      integrityHash,
      envelope,
    };
  };

  const first = makeEntry(1, 'GENESIS', '203.0.113.1');
  const second = makeEntry(2, first.integrityHash, '203.0.113.2');
  const validResult = verifyLogChain([first, second]);
  assert.equal(validResult.valid, true);
  assert.equal(validResult.verifiedCount, 2);

  const tamperedSecond: EncryptedLogEntry = { ...second, sourceIp: '203.0.113.99' };
  const invalidResult = verifyLogChain([first, tamperedSecond]);
  assert.equal(invalidResult.valid, false);
  assert.equal(invalidResult.brokenSequence, 2);
});

test('RFC 6238 TOTP MFA generates and verifies 6-digit codes', () => {
  const secret = generateTotpSecret();
  const now = 1_795_340_000_000;
  const code = computeTotpCode(secret, now);
  assert.match(code, /^\d{6}$/);
  assert.equal(verifyTotpCode(secret, code, now), true);
  assert.equal(verifyTotpCode(secret, code, now + 29_000), true);
  assert.equal(verifyTotpCode(secret, '000000', now), code === '000000');
});

test('scrypt password hashing verifies correct passwords and rejects wrong ones', () => {
  const hash = hashPasswordScrypt('S3ntinel#2026!');
  assert.equal(verifyPasswordScrypt('S3ntinel#2026!', hash), true);
  assert.equal(verifyPasswordScrypt('wrong-password', hash), false);
});
