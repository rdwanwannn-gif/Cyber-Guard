const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function decodeBase32(secret: string): Uint8Array {
  const cleaned = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export async function generateBrowserTotpFromEnrollmentSecret(secretBase32: string): Promise<string> {
  const keyBytes = decodeBase32(secretBase32);
  const counter = Math.floor(Date.now() / 1000 / 30);
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(0, Math.floor(counter / 0x100000000), false);
  view.setUint32(4, counter >>> 0, false);

  const keyCopy = new Uint8Array(keyBytes.length);
  keyCopy.set(keyBytes);

  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    keyCopy.buffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );

  const sig = new Uint8Array(await window.crypto.subtle.sign('HMAC', cryptoKey, counterBuf));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);

  return String(binary % 1_000_000).padStart(6, '0');
}
