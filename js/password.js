// Password strength estimate + Have I Been Pwned k-anonymity lookup.

// shortcut: tiny built-in wordlist; swap for zxcvbn if estimates need to be more accurate.
const COMMON = ['password', 'passw0rd', '123456', '12345678', 'qwerty', 'letmein', 'admin', 'welcome', 'iloveyou',
  'monkey', 'dragon', 'football', 'abc123', '111111', '123123', '000000', 'contraseña', 'barcelona', 'master', 'login'];

function hasSequence(s) {
  for (let i = 0; i + 2 < s.length; i++) {
    const a = s.charCodeAt(i), b = s.charCodeAt(i + 1), c = s.charCodeAt(i + 2);
    if (/[a-z0-9]/.test(s[i]) && b - a === 1 && c - b === 1) return true;
  }
  return /qwe|wer|ert|asd|sdf|zxc/.test(s);
}

export function analyzePassword(pw) {
  if (!pw) return null;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(pool);
  const issues = [];
  const lower = pw.toLowerCase();
  if (COMMON.some((w) => lower.includes(w))) { issues.push('Contains a very common password or word.'); bits = Math.min(bits, 20); }
  if (/(.)\1{2,}/.test(pw)) { issues.push('Repeats the same character 3+ times.'); bits -= 10; }
  if (hasSequence(lower)) { issues.push('Contains a sequence such as "abc", "123" or "qwe".'); bits -= 10; }
  if (pw.length < 12) issues.push('Shorter than 12 characters.');
  if (/^\d+$/.test(pw)) issues.push('Uses digits only.');
  if (pool < 60 && pw.length >= 12) issues.push('Mix upper case, digits and symbols, or use a longer passphrase.');
  bits = Math.max(0, bits);
  // Offline attack against a fast hash at 10^10 guesses/s; on average half the space is searched.
  const seconds = 2 ** bits / 2 / 1e10;
  const label = bits < 28 ? 'Very weak' : bits < 36 ? 'Weak' : bits < 60 ? 'Fair' : bits < 80 ? 'Strong' : 'Very strong';
  return { bits: Math.round(bits), seconds, label, issues };
}

export function formatDuration(s) {
  if (!Number.isFinite(s) || s > 3.15e16) return 'billions of years';
  if (s < 1) return 'instantly';
  const units = [['year', 31557600], ['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
  for (const [name, size] of units) {
    if (s >= size) {
      const v = Math.floor(s / size);
      return `${v.toLocaleString('en-US')} ${name}${v === 1 ? '' : 's'}`;
    }
  }
  return 'instantly';
}

export async function sha1Hex(text) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

// Only the first 5 hex chars of the SHA-1 leave the browser (k-anonymity).
export async function pwnedCount(pw) {
  const hash = await sha1Hex(pw);
  const prefix = hash.slice(0, 5), suffix = hash.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error(`Breach API returned HTTP ${res.status}`);
  for (const line of (await res.text()).split('\n')) {
    const [suf, count] = line.trim().split(':');
    if (suf === suffix) return Number(count);
  }
  return 0;
}
