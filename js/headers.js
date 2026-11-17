// HTTP security header audit. Pure functions, no DOM.

export function parseHeaders(raw) {
  const h = { 'set-cookie': [] };
  for (const line of String(raw).split(/\r?\n/)) {
    const i = line.indexOf(':');
    if (i <= 0 || /^HTTP\//i.test(line)) continue;
    const name = line.slice(0, i).trim().toLowerCase();
    const value = line.slice(i + 1).trim();
    if (name === 'set-cookie') h['set-cookie'].push(value);
    else h[name] = value;
  }
  return h;
}

export function auditHeaders(h) {
  const out = [];
  const add = (status, name, message, fix = '') => out.push({ status, name, message, fix });

  const hsts = h['strict-transport-security'];
  const hstsFix = 'Strict-Transport-Security: max-age=31536000; includeSubDomains';
  if (!hsts) add('fail', 'Strict-Transport-Security', 'Missing: browsers may still connect over plain HTTP.', hstsFix);
  else {
    const m = /max-age=(\d+)/i.exec(hsts);
    if (!m || +m[1] < 15552000) add('warn', 'Strict-Transport-Security', 'max-age is shorter than 6 months.', hstsFix);
    else add('pass', 'Strict-Transport-Security', `Enabled (${hsts}).`);
  }

  const csp = h['content-security-policy'];
  if (!csp) add('fail', 'Content-Security-Policy', 'Missing: no defence-in-depth against XSS and content injection.', "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'");
  else if (/'unsafe-inline'|'unsafe-eval'/.test(csp)) add('warn', 'Content-Security-Policy', "Allows 'unsafe-inline' or 'unsafe-eval', which weakens XSS protection.", 'Replace inline scripts with nonces or hashes.');
  else add('pass', 'Content-Security-Policy', 'Defined.');

  const xfo = h['x-frame-options'];
  if (xfo || /frame-ancestors/i.test(csp || '')) add('pass', 'Clickjacking protection', xfo ? `X-Frame-Options: ${xfo}` : 'CSP frame-ancestors is set.');
  else add('fail', 'X-Frame-Options', 'Missing: the page can be framed by other sites (clickjacking).', 'X-Frame-Options: DENY');

  if (/nosniff/i.test(h['x-content-type-options'] || '')) add('pass', 'X-Content-Type-Options', 'nosniff is set.');
  else add('fail', 'X-Content-Type-Options', 'Missing: browsers may MIME-sniff responses.', 'X-Content-Type-Options: nosniff');

  const rp = h['referrer-policy'];
  if (!rp) add('warn', 'Referrer-Policy', 'Missing: full URLs may leak to third parties.', 'Referrer-Policy: strict-origin-when-cross-origin');
  else if (/unsafe-url/i.test(rp)) add('warn', 'Referrer-Policy', 'unsafe-url leaks full URLs, including over HTTP.', 'Referrer-Policy: strict-origin-when-cross-origin');
  else add('pass', 'Referrer-Policy', rp);

  if (h['permissions-policy']) add('pass', 'Permissions-Policy', 'Defined.');
  else add('warn', 'Permissions-Policy', 'Missing: powerful browser features are not restricted.', 'Permissions-Policy: camera=(), microphone=(), geolocation=()');

  if (h.server && /\d/.test(h.server)) add('warn', 'Server', `Reveals software version (${h.server}).`, 'Hide the version, e.g. "server_tokens off;" in nginx or "ServerTokens Prod" in Apache.');
  if (h['x-powered-by']) add('warn', 'X-Powered-By', `Reveals the technology stack (${h['x-powered-by']}).`, 'Remove the X-Powered-By header.');

  for (const c of h['set-cookie']) {
    const name = c.split('=')[0];
    const missing = ['Secure', 'HttpOnly', 'SameSite'].filter((f) => !new RegExp(`;\\s*${f}`, 'i').test(c));
    if (missing.length) add('warn', `Cookie "${name}"`, `Missing flags: ${missing.join(', ')}.`, `Set-Cookie: ${name}=…; Secure; HttpOnly; SameSite=Lax`);
    else add('pass', `Cookie "${name}"`, 'Secure, HttpOnly and SameSite set.');
  }
  return out;
}

export function gradeOf(results) {
  const fails = results.filter((r) => r.status === 'fail').length;
  const warns = results.filter((r) => r.status === 'warn').length;
  const score = Math.max(0, 100 - fails * 20 - warns * 7);
  const letter = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, letter };
}
