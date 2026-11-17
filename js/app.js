import { parseInput, calcIPv4, calcIPv6, splitIPv4, parseIPv4 } from './subnet.js';
import { parseHeaders, auditHeaders, gradeOf } from './headers.js';
import { analyzePassword, formatDuration, pwnedCount } from './password.js';
import { SERVICES, toIptables, toNftables, toUfw } from './firewall.js';
import { CHECKS, buildAuditScript } from './hardening.js';
import { analyzeAuthLog, blockCommands } from './logs.js';
import { normalizeUrl, checkUrl, buildMonitorScript } from './monitor.js';
import { LANGS, t, setLang, getLang, fmtNum } from './i18n.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const badge = (s, label = t(`b.${s}`)) => `<span class="badge ${s}">${esc(label)}</span>`;
const kv = (pairs) => `<dl class="kv">${pairs.map(([k, v]) => `<div><dt>${esc(t(k))}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>`;
const errText = (err) => t(err.message, err.params);
const store = {
  get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode: preference just isn't remembered */ } },
};

function download(name, text) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
}

document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  await navigator.clipboard.writeText($(btn.dataset.copy).textContent);
  btn.textContent = t('Copied');
  setTimeout(() => (btn.textContent = t('Copy')), 1200);
});

// ---------- Theme ----------
const systemDark = matchMedia('(prefers-color-scheme: dark)');
const currentTheme = () => document.documentElement.dataset.theme || (systemDark.matches ? 'dark' : 'light');
function syncThemeMeta() {
  document.querySelector('meta[name="theme-color"]').content = currentTheme() === 'dark' ? '#0d1017' : '#f6f7fb';
}
$('theme-toggle').addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  store.set('netsec-theme', next);
  syncThemeMeta();
});
syncThemeMeta();

// ---------- Language ----------
// Each tool registers a function that re-renders its current output in the active language.
const rerenders = [];
$('lang-select').innerHTML = Object.entries(LANGS).map(([code, label]) => `<option value="${code}">${label}</option>`).join('');
function applyLang(lang) {
  setLang(lang);
  document.documentElement.lang = getLang();
  $('lang-select').value = getLang();
  document.querySelectorAll('[data-i18n]').forEach((el) => (el.textContent = t(el.dataset.i18n)));
  // Only keys from our own dictionary go through innerHTML.
  document.querySelectorAll('[data-i18n-html]').forEach((el) => (el.innerHTML = t(el.dataset.i18nHtml)));
  document.querySelectorAll('[data-i18n-aria]').forEach((el) => el.setAttribute('aria-label', t(el.dataset.i18nAria)));
  rerenders.forEach((fn) => fn());
}
$('lang-select').addEventListener('change', (e) => {
  store.set('netsec-lang', e.target.value);
  applyLang(e.target.value);
});

// ---------- Routing ----------
function route() {
  const id = location.hash.slice(1) || 'home';
  const target = document.getElementById(id)?.classList.contains('tool') ? id : 'home';
  document.querySelectorAll('.tool').forEach((s) => (s.hidden = s.id !== target));
  document.querySelectorAll('nav a').forEach((a) => (a.hash === `#${target}` ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  // Keep the active tab visible in the horizontally scrolling mobile nav.
  document.querySelector('nav a[aria-current]')?.scrollIntoView({ block: 'nearest', inline: 'center' });
  window.scrollTo(0, 0);
}
addEventListener('hashchange', route);

// ---------- 1. Subnet ----------
let lastV4 = null;
let splitShown = false;
function runSubnet() {
  $('subnet-error').textContent = '';
  try {
    const { version, ip, prefix } = parseInput($('subnet-input').value);
    if (version === 4) {
      const r = calcIPv4(ip, prefix);
      if (!lastV4 || lastV4.ip !== ip || lastV4.prefix !== prefix) splitShown = false;
      lastV4 = { ip, prefix };
      $('subnet-result').innerHTML = kv([
        ['Network', r.cidr], ['Subnet mask', r.mask], ['Wildcard mask', r.wildcard], ['Broadcast', r.broadcast],
        ['First host', r.firstHost], ['Last host', r.lastHost], ['Usable hosts', fmtNum(r.usableHosts)],
        ['Total addresses', fmtNum(r.totalAddresses)], ['Class', t(r.ipClass)], ['Scope', t(r.scope)], ['Binary mask', r.binaryMask],
      ]);
      $('split-form').hidden = prefix >= 32;
      $('split-prefix').min = prefix + 1;
      $('split-prefix').value = Math.min(32, Math.max(prefix + 1, +$('split-prefix').value));
    } else {
      const r = calcIPv6(ip, prefix);
      lastV4 = null;
      splitShown = false;
      $('split-form').hidden = true;
      $('subnet-result').innerHTML = kv([
        ['Network', r.cidr], ['First address', r.firstAddress], ['Last address', r.lastAddress],
        ['Total addresses', r.totalAddresses], ['Scope', t(r.scope)], ['Expanded', r.expanded],
      ]);
    }
  } catch (err) {
    lastV4 = null;
    splitShown = false;
    $('subnet-result').innerHTML = '';
    $('split-form').hidden = true;
    $('subnet-error').textContent = errText(err);
  }
  renderSplit();
}
function renderSplit() {
  $('split-result').innerHTML = '';
  if (!splitShown || !lastV4) return;
  try {
    const { count, rows } = splitIPv4(lastV4.ip, lastV4.prefix, Number($('split-prefix').value));
    $('split-result').innerHTML = `<p class="hint">${esc(t('{n} subnets', { n: fmtNum(count) }))}${count > rows.length ? ` ${esc(t('(showing first {n})', { n: rows.length }))}` : ''}</p>
      <div class="table-wrap"><table><tr><th>#</th><th>${esc(t('Subnet'))}</th><th>${esc(t('First host'))}</th><th>${esc(t('Last host'))}</th><th>${esc(t('Broadcast'))}</th><th>${esc(t('Hosts'))}</th></tr>
      ${rows.map((r, i) => `<tr><td>${i + 1}</td><td class="mono">${r.cidr}</td><td class="mono">${r.first}</td><td class="mono">${r.last}</td><td class="mono">${r.broadcast}</td><td>${fmtNum(r.hosts)}</td></tr>`).join('')}
      </table></div>`;
  } catch (err) {
    $('subnet-error').textContent = errText(err);
  }
}
$('subnet-form').addEventListener('submit', (e) => { e.preventDefault(); runSubnet(); });
$('split-form').addEventListener('submit', (e) => { e.preventDefault(); splitShown = true; $('subnet-error').textContent = ''; renderSplit(); });
rerenders.push(runSubnet);

// ---------- 2. Headers ----------
const SAMPLE_HEADERS = `HTTP/2 200
server: nginx/1.18.0 (Ubuntu)
content-type: text/html; charset=UTF-8
x-powered-by: PHP/7.4.3
strict-transport-security: max-age=3600
x-content-type-options: nosniff
set-cookie: session=abc123; Path=/; HttpOnly`;
let headersShown = false;
$('headers-sample').addEventListener('click', () => { $('headers-input').value = SAMPLE_HEADERS; headersShown = true; runHeaders(); });
$('headers-run').addEventListener('click', () => { headersShown = true; runHeaders(); });
function runHeaders() {
  if (!headersShown) return;
  const raw = $('headers-input').value.trim();
  if (!raw) { $('headers-result').innerHTML = `<p class="error">${esc(t('Paste some headers first.'))}</p>`; return; }
  const results = auditHeaders(parseHeaders(raw));
  const { score, letter } = gradeOf(results);
  const cls = letter === 'A' ? 'pass' : letter <= 'C' ? 'warn' : 'fail';
  $('headers-result').innerHTML = `
    <div class="grade"><div class="grade-letter ${cls}">${letter}</div><div><b>${esc(t('Score {n}/100', { n: score }))}</b><br><span class="hint">${esc(t('{n} issue(s) found', { n: results.filter((r) => r.status !== 'pass').length }))}</span></div></div>
    <div class="table-wrap"><table class="stack"><tr><th>${esc(t('Status'))}</th><th>${esc(t('Header'))}</th><th>${esc(t('Finding'))}</th><th>${esc(t('Recommended fix'))}</th></tr>
    ${results.map((r) => `<tr><td>${badge(r.status)}</td><td><b>${esc(t(r.name))}</b></td><td>${esc(t(r.message, r.params))}</td><td class="mono">${esc(t(r.fix, r.params))}</td></tr>`).join('')}
    </table></div>`;
}
rerenders.push(runHeaders);

// ---------- 3. Password ----------
const COLORS = { 'Very weak': 'var(--fail)', Weak: 'var(--fail)', Fair: 'var(--warn)', Strong: 'var(--pass)', 'Very strong': 'var(--pass)' };
let pwnedState = null; // { n } | { error } | 'checking'
$('pw-toggle').addEventListener('click', () => {
  $('pw-input').type = $('pw-input').type === 'password' ? 'text' : 'password';
  renderPwToggle();
});
function renderPwToggle() { $('pw-toggle').textContent = t($('pw-input').type === 'password' ? 'Show' : 'Hide'); }
$('pw-input').addEventListener('input', () => { pwnedState = null; renderPassword(); });
function renderPassword() {
  renderPwToggle();
  const r = analyzePassword($('pw-input').value);
  if (!r) { $('pw-result').innerHTML = ''; $('pw-bar').style.width = '0'; }
  else {
    $('pw-bar').style.width = `${Math.min(100, r.bits)}%`;
    $('pw-bar').style.background = COLORS[r.label];
    $('pw-result').innerHTML = `<p><b style="color:${COLORS[r.label]}">${esc(t(r.label))}</b> · ${esc(t('~{n} bits of entropy', { n: r.bits }))} · ${esc(t('estimated offline crack time:'))} <b>${esc(formatDuration(r.seconds, t, fmtNum))}</b></p>
      ${r.issues.length ? `<ul class="issues">${r.issues.map((i) => `<li>${esc(t(i))}</li>`).join('')}</ul>` : ''}`;
  }
  const out = $('pw-pwned-result');
  if (!pwnedState) out.innerHTML = '';
  else if (pwnedState === 'checking') out.textContent = t('Checking…');
  else if (pwnedState.error) out.textContent = t('Could not reach the breach database: {v}', { v: pwnedState.error });
  else if (pwnedState.empty) out.textContent = t('Type a password first.');
  else out.innerHTML = pwnedState.n
    ? `<span class="fail"><b>${esc(t('Found in {n} breaches.', { n: fmtNum(pwnedState.n) }))}</b> ${esc(t('Do not use this password.'))}</span>`
    : `<span class="pass"><b>${esc(t('Not found in known breaches.'))}</b></span>`;
}
$('pw-pwned').addEventListener('click', async () => {
  const pw = $('pw-input').value;
  if (!pw) { pwnedState = { empty: true }; renderPassword(); return; }
  pwnedState = 'checking';
  renderPassword();
  try { pwnedState = { n: await pwnedCount(pw) }; } catch (err) { pwnedState = { error: err.message }; }
  if ($('pw-input').value === pw) renderPassword(); // ignore a stale answer if the user kept typing
});
rerenders.push(renderPassword);

// ---------- 4. Firewall ----------
let fwFormat = 'iptables';
function renderFwServices() {
  const checked = new Set([...$('fw-services').querySelectorAll('input:checked')].map((i) => i.value));
  const initial = !$('fw-services').children.length;
  $('fw-services').innerHTML = SERVICES.map((s) => {
    const on = initial ? ['ssh', 'http', 'https'].includes(s.id) : checked.has(s.id);
    return `<label><input type="checkbox" value="${s.id}" ${on ? 'checked' : ''}/> ${esc(t(s.name))} <span class="hint">(${s.ports.map((p) => p.join('/')).join(', ')})</span></label>`;
  }).join('');
}
function fwOptions() {
  const services = [...$('fw-services').querySelectorAll('input:checked')].map((i) => i.value);
  const custom = [];
  for (const part of $('fw-custom').value.split(/[,\s]+/).filter(Boolean)) {
    const m = /^(\d{1,5})(?:\/(tcp|udp))?$/i.exec(part);
    if (!m || +m[1] < 1 || +m[1] > 65535) throw Object.assign(new Error('Invalid custom port "{v}" (use e.g. 8080/tcp)'), { params: { v: part } });
    custom.push({ port: +m[1], proto: (m[2] || 'tcp').toLowerCase() });
  }
  const src = $('fw-ssh-src').value.trim();
  if (src) {
    const [a, p = '32'] = src.split('/');
    try { parseIPv4(a); } catch { throw new Error('Invalid SSH source CIDR'); }
    if (!/^\d{1,2}$/.test(p) || +p > 32) throw new Error('Invalid SSH source CIDR');
  }
  return { services, custom, sshSource: src, icmp: $('fw-icmp').checked };
}
function renderFw() {
  $('fw-error').textContent = '';
  try {
    $('fw-output').textContent = { iptables: toIptables, nftables: toNftables, ufw: toUfw }[fwFormat](fwOptions());
  } catch (err) {
    $('fw-error').textContent = errText(err);
  }
}
$('fw-form').addEventListener('input', renderFw);
$('fw-tabs').addEventListener('click', (e) => {
  const fmt = e.target.closest('[data-fmt]')?.dataset.fmt;
  if (!fmt) return;
  fwFormat = fmt;
  $('fw-tabs').querySelectorAll('button').forEach((b) => b.setAttribute('aria-selected', b.dataset.fmt === fmt));
  renderFw();
});
$('fw-download').addEventListener('click', () => download(fwFormat === 'nftables' ? 'rules.nft' : `firewall-${fwFormat}.sh`, $('fw-output').textContent));
rerenders.push(() => { renderFwServices(); renderFw(); });

// ---------- 5. Hardening ----------
function renderHdChecks() {
  const unchecked = new Set([...$('hd-checks').querySelectorAll('input:not(:checked)')].map((i) => i.value));
  $('hd-checks').innerHTML = CHECKS.map((c) => `<label><input type="checkbox" value="${c.id}" ${unchecked.has(c.id) ? '' : 'checked'} /> ${esc(t(c.name))}</label>`).join('');
}
function renderHd() {
  const ids = [...$('hd-checks').querySelectorAll('input:checked')].map((i) => i.value);
  try { $('hd-output').textContent = buildAuditScript(ids); } catch (err) { $('hd-output').textContent = `# ${errText(err)}`; }
}
$('hd-checks').addEventListener('change', renderHd);
$('hd-download').addEventListener('click', () => download('audit.sh', $('hd-output').textContent));
rerenders.push(() => { renderHdChecks(); renderHd(); });

// ---------- 6. Logs ----------
const SAMPLE_LOG = [
  ...Array.from({ length: 8 }, (_, i) => `Nov 17 03:1${i}:0${i} srv sshd[20${i}]: Failed password for root from 203.0.113.45 port 4${i}112 ssh2`),
  ...['admin', 'oracle', 'test', 'ubuntu', 'pi'].map((u, i) => `Nov 17 03:2${i}:11 srv sshd[30${i}]: Failed password for invalid user ${u} from 198.51.100.7 port 5${i}201 ssh2`),
  'Nov 17 03:30:42 srv sshd[401]: message repeated 4 times: [ Failed password for admin from 198.51.100.7 port 51111 ssh2]',
  'Nov 17 08:02:13 srv sshd[502]: Accepted publickey for jheremy from 192.168.1.20 port 50022 ssh2',
  'Nov 17 08:45:01 srv sshd[503]: Failed password for jheremy from 192.168.1.20 port 50100 ssh2',
  'Nov 17 09:12:55 srv sshd[504]: Accepted password for root from 203.0.113.45 port 41999 ssh2',
].join('\n');
let logsShown = false;
$('log-sample').addEventListener('click', () => { $('log-input').value = SAMPLE_LOG; logsShown = true; runLogs(); });
$('log-file').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $('log-input').value = await f.text();
  logsShown = true;
  runLogs();
});
$('log-run').addEventListener('click', () => { logsShown = true; runLogs(); });
function runLogs() {
  if (!logsShown) return;
  const text = $('log-input').value;
  if (!text.trim()) { $('log-result').innerHTML = `<p class="error">${esc(t('Paste or open a log first.'))}</p>`; return; }
  const r = analyzeAuthLog(text, Math.max(1, Number($('log-threshold').value) || 5));
  const stat = (n, label) => `<div class="stat"><b>${fmtNum(n)}</b><span>${esc(t(label))}</span></div>`;
  const th = (k) => `<th>${esc(t(k))}</th>`;
  $('log-result').innerHTML = `
    ${r.suspicious.map((s) => `<div class="alert">${t('log.compromise', { m: esc(s.method), u: esc(s.user), ip: esc(s.ip), n: s.priorFails })}</div>`).join('')}
    <div class="stats">${stat(r.lines, 'lines read')}${stat(r.failed, 'failed logins')}${stat(r.successful, 'successful logins')}${stat(r.uniqueIps, 'unique IPs')}${stat(r.attackers.length, 'brute-force IPs')}</div>
    ${r.ipList.length ? `<h3>${esc(t('Source IPs'))}</h3><div class="table-wrap"><table><tr><th>IP</th>${th('Failed')}${th('Successful')}${th('Usernames tried')}<th></th></tr>
      ${r.ipList.slice(0, 50).map((e) => `<tr><td class="mono">${esc(e.ip)}</td><td>${e.fail}</td><td>${e.ok}</td><td>${esc(e.users.slice(0, 6).join(', '))}${e.users.length > 6 ? '…' : ''}</td><td>${r.attackers.some((a) => a.ip === e.ip) ? badge('fail', t('brute force')) : ''}</td></tr>`).join('')}
      </table></div>` : `<p class="hint">${esc(t('No SSH login events found in this log.'))}</p>`}
    ${r.topUsers.length ? `<h3>${esc(t('Most targeted usernames'))}</h3><div class="table-wrap"><table><tr>${th('Username')}${th('Failed attempts')}</tr>${r.topUsers.map(([u, n]) => `<tr><td class="mono">${esc(u)}</td><td>${n}</td></tr>`).join('')}</table></div>` : ''}
    ${r.attackers.length ? `<h3>${esc(t('Block brute-force IPs'))}</h3><div class="code-wrap"><pre id="log-block">${esc(blockCommands(r.attackers.map((a) => a.ip)))}</pre><div class="code-actions"><button class="ghost" data-copy="log-block">${esc(t('Copy'))}</button></div></div>
      <p class="hint">${t('logs.fail2ban')}</p>` : ''}`;
}
rerenders.push(runLogs);

// ---------- 7. Monitor ----------
let monResults = null;
function monUrls() {
  return $('mon-urls').value.split('\n').map((l) => l.trim()).filter(Boolean).map((u) => {
    try { return normalizeUrl(u); } catch { throw Object.assign(new Error('Invalid URL: {v}'), { params: { v: u } }); }
  });
}
$('mon-run').addEventListener('click', async () => {
  $('mon-error').textContent = '';
  let urls;
  try { urls = monUrls(); } catch (err) { $('mon-error').textContent = errText(err); return; }
  monResults = 'checking';
  renderMonResults();
  monResults = await Promise.all(urls.map((u) => checkUrl(u)));
  renderMonResults();
});
function renderMonResults() {
  if (!monResults) return;
  if (monResults === 'checking') { $('mon-result').innerHTML = `<p class="hint">${esc(t('Checking…'))}</p>`; return; }
  $('mon-result').innerHTML = `<div class="table-wrap"><table><tr><th>${esc(t('Status'))}</th><th>URL</th><th>${esc(t('Response time'))}</th></tr>
    ${monResults.map((r) => `<tr><td>${r.up ? badge('pass', t('up')) : badge('fail', t('down'))}</td><td class="mono">${esc(r.url)}</td><td>${r.up ? `${r.ms} ms` : esc(t(r.error))}</td></tr>`).join('')}
    </table></div>`;
}
function renderMon() {
  const ch = $('mon-channel').value;
  $('mon-discord-wrap').hidden = ch !== 'discord';
  $('mon-tg-token-wrap').hidden = ch !== 'telegram';
  $('mon-tg-chat-wrap').hidden = ch !== 'telegram';
  $('mon-error').textContent = '';
  try {
    $('mon-output').textContent = buildMonitorScript({
      urls: monUrls(), channel: ch,
      discordWebhook: $('mon-discord').value.trim(), telegramToken: $('mon-tg-token').value.trim(), telegramChat: $('mon-tg-chat').value.trim(),
    });
  } catch (err) {
    $('mon-error').textContent = errText(err);
  }
}
['mon-urls', 'mon-channel', 'mon-discord', 'mon-tg-token', 'mon-tg-chat'].forEach((id) => $(id).addEventListener('input', renderMon));
$('mon-download').addEventListener('click', () => download('monitor.sh', $('mon-output').textContent));
rerenders.push(() => { renderMonResults(); renderMon(); });

// ---------- Boot ----------
const browserLang = (navigator.language || 'en').slice(0, 2);
applyLang(store.get('netsec-lang') || (LANGS[browserLang] ? browserLang : 'en'));
route();
