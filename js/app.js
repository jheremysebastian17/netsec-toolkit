import { parseInput, calcIPv4, calcIPv6, splitIPv4, parseIPv4 } from './subnet.js';
import { parseHeaders, auditHeaders, gradeOf } from './headers.js';
import { analyzePassword, formatDuration, pwnedCount } from './password.js';
import { SERVICES, toIptables, toNftables, toUfw } from './firewall.js';
import { CHECKS, buildAuditScript } from './hardening.js';
import { analyzeAuthLog, blockCommands } from './logs.js';
import { normalizeUrl, checkUrl, buildMonitorScript } from './monitor.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const badge = (s) => `<span class="badge ${s}">${s}</span>`;
const kv = (pairs) => `<dl class="kv">${pairs.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>`;

function download(name, text) {
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
}

document.addEventListener('click', async (e) => {
  const id = e.target.dataset?.copy;
  if (!id) return;
  await navigator.clipboard.writeText($(id).textContent);
  const old = e.target.textContent;
  e.target.textContent = 'Copied';
  setTimeout(() => (e.target.textContent = old), 1200);
});

// ---------- Routing ----------
function route() {
  const id = location.hash.slice(1) || 'home';
  const target = document.getElementById(id)?.classList.contains('tool') ? id : 'home';
  document.querySelectorAll('.tool').forEach((s) => (s.hidden = s.id !== target));
  document.querySelectorAll('nav a').forEach((a) => (a.hash === `#${target}` ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current')));
  window.scrollTo(0, 0);
}
addEventListener('hashchange', route);
route();

// ---------- 1. Subnet ----------
let lastV4 = null;
function runSubnet() {
  $('subnet-error').textContent = '';
  $('split-result').innerHTML = '';
  try {
    const { version, ip, prefix } = parseInput($('subnet-input').value);
    if (version === 4) {
      const r = calcIPv4(ip, prefix);
      lastV4 = { ip, prefix };
      $('subnet-result').innerHTML = kv([
        ['Network', r.cidr], ['Subnet mask', r.mask], ['Wildcard mask', r.wildcard], ['Broadcast', r.broadcast],
        ['First host', r.firstHost], ['Last host', r.lastHost], ['Usable hosts', r.usableHosts.toLocaleString('en-US')],
        ['Total addresses', r.totalAddresses.toLocaleString('en-US')], ['Class', r.ipClass], ['Scope', r.scope], ['Binary mask', r.binaryMask],
      ]);
      $('split-form').hidden = prefix >= 32;
      $('split-prefix').min = prefix + 1;
      $('split-prefix').value = Math.min(32, Math.max(prefix + 1, +$('split-prefix').value));
    } else {
      const r = calcIPv6(ip, prefix);
      lastV4 = null;
      $('split-form').hidden = true;
      $('subnet-result').innerHTML = kv([
        ['Network', r.cidr], ['First address', r.firstAddress], ['Last address', r.lastAddress],
        ['Total addresses', r.totalAddresses], ['Scope', r.scope], ['Expanded', r.expanded],
      ]);
    }
  } catch (err) {
    $('subnet-result').innerHTML = '';
    $('split-form').hidden = true;
    $('subnet-error').textContent = err.message;
  }
}
$('subnet-form').addEventListener('submit', (e) => { e.preventDefault(); runSubnet(); });
$('split-form').addEventListener('submit', (e) => {
  e.preventDefault();
  if (!lastV4) return;
  try {
    const { count, rows } = splitIPv4(lastV4.ip, lastV4.prefix, Number($('split-prefix').value));
    $('split-result').innerHTML = `<p class="hint">${count.toLocaleString('en-US')} subnets${count > rows.length ? ` (showing first ${rows.length})` : ''}</p>
      <div class="table-wrap"><table><tr><th>#</th><th>Subnet</th><th>First host</th><th>Last host</th><th>Broadcast</th><th>Hosts</th></tr>
      ${rows.map((r, i) => `<tr><td>${i + 1}</td><td class="mono">${r.cidr}</td><td class="mono">${r.first}</td><td class="mono">${r.last}</td><td class="mono">${r.broadcast}</td><td>${r.hosts.toLocaleString('en-US')}</td></tr>`).join('')}
      </table></div>`;
  } catch (err) {
    $('subnet-error').textContent = err.message;
  }
});
runSubnet();

// ---------- 2. Headers ----------
const SAMPLE_HEADERS = `HTTP/2 200
server: nginx/1.18.0 (Ubuntu)
content-type: text/html; charset=UTF-8
x-powered-by: PHP/7.4.3
strict-transport-security: max-age=3600
x-content-type-options: nosniff
set-cookie: session=abc123; Path=/; HttpOnly`;
$('headers-sample').addEventListener('click', () => { $('headers-input').value = SAMPLE_HEADERS; runHeaders(); });
$('headers-run').addEventListener('click', runHeaders);
function runHeaders() {
  const raw = $('headers-input').value.trim();
  if (!raw) { $('headers-result').innerHTML = '<p class="error">Paste some headers first.</p>'; return; }
  const results = auditHeaders(parseHeaders(raw));
  const { score, letter } = gradeOf(results);
  const cls = letter === 'A' ? 'pass' : letter <= 'C' ? 'warn' : 'fail';
  $('headers-result').innerHTML = `
    <div class="grade"><div class="grade-letter ${cls}">${letter}</div><div><b>Score ${score}/100</b><br><span class="hint">${results.filter((r) => r.status !== 'pass').length} issue(s) found</span></div></div>
    <div class="table-wrap"><table><tr><th>Status</th><th>Header</th><th>Finding</th><th>Recommended fix</th></tr>
    ${results.map((r) => `<tr><td>${badge(r.status)}</td><td><b>${esc(r.name)}</b></td><td>${esc(r.message)}</td><td class="mono">${esc(r.fix)}</td></tr>`).join('')}
    </table></div>`;
}

// ---------- 3. Password ----------
const COLORS = { 'Very weak': 'var(--fail)', Weak: 'var(--fail)', Fair: 'var(--warn)', Strong: 'var(--pass)', 'Very strong': 'var(--pass)' };
$('pw-toggle').addEventListener('click', () => {
  const show = $('pw-input').type === 'password';
  $('pw-input').type = show ? 'text' : 'password';
  $('pw-toggle').textContent = show ? 'Hide' : 'Show';
});
$('pw-input').addEventListener('input', () => {
  $('pw-pwned-result').textContent = '';
  const r = analyzePassword($('pw-input').value);
  if (!r) { $('pw-result').innerHTML = ''; $('pw-bar').style.width = '0'; return; }
  $('pw-bar').style.width = `${Math.min(100, (r.bits / 100) * 100)}%`;
  $('pw-bar').style.background = COLORS[r.label];
  $('pw-result').innerHTML = `<p><b style="color:${COLORS[r.label]}">${r.label}</b> · ~${r.bits} bits of entropy · estimated offline crack time: <b>${formatDuration(r.seconds)}</b></p>
    ${r.issues.length ? `<ul class="issues">${r.issues.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>` : ''}`;
});
$('pw-pwned').addEventListener('click', async () => {
  const pw = $('pw-input').value;
  const out = $('pw-pwned-result');
  if (!pw) { out.textContent = 'Type a password first.'; return; }
  out.textContent = 'Checking…';
  try {
    const n = await pwnedCount(pw);
    out.innerHTML = n
      ? `<span class="fail"><b>Found in ${n.toLocaleString('en-US')} breaches.</b> Do not use this password.</span>`
      : '<span class="pass"><b>Not found</b> in known breaches.</span>';
  } catch (err) {
    out.textContent = `Could not reach the breach database: ${err.message}`;
  }
});

// ---------- 4. Firewall ----------
let fwFormat = 'iptables';
$('fw-services').innerHTML = SERVICES.map((s) => `<label><input type="checkbox" value="${s.id}" ${['ssh', 'http', 'https'].includes(s.id) ? 'checked' : ''}/> ${s.name} <span class="hint">(${s.ports.map((p) => p.join('/')).join(', ')})</span></label>`).join('');
function fwOptions() {
  const services = [...$('fw-services').querySelectorAll('input:checked')].map((i) => i.value);
  const custom = [];
  for (const part of $('fw-custom').value.split(/[,\s]+/).filter(Boolean)) {
    const m = /^(\d{1,5})(?:\/(tcp|udp))?$/i.exec(part);
    if (!m || +m[1] < 1 || +m[1] > 65535) throw new Error(`Invalid custom port "${part}" (use e.g. 8080/tcp)`);
    custom.push({ port: +m[1], proto: (m[2] || 'tcp').toLowerCase() });
  }
  const src = $('fw-ssh-src').value.trim();
  if (src) {
    const [a, p = '32'] = src.split('/');
    parseIPv4(a);
    if (!/^\d{1,2}$/.test(p) || +p > 32) throw new Error('Invalid SSH source CIDR');
  }
  return { services, custom, sshSource: src, icmp: $('fw-icmp').checked };
}
function renderFw() {
  $('fw-error').textContent = '';
  try {
    const o = fwOptions();
    $('fw-output').textContent = { iptables: toIptables, nftables: toNftables, ufw: toUfw }[fwFormat](o);
  } catch (err) {
    $('fw-error').textContent = err.message;
  }
}
$('fw-form').addEventListener('input', renderFw);
$('fw-tabs').addEventListener('click', (e) => {
  const fmt = e.target.dataset?.fmt;
  if (!fmt) return;
  fwFormat = fmt;
  $('fw-tabs').querySelectorAll('button').forEach((b) => b.setAttribute('aria-selected', b.dataset.fmt === fmt));
  renderFw();
});
$('fw-download').addEventListener('click', () => download(fwFormat === 'nftables' ? 'rules.nft' : `firewall-${fwFormat}.sh`, $('fw-output').textContent));
renderFw();

// ---------- 5. Hardening ----------
$('hd-checks').innerHTML = CHECKS.map((c) => `<label><input type="checkbox" value="${c.id}" checked /> ${c.name}</label>`).join('');
function renderHd() {
  const ids = [...$('hd-checks').querySelectorAll('input:checked')].map((i) => i.value);
  try { $('hd-output').textContent = buildAuditScript(ids); } catch (err) { $('hd-output').textContent = `# ${err.message}`; }
}
$('hd-checks').addEventListener('change', renderHd);
$('hd-download').addEventListener('click', () => download('audit.sh', $('hd-output').textContent));
renderHd();

// ---------- 6. Logs ----------
const SAMPLE_LOG = [
  ...Array.from({ length: 8 }, (_, i) => `Nov 17 03:1${i}:0${i} srv sshd[20${i}]: Failed password for root from 203.0.113.45 port 4${i}112 ssh2`),
  ...['admin', 'oracle', 'test', 'ubuntu', 'pi'].map((u, i) => `Nov 17 03:2${i}:11 srv sshd[30${i}]: Failed password for invalid user ${u} from 198.51.100.7 port 5${i}201 ssh2`),
  'Nov 17 03:30:42 srv sshd[401]: message repeated 4 times: [ Failed password for admin from 198.51.100.7 port 51111 ssh2]',
  'Nov 17 08:02:13 srv sshd[502]: Accepted publickey for jheremy from 192.168.1.20 port 50022 ssh2',
  'Nov 17 08:45:01 srv sshd[503]: Failed password for jheremy from 192.168.1.20 port 50100 ssh2',
  'Nov 17 09:12:55 srv sshd[504]: Accepted password for root from 203.0.113.45 port 41999 ssh2',
].join('\n');
$('log-sample').addEventListener('click', () => { $('log-input').value = SAMPLE_LOG; runLogs(); });
$('log-file').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  $('log-input').value = await f.text();
  runLogs();
});
$('log-run').addEventListener('click', runLogs);
function runLogs() {
  const text = $('log-input').value;
  if (!text.trim()) { $('log-result').innerHTML = '<p class="error">Paste or open a log first.</p>'; return; }
  const r = analyzeAuthLog(text, Math.max(1, Number($('log-threshold').value) || 5));
  const stat = (n, label) => `<div class="stat"><b>${n.toLocaleString('en-US')}</b><span>${label}</span></div>`;
  $('log-result').innerHTML = `
    ${r.suspicious.map((s) => `<div class="alert"><b>Possible compromise:</b> successful ${esc(s.method)} login as <b>${esc(s.user)}</b> from <code>${esc(s.ip)}</code> after ${s.priorFails} failed attempts. Investigate immediately.</div>`).join('')}
    <div class="stats">${stat(r.lines, 'lines read')}${stat(r.failed, 'failed logins')}${stat(r.successful, 'successful logins')}${stat(r.uniqueIps, 'unique IPs')}${stat(r.attackers.length, 'brute-force IPs')}</div>
    ${r.ipList.length ? `<h3>Source IPs</h3><div class="table-wrap"><table><tr><th>IP</th><th>Failed</th><th>Successful</th><th>Usernames tried</th><th></th></tr>
      ${r.ipList.slice(0, 50).map((e) => `<tr><td class="mono">${esc(e.ip)}</td><td>${e.fail}</td><td>${e.ok}</td><td>${esc(e.users.slice(0, 6).join(', '))}${e.users.length > 6 ? '…' : ''}</td><td>${r.attackers.some((a) => a.ip === e.ip) ? '<span class="badge fail">brute force</span>' : ''}</td></tr>`).join('')}
      </table></div>` : '<p class="hint">No SSH login events found in this log.</p>'}
    ${r.topUsers.length ? `<h3>Most targeted usernames</h3><div class="table-wrap"><table><tr><th>Username</th><th>Failed attempts</th></tr>${r.topUsers.map(([u, n]) => `<tr><td class="mono">${esc(u)}</td><td>${n}</td></tr>`).join('')}</table></div>` : ''}
    ${r.attackers.length ? `<h3>Block brute-force IPs</h3><div class="code-wrap"><pre id="log-block">${esc(blockCommands(r.attackers.map((a) => a.ip)))}</pre><div class="code-actions"><button class="ghost" data-copy="log-block">Copy</button></div></div>
      <p class="hint">For automatic, long-term protection install <code>fail2ban</code> with the <code>sshd</code> jail enabled.</p>` : ''}`;
}

// ---------- 7. Monitor ----------
function monUrls() {
  return $('mon-urls').value.split('\n').map((l) => l.trim()).filter(Boolean).map((u) => {
    try { return normalizeUrl(u); } catch { throw new Error(`Invalid URL: ${u}`); }
  });
}
$('mon-run').addEventListener('click', async () => {
  $('mon-error').textContent = '';
  let urls;
  try { urls = monUrls(); } catch (err) { $('mon-error').textContent = err.message; return; }
  $('mon-result').innerHTML = '<p class="hint">Checking…</p>';
  const results = await Promise.all(urls.map((u) => checkUrl(u)));
  $('mon-result').innerHTML = `<div class="table-wrap"><table><tr><th>Status</th><th>URL</th><th>Response time</th></tr>
    ${results.map((r) => `<tr><td>${r.up ? '<span class="badge pass">up</span>' : '<span class="badge fail">down</span>'}</td><td class="mono">${esc(r.url)}</td><td>${r.up ? `${r.ms} ms` : esc(r.error)}</td></tr>`).join('')}
    </table></div>`;
});
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
    $('mon-error').textContent = err.message;
  }
}
['mon-urls', 'mon-channel', 'mon-discord', 'mon-tg-token', 'mon-tg-chat'].forEach((id) => $(id).addEventListener('input', renderMon));
$('mon-download').addEventListener('click', () => download('monitor.sh', $('mon-output').textContent));
renderMon();
