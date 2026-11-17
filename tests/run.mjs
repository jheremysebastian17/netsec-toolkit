// Run with: node tests/run.mjs
import assert from 'node:assert/strict';
import { parseInput, calcIPv4, splitIPv4, parseIPv4, parsePrefix4, parseIPv6, formatIPv6, calcIPv6 } from '../js/subnet.js';
import { parseHeaders, auditHeaders, gradeOf } from '../js/headers.js';
import { analyzePassword, formatDuration, sha1Hex } from '../js/password.js';
import { toIptables, toNftables, toUfw } from '../js/firewall.js';
import { buildAuditScript, CHECKS } from '../js/hardening.js';
import { analyzeAuthLog, blockCommands } from '../js/logs.js';
import { normalizeUrl, buildMonitorScript } from '../js/monitor.js';

let passed = 0;
const test = (name, fn) => { fn(); passed++; console.log(`ok - ${name}`); };

test('IPv4 /24', () => {
  const { ip, prefix } = parseInput('192.168.1.10/24');
  const r = calcIPv4(ip, prefix);
  assert.equal(r.network, '192.168.1.0');
  assert.equal(r.broadcast, '192.168.1.255');
  assert.equal(r.firstHost, '192.168.1.1');
  assert.equal(r.lastHost, '192.168.1.254');
  assert.equal(r.usableHosts, 254);
  assert.equal(r.mask, '255.255.255.0');
  assert.equal(r.wildcard, '0.0.0.255');
  assert.equal(r.scope, 'Private (RFC 1918)');
});

test('IPv4 dotted mask, /31, /32, /0', () => {
  assert.equal(parseInput('10.0.0.5 255.255.252.0').prefix, 22);
  assert.equal(calcIPv4(parseIPv4('10.0.0.5'), 22).cidr, '10.0.0.0/22');
  assert.equal(calcIPv4(parseIPv4('10.0.0.1'), 31).usableHosts, 2);
  assert.equal(calcIPv4(parseIPv4('10.0.0.1'), 32).usableHosts, 1);
  assert.equal(parsePrefix4('0.0.0.0'), 0);
  assert.equal(calcIPv4(parseIPv4('8.8.8.8'), 0).broadcast, '255.255.255.255');
  assert.equal(calcIPv4(parseIPv4('8.8.8.8'), 32).scope, 'Public');
});

test('IPv4 invalid input rejected', () => {
  assert.throws(() => parseIPv4('256.1.1.1'));
  assert.throws(() => parseIPv4('1.2.3'));
  assert.throws(() => parsePrefix4('255.0.255.0'));
  assert.throws(() => parsePrefix4('33'));
});

test('IPv4 split', () => {
  const { count, rows } = splitIPv4(parseIPv4('192.168.1.0'), 24, 26);
  assert.equal(count, 4);
  assert.deepEqual(rows.map((r) => r.cidr), ['192.168.1.0/26', '192.168.1.64/26', '192.168.1.128/26', '192.168.1.192/26']);
  assert.equal(rows[1].last, '192.168.1.126');
  assert.throws(() => splitIPv4(parseIPv4('192.168.1.0'), 24, 24));
});

test('IPv6 parse/format/calc', () => {
  assert.equal(formatIPv6(parseIPv6('2001:0db8:0000:0000:0000:0000:0000:0001')), '2001:db8::1');
  assert.equal(formatIPv6(parseIPv6('::')), '::');
  assert.equal(formatIPv6(parseIPv6('fe80::1:0:0:1')), 'fe80::1:0:0:1');
  const r = calcIPv6(parseIPv6('2001:db8:abcd:12::99'), 64);
  assert.equal(r.cidr, '2001:db8:abcd:12::/64');
  assert.equal(r.lastAddress, '2001:db8:abcd:12:ffff:ffff:ffff:ffff');
  assert.equal(r.totalAddresses, '2^64');
  assert.equal(r.scope, 'Global unicast');
  assert.equal(calcIPv6(parseIPv6('fd00::1'), 120).totalAddresses, '256');
  assert.throws(() => parseIPv6('1::2::3'));
  assert.throws(() => parseIPv6('12345::'));
});

test('Security headers', () => {
  const bad = auditHeaders(parseHeaders('HTTP/2 200\nserver: nginx/1.18.0\nx-powered-by: PHP/7.4\nset-cookie: s=1; HttpOnly'));
  assert.ok(bad.some((r) => r.name === 'Content-Security-Policy' && r.status === 'fail'));
  assert.ok(bad.some((r) => r.name === 'Server' && r.status === 'warn'));
  assert.equal(gradeOf(bad).letter, 'F');
  const good = auditHeaders(parseHeaders(`strict-transport-security: max-age=63072000; includeSubDomains
content-security-policy: default-src 'self'; frame-ancestors 'none'
x-content-type-options: nosniff
referrer-policy: no-referrer
permissions-policy: camera=()`));
  assert.ok(good.every((r) => r.status === 'pass'));
  assert.equal(gradeOf(good).letter, 'A');
});

test('Password strength', () => {
  assert.equal(analyzePassword(''), null);
  assert.equal(analyzePassword('password123').label, 'Very weak');
  assert.ok(analyzePassword('aaaa').issues.length >= 2);
  assert.equal(analyzePassword('t7#Kq!v2Lp@9wZx$Rm4e').label, 'Very strong');
  assert.equal(formatDuration(0.2), 'instantly');
  assert.equal(formatDuration(90), '1 minute');
  assert.equal(formatDuration(Infinity), 'billions of years');
});

test('SHA-1 for breach lookup', async () => {
  assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('Firewall rules', () => {
  const o = { services: ['ssh', 'dns'], custom: [{ port: 8080, proto: 'tcp' }], sshSource: '10.0.0.0/8', icmp: false };
  const ipt = toIptables(o);
  assert.match(ipt, /--dport 22 -s 10\.0\.0\.0\/8/);
  assert.match(ipt, /-p udp --dport 53/);
  assert.ok(ipt.indexOf('--dport 22') < ipt.indexOf('-P INPUT DROP'), 'policy must be set after allow rules');
  assert.doesNotMatch(ipt, /icmp-type echo-request/);
  assert.match(toNftables(o), /ip saddr 10\.0\.0\.0\/8 tcp dport 22 accept/);
  assert.match(toUfw(o), /ufw allow from 10\.0\.0\.0\/8 to any port 22 proto tcp/);
  assert.match(toUfw(o), /ufw allow 8080\/tcp/);
});

test('Hardening script', () => {
  const s = buildAuditScript(CHECKS.map((c) => c.id));
  for (const c of CHECKS) assert.match(s, new RegExp(`^c_${c.id}$`, 'm'));
  assert.ok(s.startsWith('#!/usr/bin/env bash'));
  assert.throws(() => buildAuditScript([]));
});

test('Auth log analysis', () => {
  const log = [
    ...Array(6).fill('Nov 17 03:10:00 srv sshd[1]: Failed password for root from 203.0.113.45 port 1 ssh2'),
    'Nov 17 03:11:00 srv sshd[1]: Failed password for invalid user admin from 198.51.100.7 port 2 ssh2',
    'Nov 17 03:12:00 srv sshd[1]: message repeated 4 times: [ Failed password for admin from 198.51.100.7 port 2 ssh2]',
    'Nov 17 08:00:00 srv sshd[1]: Accepted publickey for jheremy from 192.168.1.20 port 3 ssh2',
    'Nov 17 09:00:00 srv sshd[1]: Accepted password for root from 203.0.113.45 port 4 ssh2',
    'Nov 17 09:01:00 srv CRON[2]: pam_unix(cron:session): session opened for user root',
  ].join('\n');
  const r = analyzeAuthLog(log, 5);
  assert.equal(r.failed, 11);
  assert.equal(r.successful, 2);
  assert.deepEqual(r.attackers.map((a) => a.ip), ['203.0.113.45', '198.51.100.7']);
  assert.equal(r.suspicious.length, 1);
  assert.equal(r.suspicious[0].ip, '203.0.113.45');
  assert.equal(r.topUsers[0][0], 'root');
  assert.equal(blockCommands(['1.2.3.4', '2001:db8::1']), 'iptables -A INPUT -s 1.2.3.4 -j DROP\nip6tables -A INPUT -s 2001:db8::1 -j DROP');
});

test('Monitor script', () => {
  assert.equal(normalizeUrl('example.com'), 'https://example.com/');
  assert.throws(() => normalizeUrl('ftp://x'));
  assert.equal(normalizeUrl('  '), null);
  const s = buildMonitorScript({ urls: ["https://a.com/it's"], channel: 'discord', discordWebhook: 'https://discord.com/api/webhooks/1/x' });
  assert.match(s, /'https:\/\/a\.com\/it'\\''s'/, 'single quotes must be shell-escaped');
  assert.match(s, /DISCORD_WEBHOOK='https:\/\/discord\.com\/api\/webhooks\/1\/x'/);
  assert.throws(() => buildMonitorScript({ urls: [] }));
});

console.log(`\n${passed} tests passed`);
