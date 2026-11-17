// IPv4 / IPv6 subnet math. Pure functions, no DOM.

export function parseIPv4(s) {
  const parts = String(s).trim().split('.');
  if (parts.length !== 4) throw new Error('Invalid IPv4 address');
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || +p > 255) throw new Error('Invalid IPv4 address');
    n = n * 256 + +p;
  }
  return n;
}

export const formatIPv4 = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');

const maskFromPrefix = (p) => (p === 0 ? 0 : (0xffffffff << (32 - p)) >>> 0);

// Accepts "24" or "255.255.255.0".
export function parsePrefix4(s) {
  s = String(s).trim();
  if (/^\d{1,2}$/.test(s)) {
    if (+s > 32) throw new Error('Prefix must be 0-32');
    return +s;
  }
  const inv = ~parseIPv4(s) >>> 0;
  if ((inv & (inv + 1)) !== 0) throw new Error('Subnet mask is not contiguous');
  return 32 - Math.log2(inv + 1);
}

export function classOf(ip) {
  const a = ip >>> 24;
  if (a < 128) return 'A';
  if (a < 192) return 'B';
  if (a < 224) return 'C';
  if (a < 240) return 'D (multicast)';
  return 'E (reserved)';
}

const RANGES = [
  ['10.0.0.0', 8, 'Private (RFC 1918)'],
  ['172.16.0.0', 12, 'Private (RFC 1918)'],
  ['192.168.0.0', 16, 'Private (RFC 1918)'],
  ['100.64.0.0', 10, 'Carrier-grade NAT (RFC 6598)'],
  ['127.0.0.0', 8, 'Loopback'],
  ['169.254.0.0', 16, 'Link-local (APIPA)'],
  ['224.0.0.0', 4, 'Multicast'],
];

export function scopeOf(ip) {
  for (const [net, p, label] of RANGES) {
    const m = maskFromPrefix(p);
    if (((ip & m) >>> 0) === parseIPv4(net)) return label;
  }
  return 'Public';
}

export function calcIPv4(ip, prefix) {
  const mask = maskFromPrefix(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const total = 2 ** (32 - prefix);
  // /31 point-to-point links (RFC 3021) and /32 host routes have no network/broadcast reservation.
  const usable = prefix === 32 ? 1 : prefix === 31 ? 2 : total - 2;
  const first = prefix >= 31 ? network : network + 1;
  const last = prefix >= 31 ? broadcast : broadcast - 1;
  return {
    address: formatIPv4(ip),
    cidr: `${formatIPv4(network)}/${prefix}`,
    network: formatIPv4(network),
    broadcast: prefix >= 31 ? '—' : formatIPv4(broadcast),
    mask: formatIPv4(mask),
    wildcard: formatIPv4(~mask >>> 0),
    firstHost: formatIPv4(first),
    lastHost: formatIPv4(last),
    totalAddresses: total,
    usableHosts: usable,
    ipClass: classOf(ip),
    scope: scopeOf(ip),
    binaryMask: [24, 16, 8, 0].map((s) => ((mask >>> s) & 255).toString(2).padStart(8, '0')).join('.'),
  };
}

export function splitIPv4(ip, prefix, newPrefix, limit = 256) {
  if (newPrefix <= prefix || newPrefix > 32) throw new Error(`New prefix must be between /${prefix + 1} and /32`);
  const network = (ip & maskFromPrefix(prefix)) >>> 0;
  const size = 2 ** (32 - newPrefix);
  const count = 2 ** (newPrefix - prefix);
  const rows = [];
  for (let i = 0; i < Math.min(count, limit); i++) {
    const r = calcIPv4(network + i * size, newPrefix);
    rows.push({ cidr: r.cidr, first: r.firstHost, last: r.lastHost, broadcast: r.broadcast, hosts: r.usableHosts });
  }
  return { count, rows };
}

// ---------- IPv6 (BigInt) ----------

const ALL128 = (1n << 128n) - 1n;

export function parseIPv6(s) {
  s = String(s).trim().toLowerCase();
  const halves = s.split('::');
  if (halves.length > 2) throw new Error('Invalid IPv6 address');
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) throw new Error('Invalid IPv6 address');
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) throw new Error('Invalid IPv6 address');
    n = (n << 16n) | BigInt('0x' + g);
  }
  return n;
}

export function formatIPv6(n) {
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  // Compress the longest run (>= 2) of zero groups, per RFC 5952.
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] !== '0') { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === '0') j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return g.join(':');
  return `${g.slice(0, best).join(':')}::${g.slice(best + bestLen).join(':')}`;
}

export function expandIPv6(n) {
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn).toString(16).padStart(4, '0'));
  return g.join(':');
}

function scope6(n) {
  const top = n >> 112n;
  if (n === 1n) return 'Loopback';
  if ((top & 0xffc0n) === 0xfe80n) return 'Link-local';
  if ((top & 0xfe00n) === 0xfc00n) return 'Unique local (private)';
  if ((top & 0xff00n) === 0xff00n) return 'Multicast';
  if ((top & 0xe000n) === 0x2000n) return 'Global unicast';
  return 'Other / reserved';
}

export function calcIPv6(ip, prefix) {
  if (prefix < 0 || prefix > 128) throw new Error('Prefix must be 0-128');
  const hostBits = BigInt(128 - prefix);
  const mask = ALL128 ^ ((1n << hostBits) - 1n);
  const network = ip & mask;
  const last = network | (ALL128 ^ mask);
  return {
    address: formatIPv6(ip),
    expanded: expandIPv6(ip),
    cidr: `${formatIPv6(network)}/${prefix}`,
    network: formatIPv6(network),
    firstAddress: formatIPv6(network),
    lastAddress: formatIPv6(last),
    totalAddresses: hostBits > 52n ? `2^${hostBits}` : (1n << hostBits).toLocaleString('en-US'),
    scope: scope6(ip),
  };
}

// Parses "10.0.0.1/24", "10.0.0.1 255.255.255.0" or "2001:db8::1/64".
export function parseInput(text) {
  const [addr, pfx] = String(text).trim().split(/[\s/]+/);
  if (!addr) throw new Error('Enter an address, e.g. 192.168.1.10/24');
  if (addr.includes(':')) {
    const p = pfx === undefined ? 64 : Number(pfx);
    if (!Number.isInteger(p)) throw new Error('Invalid IPv6 prefix');
    return { version: 6, ip: parseIPv6(addr), prefix: p };
  }
  return { version: 4, ip: parseIPv4(addr), prefix: pfx === undefined ? 24 : parsePrefix4(pfx) };
}
