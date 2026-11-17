// SSH auth.log analyser. Pure functions, no DOM; the log never leaves the browser.

const RE_FAIL = /Failed (?:password|publickey|keyboard-interactive\/pam) for (invalid user )?(\S+) from ([0-9a-fA-F.:]+)/;
const RE_OK = /Accepted (\S+) for (\S+) from ([0-9a-fA-F.:]+)/;
const RE_REPEAT = /message repeated (\d+) times/;

export function analyzeAuthLog(text, threshold = 5) {
  const ips = new Map();
  const users = new Map();
  const logins = [];
  let failed = 0, lines = 0;
  const ipEntry = (ip) => {
    if (!ips.has(ip)) ips.set(ip, { ip, fail: 0, ok: 0, invalidUsers: 0, users: new Set() });
    return ips.get(ip);
  };

  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim()) continue;
    lines++;
    let m;
    // shortcut: "Invalid user X" lines without a matching "Failed ..." line are not counted.
    if ((m = RE_FAIL.exec(line))) {
      const n = Number(RE_REPEAT.exec(line)?.[1] || 1);
      const e = ipEntry(m[3]);
      e.fail += n;
      if (m[1]) e.invalidUsers += n;
      e.users.add(m[2]);
      users.set(m[2], (users.get(m[2]) || 0) + n);
      failed += n;
    } else if ((m = RE_OK.exec(line))) {
      const e = ipEntry(m[3]);
      e.ok++;
      logins.push({ user: m[2], ip: m[3], method: m[1], priorFails: e.fail });
    }
  }

  const ipList = [...ips.values()]
    .map((e) => ({ ...e, users: [...e.users] }))
    .sort((a, b) => b.fail - a.fail);
  const attackers = ipList.filter((e) => e.fail >= threshold);
  return {
    lines,
    failed,
    successful: logins.length,
    uniqueIps: ipList.length,
    ipList,
    attackers,
    topUsers: [...users.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10),
    // A success from an IP that was brute-forcing first is the most important finding.
    suspicious: logins.filter((l) => l.priorFails >= threshold),
    logins,
  };
}

export function blockCommands(ips) {
  return ips
    .map((ip) => (ip.includes(':') ? `ip6tables -A INPUT -s ${ip} -j DROP` : `iptables -A INPUT -s ${ip} -j DROP`))
    .join('\n');
}
