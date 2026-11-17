<div align="center">

# 🛡️ NetSec Toolkit

**Seven practical networking and defensive-security tools that run entirely in your browser.**

[![Live demo](https://img.shields.io/badge/Live%20demo-5865F2?style=for-the-badge&logo=githubpages&logoColor=white)](https://jheremysebastian17.github.io/netsec-toolkit/)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)

</div>

## Tools

| Tool | What it does |
|------|--------------|
| **Subnet Calculator** | IPv4 & IPv6: network, broadcast, host range, masks, scope, and subnet splitting. |
| **Firewall Rule Generator** | Default-deny inbound rules for **iptables**, **nftables** and **UFW**, with source-restricted SSH. |
| **Security Headers Analyzer** | Grades HTTP response headers (HSTS, CSP, X-Frame-Options, cookies, version leaks) and suggests fixes. |
| **Password Strength Checker** | Entropy and offline crack-time estimate, plus a breach check via Have I Been Pwned using k-anonymity. |
| **Linux Hardening Audit** | Generates a read-only Bash audit (SSH config, UID 0, empty passwords, SUID, firewall, updates) with an optional HTML report. |
| **Auth Log Analyzer** | Parses `auth.log` / `secure`, ranks brute-force IPs, flags successful logins after attacks, and outputs block rules. |
| **Uptime Monitor** | Checks services from the browser and generates a cron script that alerts on Discord or Telegram when state changes. |

## Features

- **5 languages:** Español, English, Català, Français, Deutsch — remembers your choice and follows the browser language on first visit.
- **Light / dark theme** toggle, defaulting to the system preference.
- **Responsive** layout for phones, tablets and desktops (sidebar collapses into a scrolling tab bar; wide tables turn into cards).

## Privacy by design

- No backend, no analytics, no storage: everything runs client-side.
- Log files are read with the File API and never uploaded.
- The breach check sends only the first 5 characters of the password's SHA-1 hash.

## Run locally

No build step. Serve the folder with any static server:

```bash
npx serve .
# or
python -m http.server 8000
```

## Tests

Core logic (subnetting, header audit, password scoring, rule/script generation, log parsing) is covered by dependency-free tests:

```bash
node tests/run.mjs
```

## Project structure

```
index.html        UI and layout
css/style.css     Theme (light/dark), responsive layout
js/app.js         DOM wiring, routing, theme and language switching
js/i18n.js        Translations (ES, EN, CA, FR, DE)
js/*.js           One pure module per tool
tests/run.mjs     Unit tests (Node.js)
```

## License

MIT © Jheremy Sánchez
