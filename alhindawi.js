#!/usr/bin/env node
/**
 * ╔════════════════════════════════════════════════════════════════════════╗
 * ║                                                                        ║
 * ║   █████╗ ██╗     ██╗  ██╗██╗███╗   ██╗██████╗  █████╗ ██╗    ██╗██╗    ║
 * ║  ██╔══██╗██║     ██║  ██║██║████╗  ██║██╔══██╗██╔══██╗██║    ██║██║    ║
 * ║  ███████║██║     ███████║██║██╔██╗ ██║██║  ██║███████║██║ █╗ ██║██║    ║
 * ║  ██╔══██║██║     ██╔══██║██║██║╚██╗██║██║  ██║██╔══██║██║███╗██║██║    ║
 * ║  ██║  ██║███████╗██║  ██║██║██║ ╚████║██████╔╝██║  ██║╚███╔███╔╝██║    ║
 * ║  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝    ║
 * ║                                                                        ║
 * ║              A L H I N D A W I   H U N T E R   v10.0                   ║
 * ║                                                                        ║
 * ║         Nuclei + Bugcrowd VRT v1.19 + CVE Intel + FP Engine            ║
 * ║                                                                        ║
 * ║         by ALHINDAWI                                                   ║
 * ║                                                                        ║
 * ║  ⚠️  LEGAL: Scan hanya domain yang Anda punya izin tertulis.           ║
 * ║  ⚠️  Unauthorized scanning = pelanggaran hukum (CFAA, UU ITE, dll).    ║
 * ╚════════════════════════════════════════════════════════════════════════╝
 *
 * Usage:
 *   node alhindawi.js <targets.txt|domain> [out] [flags]
 *
 * Flags:
 *   --profile=stealth|normal|aggressive|ninja   (default: normal)
 *   --rate=5              req/s per-host
 *   --severity=critical,high
 *   --workers=3 --batch=40
 *
 *   --recon --ct --permute --crawler --tech
 *   --js-secrets --js-endpoints --source-maps
 *   --takeover --cors --graphql --jwt --dir-brute
 *   --openapi --http-methods --iis
 *   --ai-filter --dashboard
 *   --resume --dry-run 
 *
 *   --scope=allow.txt --deny=deny.txt
 *   --proxy=proxies.txt
 *   --auth-url= --auth-data= --auth-cookie= --auth-token=
 *
 *   --cve-feed=path/         Load CVE dari file Tenable / folder
 *   --cve-kev                Fetch CISA KEV feed
 *   --cve-fetch-nvd          Fetch live dari NVD API 2.0
 *   --cve-only               Hanya finding dengan CVE match
 *   --cve-kev-only           Hanya KEV (exploited-in-wild)
 *   --cve-min-cvss=7.0       Min CVSS
 *   --cve-override           KEV → force P1/P2 (default true)
 *
 *   --fp-strict              Anti-FP ketat (drop confidence < 70%)
 *   --fp-paranoid            Anti-FP paranoid (drop < 85% + retest)
 *   --verify-poc             Re-hit endpoint → konfirmasi finding masih ada
 *
 *   --sarif --junit --report-format=hackerone|bugcrowd|intigriti|generic
 *   --vrt=false              Disable Bugcrowd VRT
 *   --vrt-include-p5         Include P5 informational
 *
 * ENV:
 *   NUCLEI_PATH, SUBFINDER_PATH, HTTPX_PATH, GAU_PATH,
 *   NUCLEI_SKIP_UPDATE=1, RESUME=1, DRY_RUN=1, NVD_API_KEY,
 *   DISCORD_WEBHOOK, SLACK_WEBHOOK, TELEGRAM_BOT, TELEGRAM_CHAT
 *
 * by ALHINDAWI
 */
'use strict';

const { spawn, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const dns = require('dns').promises;

// ═══════════════════════════════════════════════════════════════════════════
//  VULN EXTENDED PACK — Inline (14 modules)
// ═══════════════════════════════════════════════════════════════════════════

// ═══ 1. SECURITY HEADERS CHECK ═══
async function securityHeadersCheck(targets) {
  log('HEADERS', `🔒 Security headers check`);
  const findings = [];
  const required = [
    { h: 'strict-transport-security', name: 'HSTS', sev: 'low', desc: 'Cookie bisa di-intercept via MITM' },
    { h: 'content-security-policy', name: 'CSP', sev: 'medium', desc: 'XSS lebih mudah dieksploit' },
    { h: 'x-frame-options', name: 'X-Frame-Options', sev: 'low', desc: 'Rentan clickjacking' },
    { h: 'x-content-type-options', name: 'X-Content-Type-Options', sev: 'low', desc: 'Rentan MIME sniffing' },
    { h: 'referrer-policy', name: 'Referrer-Policy', sev: 'low', desc: 'Token bisa leak via referer' },
    { h: 'permissions-policy', name: 'Permissions-Policy', sev: 'low', desc: 'Browser feature tidak dibatasi' }
  ];
  for (const t of targets.slice(0, 60)) {
    try {
      const r = await httpReq(t, { timeout: 8000 });
      if (r.status === 0) continue;
      const hdrs = Object.keys(r.headers).map(k => k.toLowerCase());
      for (const req of required) {
        if (!hdrs.includes(req.h)) {
          findings.push({
            'template-id': `missing-header-${req.h}`,
            'matched-at': t, host: t,
            info: { name: `Missing ${req.name} header`, severity: req.sev, tags: ['headers', 'misconfig'], description: req.desc },
            extracted_results: [`Missing: ${req.h}`]
          });
        }
      }
      const server = r.headers.server || '';
      if (/\d+\.\d+/.test(server)) {
        findings.push({
          'template-id': 'server-version-disclosure',
          'matched-at': t, host: t,
          info: { name: 'Server Version Disclosure', severity: 'low', tags: ['headers', 'info-disclosure'], description: `Server header bocorin versi: ${server}` },
          extracted_results: [server]
        });
      }
    } catch {}
    await sleep(80);
  }
  log('HEADERS', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 2. REFLECTED XSS ═══
async function xssReflectCheck(targets) {
  log('XSS', `🎯 Reflected XSS check`);
  const findings = [];
  const payloads = [
    { p: '<vX9pQ>test</vX9pQ>', sig: '<vX9pQ>' },
    { p: '"><xY7zW>', sig: '<xY7zW>' },
    { p: "'><qA3bC>", sig: '<qA3bC>' }
  ];
  const params = ['q', 's', 'search', 'query', 'id', 'name', 'ref', 'url', 'redirect', 'next', 'page', 'lang', 'view', 'msg', 'error', 'callback'];
  for (const t of targets.slice(0, 30)) {
    try {
      const u = new URL(t);
      for (const param of params) {
        for (const pl of payloads) {
          const testUrl = `${u.origin}${u.pathname}${u.search ? u.search + '&' : '?'}${param}=${encodeURIComponent(pl.p)}`;
          try {
            const r = await httpReq(testUrl, { timeout: 6000 });
            if (r.status !== 200) continue;
            const idx = r.body.indexOf(pl.sig);
            if (idx > 0) {
              const before = r.body.slice(Math.max(0, idx - 5), idx);
              if (!/&lt;|&gt;|&quot;|&#/.test(before)) {
                findings.push({
                  'template-id': 'xss-reflected',
                  'matched-at': testUrl, host: t,
                  info: { name: 'Reflected XSS', severity: 'medium', tags: ['xss', 'injection', 'reflected'], description: `Payload XSS terefleksi di parameter '${param}' tanpa encoding` },
                  extracted_results: [`Param: ${param}`, `Payload: ${pl.p}`],
                  response: r.body.slice(Math.max(0, idx - 100), idx + 200)
                });
                break;
              }
            }
          } catch {}
          await sleep(60);
        }
        if (findings.length) break;
      }
    } catch {}
  }
  log('XSS', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 3. OPEN REDIRECT ═══
async function openRedirectCheck(targets) {
  log('REDIR', `↪️  Open redirect check`);
  const findings = [];
  const payloads = ['https://evil.com', '//evil.com', '/\\evil.com', 'https:evil.com'];
  const params = ['redirect', 'url', 'next', 'return', 'return_url', 'returnUrl', 'goto', 'target', 'dest', 'destination', 'continue', 'callback', 'back', 'r', 'u', 'link', 'to', 'out', 'view'];
  for (const t of targets.slice(0, 30)) {
    try {
      const u = new URL(t);
      for (const param of params) {
        for (const p of payloads) {
          const testUrl = `${u.origin}${u.pathname}${u.search ? u.search + '&' : '?'}${param}=${encodeURIComponent(p)}`;
          try {
            const r = await httpReq(testUrl, { timeout: 6000 });
            const loc = r.headers['location'] || r.headers['Location'] || '';
            if (r.status >= 300 && r.status < 400 && (loc.includes('evil.com'))) {
              findings.push({
                'template-id': 'open-redirect',
                'matched-at': testUrl, host: t,
                info: { name: 'Open Redirect', severity: 'medium', tags: ['open-redirect', 'redirect'], description: `Parameter '${param}' vulnerable → ${loc}` },
                extracted_results: [`Param: ${param}`, `Location: ${loc}`]
              });
              break;
            }
          } catch {}
          await sleep(60);
        }
        if (findings.length) break;
      }
    } catch {}
  }
  log('REDIR', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 4. LFI / PATH TRAVERSAL ═══
async function lfiCheck(targets) {
  log('LFI', `📂 LFI / Path Traversal check`);
  const findings = [];
  const payloads = [
    { p: '../../../../etc/passwd', sig: /root:x:0:0|daemon:x:1:1|bin:x:2:2|nobody:x:/ },
    { p: '....//....//....//etc/passwd', sig: /root:x:0:0/ },
    { p: '..\\..\\..\\..\\windows\\win.ini', sig: /\[fonts\]|\[extensions\]/i },
    { p: '/etc/passwd', sig: /root:x:0:0/ }
  ];
  const params = ['file', 'path', 'page', 'include', 'inc', 'template', 'view', 'doc', 'document', 'load', 'read', 'filename', 'f', 'url', 'src', 'lang', 'action', 'module', 'conf'];
  for (const t of targets.slice(0, 30)) {
    try {
      const u = new URL(t);
      for (const param of params) {
        for (const pl of payloads) {
          const testUrl = `${u.origin}${u.pathname}${u.search ? u.search + '&' : '?'}${param}=${encodeURIComponent(pl.p)}`;
          try {
            const r = await httpReq(testUrl, { timeout: 6000 });
            if (r.status === 200 && pl.sig.test(r.body)) {
              findings.push({
                'template-id': 'lfi-path-traversal',
                'matched-at': testUrl, host: t,
                info: { name: 'Local File Inclusion / Path Traversal', severity: 'critical', tags: ['lfi', 'path-traversal', 'injection'], description: `Parameter '${param}' vulnerable LFI` },
                extracted_results: [`Param: ${param}`, `Payload: ${pl.p}`, `Evidence: ${r.body.slice(0, 200)}`],
                response: r.body.slice(0, 500)
              });
              break;
            }
          } catch {}
          await sleep(80);
        }
        if (findings.length) break;
      }
    } catch {}
  }
  log('LFI', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 5. SSRF + CLOUD METADATA ═══
async function ssrfCheck(targets) {
  log('SSRF', `☁️  SSRF / Cloud Metadata check`);
  const findings = [];
  const payloads = [
    { url: 'http://169.254.169.254/latest/meta-data/', sig: /ami-id|instance-id|hostname|iam/i, name: 'AWS-Metadata' },
    { url: 'http://metadata.google.internal/computeMetadata/v1/', sig: /project|instance/i, name: 'GCP-Metadata' },
    { url: 'http://100.100.100.200/latest/meta-data/', sig: /instance-id|region/i, name: 'Alibaba-Metadata' }
  ];
  const params = ['url', 'uri', 'path', 'dest', 'redirect', 'next', 'target', 'proxy', 'fetch', 'load', 'src', 'href', 'link', 'u', 'r', 'return', 'callback', 'webhook', 'image', 'imageUrl', 'avatar'];
  for (const t of targets.slice(0, 20)) {
    try {
      const u = new URL(t);
      for (const param of params) {
        for (const pl of payloads) {
          const testUrl = `${u.origin}${u.pathname}${u.search ? u.search + '&' : '?'}${param}=${encodeURIComponent(pl.url)}`;
          try {
            const r = await httpReq(testUrl, { timeout: 10000 });
            if (r.status === 200 && pl.sig.test(r.body) && r.body.length > 50) {
              findings.push({
                'template-id': `ssrf-${pl.name.toLowerCase()}`,
                'matched-at': testUrl, host: t,
                info: { name: `SSRF → ${pl.name}`, severity: 'critical', tags: ['ssrf', 'cloud', 'metadata'], description: `Parameter '${param}' vulnerable SSRF ke ${pl.name}` },
                extracted_results: [`Param: ${param}`, `URL: ${pl.url}`, `Evidence: ${r.body.slice(0, 200)}`],
                response: r.body.slice(0, 500)
              });
              break;
            }
          } catch {}
          await sleep(100);
        }
        if (findings.length) break;
      }
    } catch {}
  }
  log('SSRF', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 6. SQL INJECTION ═══
async function sqliCheck(targets) {
  log('SQLI', `💉 SQL Injection check`);
  const findings = [];
  const payloads = [
    { p: "'", sig: /SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|Microsoft OLE DB|Unclosed quotation|SQLite3|sqlite_|near \"/i },
    { p: "''", sig: /SQL syntax|mysql_fetch|ORA-\d{5}/i },
    { p: "1'", sig: /SQL syntax|mysql_fetch|Unclosed quotation/i },
    { p: "' OR '1'='1", sig: /SQL syntax|error in your SQL/i }
  ];
  const params = ['id', 'user', 'username', 'email', 'name', 'page', 'cat', 'category', 'product', 'item', 'pid', 'uid', 'q', 'search', 'order', 'sort', 'filter', 'key', 'token'];
  for (const t of targets.slice(0, 20)) {
    try {
      const u = new URL(t);
      for (const param of params) {
        for (const pl of payloads) {
          const testUrl = `${u.origin}${u.pathname}${u.search ? u.search + '&' : '?'}${param}=${encodeURIComponent(pl.p)}`;
          try {
            const r = await httpReq(testUrl, { timeout: 8000 });
            if (pl.sig.test(r.body)) {
              findings.push({
                'template-id': 'sqli-error-based',
                'matched-at': testUrl, host: t,
                info: { name: 'SQL Injection (error-based)', severity: 'critical', tags: ['sqli', 'injection'], description: `Parameter '${param}' vulnerable SQLi — error terlihat` },
                extracted_results: [`Param: ${param}`, `Payload: ${pl.p}`, `Evidence: ${r.body.slice(0, 300)}`],
                response: r.body.slice(0, 500)
              });
              break;
            }
          } catch {}
          await sleep(80);
        }
        if (findings.length) break;
      }
    } catch {}
  }
  log('SQLI', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 7. CRLF INJECTION ═══
async function crlfCheck(targets) {
  log('CRLF', `↵  CRLF injection check`);
  const findings = [];
  const payloads = ['%0d%0aX-Crlf-Test:yes', '%0aX-Crlf-Test:yes'];
  const params = ['url', 'redirect', 'next', 'page', 'lang', 'ref', 'q', 'id', 'name'];
  for (const t of targets.slice(0, 20)) {
    try {
      const u = new URL(t);
      for (const param of params) {
        for (const p of payloads) {
          const testUrl = `${u.origin}${u.pathname}${u.search ? u.search + '&' : '?'}${param}=test${p}`;
          try {
            const r = await httpReq(testUrl, { timeout: 6000 });
            if (r.headers['x-crlf-test']) {
              findings.push({
                'template-id': 'crlf-injection',
                'matched-at': testUrl, host: t,
                info: { name: 'CRLF Injection / HTTP Response Splitting', severity: 'medium', tags: ['crlf', 'injection'], description: `Parameter '${param}' vulnerable CRLF` },
                extracted_results: [`Param: ${param}`, `Payload: ${p}`]
              });
              break;
            }
          } catch {}
          await sleep(60);
        }
        if (findings.length) break;
      }
    } catch {}
  }
  log('CRLF', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 8. HOST HEADER INJECTION ═══
async function hostHeaderCheck(targets) {
  log('HOST', `🎭 Host header injection check`);
  const findings = [];
  const resetPages = ['/forgot-password', '/password-reset', '/reset', '/forgot', '/account/recover', '/users/password/new', '/auth/forgot'];
  for (const t of targets.slice(0, 40)) {
    try {
      const u = new URL(t);
      for (const page of resetPages) {
        const testUrl = `${u.origin}${page}`;
        try {
          const r = await httpReq(testUrl, {
            headers: { 'Host': 'evil-attacker.com', 'X-Forwarded-Host': 'evil-attacker.com' },
            timeout: 6000
          });
          if (r.status === 200 && /evil-attacker\.com/i.test(r.body)) {
            findings.push({
              'template-id': 'host-header-injection',
              'matched-at': testUrl, host: t,
              info: { name: 'Host Header Injection', severity: 'medium', tags: ['host-header', 'injection', 'password-reset'], description: `Host header terefleksi di ${page}` },
              extracted_results: ['Host: evil-attacker.com']
            });
            break;
          }
        } catch {}
        await sleep(80);
      }
    } catch {}
  }
  log('HOST', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 9. DNS SECURITY (SPF / DMARC) ═══
async function dnsSecurityCheck(targets) {
  log('DNS', `📧 DNS Security (SPF/DMARC) check`);
  const findings = [];
  const domains = unique(targets.map(t => {
    try { return new URL(t).hostname.replace(/^www\./, '').split('.').slice(-2).join('.'); } catch { return null; }
  }).filter(Boolean));
  for (const d of domains.slice(0, 20)) {
    try {
      const spfTxt = await dns.resolveTxt(d).catch(() => []);
      const spf = spfTxt.flat().find(r => /v=spf1/i.test(r));
      if (!spf) {
        findings.push({
          'template-id': 'missing-spf', 'matched-at': `dns:${d}`, host: `https://${d}`,
          info: { name: 'Missing SPF Record', severity: 'medium', tags: ['dns', 'email', 'spoofing'], description: `Domain ${d} tidak punya SPF — rentan email spoofing` },
          extracted_results: [d]
        });
      } else if (/[+?]all/.test(spf)) {
        findings.push({
          'template-id': 'weak-spf', 'matched-at': `dns:${d}`, host: `https://${d}`,
          info: { name: 'Weak SPF Record', severity: 'medium', tags: ['dns', 'email'], description: `SPF terlalu permisif: ${spf}` },
          extracted_results: [spf]
        });
      }
      const dmarcTxt = await dns.resolveTxt(`_dmarc.${d}`).catch(() => []);
      const dmarc = dmarcTxt.flat().find(r => /v=DMARC1/i.test(r));
      if (!dmarc) {
        findings.push({
          'template-id': 'missing-dmarc', 'matched-at': `dns:_dmarc.${d}`, host: `https://${d}`,
          info: { name: 'Missing DMARC Record', severity: 'medium', tags: ['dns', 'email', 'spoofing'], description: `Domain ${d} tidak punya DMARC` },
          extracted_results: [d]
        });
      } else if (/p=none/i.test(dmarc)) {
        findings.push({
          'template-id': 'dmarc-monitor-only', 'matched-at': `dns:_dmarc.${d}`, host: `https://${d}`,
          info: { name: 'DMARC Policy = none (monitoring only)', severity: 'low', tags: ['dns', 'email'], description: `DMARC tidak block spoofing: ${dmarc}` },
          extracted_results: [dmarc]
        });
      }
    } catch {}
    await sleep(200);
  }
  log('DNS', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 10. RATE LIMITING ═══
async function rateLimitCheck(targets) {
  log('RATE', `⏱  Rate limiting check`);
  const findings = [];
  const forms = ['/login', '/signin', '/api/login', '/api/auth', '/api/token', '/register', '/api/register', '/api/v1/login'];
  for (const t of targets.slice(0, 15)) {
    try {
      const u = new URL(t);
      for (const f of forms) {
        const testUrl = `${u.origin}${f}`;
        try {
          const probe = await httpReq(testUrl, { timeout: 5000 });
          if (![200, 401, 405, 422].includes(probe.status)) continue;
          let blocked = false;
          for (let i = 0; i < 15; i++) {
            const r = await httpReq(testUrl, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: '{"username":"nonexistent_test_user","password":"wrong"}',
              timeout: 5000
            });
            if (r.status === 429 || r.status === 403) { blocked = true; break; }
          }
          if (!blocked) {
            findings.push({
              'template-id': 'no-rate-limit-login', 'matched-at': testUrl, host: t,
              info: { name: 'No Rate Limiting on Login', severity: 'low', tags: ['rate-limit', 'brute-force'], description: '15 request cepat tidak diblokir' },
              extracted_results: ['Tested: 15 POST requests']
            });
            break;
          }
        } catch {}
        await sleep(500);
      }
    } catch {}
  }
  log('RATE', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 11. USER ENUMERATION ═══
async function userEnumCheck(targets) {
  log('ENUM', `👤 User enumeration check`);
  const findings = [];
  const pages = ['/login', '/signin', '/api/login', '/api/auth', '/forgot-password', '/api/password/reset'];
  for (const t of targets.slice(0, 15)) {
    try {
      const u = new URL(t);
      for (const page of pages) {
        const testUrl = `${u.origin}${page}`;
        try {
          const r1 = await httpReq(testUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{"username":"admin@' + u.hostname + '","password":"wrongpw123"}',
            timeout: 6000
          });
          const r2 = await httpReq(testUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{"username":"xyz_' + rand(8) + '@nonexist.invalid","password":"wrongpw123"}',
            timeout: 6000
          });
          const m1 = (r1.body || '').match(/"(?:error|message|detail)"\s*:\s*"([^"]+)"/);
          const m2 = (r2.body || '').match(/"(?:error|message|detail)"\s*:\s*"([^"]+)"/);
          if (m1 && m2 && m1[1] !== m2[1]) {
            findings.push({
              'template-id': 'user-enumeration', 'matched-at': testUrl, host: t,
              info: { name: 'Username Enumeration', severity: 'low', tags: ['user-enum', 'enumeration'], description: 'Response berbeda untuk user valid vs invalid' },
              extracted_results: [`Valid: "${m1[1]}"`, `Invalid: "${m2[1]}"`]
            });
            break;
          }
        } catch {}
        await sleep(400);
      }
    } catch {}
  }
  log('ENUM', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 12. ROBOTS.TXT ANALYSIS ═══
async function robotsCheck(targets) {
  log('ROBOTS', `🤖 robots.txt analysis`);
  const findings = [];
  const sensitive = /admin|backup|config|private|secret|internal|api|dashboard|panel|test|dev|staging|\.git|\.env|\.sql|\.bak|phpinfo|debug|console/i;
  for (const t of targets.slice(0, 40)) {
    try {
      const u = new URL(t);
      const r = await httpReq(`${u.origin}/robots.txt`, { timeout: 6000 });
      if (r.status !== 200 || !/Disallow|Allow/i.test(r.body)) continue;
      const disallows = (r.body.match(/(?:Disallow|Allow):\s*([^\r\n#]+)/gi) || [])
        .map(l => l.replace(/^(?:Disallow|Allow):\s*/i, '').trim())
        .filter(l => l && l !== '/' && l !== '*');
      const interesting = disallows.filter(p => sensitive.test(p));
      if (interesting.length) {
        findings.push({
          'template-id': 'robots-sensitive-paths', 'matched-at': `${u.origin}/robots.txt`, host: t,
          info: { name: 'Sensitive Paths in robots.txt', severity: 'low', tags: ['robots', 'info-disclosure', 'recon'], description: `${interesting.length} path sensitif terungkap` },
          extracted_results: unique(interesting).slice(0, 20)
        });
      }
    } catch {}
    await sleep(80);
  }
  log('ROBOTS', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 13. FIREBASE MISCONFIG ═══
async function firebaseCheck(targets) {
  log('FB', `🔥 Firebase misconfig check`);
  const findings = [];
  for (const t of targets.slice(0, 30)) {
    try {
      const r = await httpReq(t, { timeout: 8000 });
      if (!r.body) continue;
      const fbUrls = unique((r.body.match(/https:\/\/([a-z0-9-]+)\.firebaseio\.com/gi) || []));
      for (const fb of fbUrls.slice(0, 3)) {
        const testUrl = `${fb}/.json`;
        try {
          const cr = await httpReq(testUrl, { timeout: 6000 });
          if (cr.status === 200 && cr.body && cr.body !== 'null' && cr.body.length > 2 && /{/.test(cr.body)) {
            findings.push({
              'template-id': 'firebase-public-read', 'matched-at': testUrl, host: t,
              info: { name: 'Firebase Public Read Enabled', severity: 'high', tags: ['firebase', 'cloud', 'exposure'], description: 'Firebase database bisa dibaca publik' },
              extracted_results: [cr.body.slice(0, 200)]
            });
          }
        } catch {}
        await sleep(100);
      }
    } catch {}
    await sleep(100);
  }
  log('FB', `✓ ${findings.length} findings`);
  return findings;
}

// ═══ 14. S3 BUCKET PUBLIC ═══
async function s3Check(targets) {
  log('S3', `🪣 S3 bucket enumeration`);
  const findings = [];
  const domains = unique(targets.map(t => {
    try { return new URL(t).hostname.replace(/^www\./, '').split('.')[0]; } catch { return null; }
  }).filter(Boolean));
  const suffixes = ['', '-backup', '-dev', '-prod', '-staging', '-test', '-assets', '-static', '-files', '-uploads', '-media', '-public'];
  for (const d of domains.slice(0, 10)) {
    for (const s of suffixes) {
      const bucket = `${d}${s}`;
      const url = `https://${bucket}.s3.amazonaws.com/`;
      try {
        const r = await httpReq(url, { timeout: 5000 });
        if (r.status === 200 && /ListBucketResult|<Contents>|<Key>/i.test(r.body)) {
          findings.push({
            'template-id': 's3-bucket-public', 'matched-at': url, host: url,
            info: { name: 'Public S3 Bucket', severity: 'high', tags: ['s3', 'cloud', 'exposure'], description: `Bucket S3 publik: ${bucket}` },
            extracted_results: [r.body.slice(0, 300)]
          });
        }
      } catch {}
      await sleep(100);
    }
  }
  log('S3', `✓ ${findings.length} findings`);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 1: UTILS
// ═══════════════════════════════════════════════════════════════════════════
const sleep = ms => new Promise(r => setTimeout(r, ms));
const ensureDir = p => { try { fs.mkdirSync(p, { recursive: true }); } catch {} };
const unique = a => [...new Set(a)];
const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const rand = (n = 8) => crypto.randomBytes(n).toString('hex').slice(0, n);
const chunk = (a, n) => { const o = []; for (let i = 0; i < a.length; i += n) o.push(a.slice(i, i + n)); return o; };
const nowISO = () => new Date().toISOString();
const clamp = (n, min, max) => Math.max(min, Math.min(max, n));

function toolExists(name) {
  try {
    const r = spawnSync(name, ['-h'], { encoding: 'utf-8', timeout: 3000, stdio: ['ignore', 'ignore', 'ignore'] });
    return !r.error;
  } catch { return false; }
}

function httpReq(url, opts = {}) {
  return new Promise(resolve => {
    let done = false;
    const finish = r => { if (!done) { done = true; resolve(r); } };
    try {
      const u = new URL(url);
      const lib = u.protocol === 'https:' ? https : http;
      const headers = Object.assign({
        'User-Agent': 'Mozilla/5.0 (compatible; SecurityResearch; +alhindawi-hunter)'
      }, opts.headers || {});
      const req = lib.request({
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method: opts.method || 'GET',
        headers,
        timeout: opts.timeout || 10000,
        rejectUnauthorized: false
      }, res => {
        let body = '';
        res.on('data', c => {
          body += c;
          if (body.length > 500000) { body = body.slice(0, 500000); req.destroy(); }
        });
        res.on('end', () => finish({ status: res.statusCode, headers: res.headers, body, url }));
      });
      req.on('error', e => finish({ status: 0, headers: {}, body: '', error: e.message }));
      req.on('timeout', () => { req.destroy(); finish({ status: 0, headers: {}, body: '' }); });
      if (opts.body) req.write(opts.body);
      req.end();
    } catch (e) { finish({ status: 0, headers: {}, body: '', error: e.message }); }
  });
}

function httpPost(url, body, headers = {}) {
  return new Promise(res => {
    try {
      const u = new URL(url);
      const data = typeof body === 'string' ? body : JSON.stringify(body);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.request({
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers },
        timeout: 10000
      }, r => { r.on('data', () => {}); r.on('end', res); });
      req.on('error', res);
      req.write(data);
      req.end();
    } catch { res(); }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 2: COLOR LOGGER
// ═══════════════════════════════════════════════════════════════════════════
const C = {
  r: '\x1b[0m', b: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', grn: '\x1b[32m', yel: '\x1b[33m',
  blu: '\x1b[34m', mag: '\x1b[35m', cyn: '\x1b[36m', gry: '\x1b[90m'
};

const LEVEL_COLORS = {
  INFO: C.blu, WARN: C.yel, ERROR: C.red, DEBUG: C.gry,
  FINDING: C.grn, RECON: C.cyn, PERMUTE: C.cyn, CT: C.cyn,
  JS: C.mag, SRCMAP: C.mag, TAKEOVER: C.red, CORS: C.mag,
  GRAPHQL: C.mag, JWT: C.mag, DIR: C.yel, OPENAPI: C.mag,
  HTTPM: C.yel, CRAWL: C.cyn, TECH: C.cyn, AI: C.grn,
  DASH: C.cyn, WAF: C.yel, SCOPE: C.yel, RATE: C.yel,
  CHECKPOINT: C.grn, DUP: C.gry, NOTIFY: C.mag, PROXY: C.cyn,
  AUTH: C.cyn, VRT: C.grn, CVE: C.mag, FP: C.yel, VERIFY: C.grn,
  MODULE: C.gry, IIS: C.mag,
  HEADERS: C.cyn, XSS: C.mag, REDIR: C.yel, LFI: C.red,
  SSRF: C.red, SQLI: C.red, CRLF: C.yel, HOST: C.mag,
  DNS: C.cyn, ROBOTS: C.gry, FB: C.yel, S3: C.yel,
  ENUM: C.yel
  };

let logStream = null;
const liveBus = [];

function initLogger(dir) {
  ensureDir(dir);
  try { logStream = fs.createWriteStream(path.join(dir, 'scan.log'), { flags: 'a' }); }
  catch {}
}

function log(lvl, msg) {
  try {
    const color = LEVEL_COLORS[lvl] || '';
    const line = `[${nowISO()}] [${lvl}] ${msg}`;
    console.log(`${color}${line}${C.r}`);
    if (logStream) logStream.write(line + '\n');
    liveBus.push({ ts: Date.now(), lvl, msg: String(msg).replace(/\x1b\[\d+m/g, '') });
    if (liveBus.length > 500) liveBus.splice(0, 100);
  } catch {}
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 3: ARGS + CONFIG
// ═══════════════════════════════════════════════════════════════════════════
const argv = process.argv.slice(2);
const FLAGS = {};
const POSITIONAL = [];
for (const a of argv) {
  if (a.startsWith('--')) {
    const eq = a.indexOf('=');
    if (eq > 0) FLAGS[a.slice(2, eq)] = a.slice(eq + 1);
    else FLAGS[a.slice(2)] = true;
  } else {
    POSITIONAL.push(a);
  }
}

function loadYamlConfig(file) {
  if (!file || !fs.existsSync(file)) return {};
  try {
    const lines = fs.readFileSync(file, 'utf-8').split(/\r?\n/);
    const out = {};
    const stack = [out];
    const keys = [];
    for (const raw of lines) {
      const line = raw.replace(/#.*$/, '').replace(/\s+$/, '');
      if (!line.trim()) continue;
      const m = line.match(/^(\s*)([\w-]+):\s*(.*)$/);
      if (!m) continue;
      const indent = m[1].length;
      const key = m[2];
      let val = m[3].trim();
      while (stack.length > 1 && keys.length && indent <= keys[keys.length - 1].indent) {
        stack.pop(); keys.pop();
      }
      const parent = stack[stack.length - 1];
      if (val === '') {
        parent[key] = {};
        stack.push(parent[key]);
        keys.push({ indent, key });
      } else {
        if (val === 'true') val = true;
        else if (val === 'false') val = false;
        else if (/^\d+$/.test(val)) val = parseInt(val, 10);
        else if (/^\[.*\]$/.test(val)) val = val.slice(1, -1).split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
        else val = val.replace(/^["']|["']$/g, '');
        parent[key] = val;
      }
    }
    return out;
  } catch (e) { return {}; }
}

const YAML = loadYamlConfig(FLAGS.config || process.env.CONFIG_FILE);
const INPUT_RAW = POSITIONAL[0] || YAML.targets || 'targets.txt';
const INPUT = (() => {
  try {
    if (fs.existsSync(INPUT_RAW)) return { file: INPUT_RAW, isFile: true };
  } catch {}
  return { file: null, isFile: false, domains: INPUT_RAW.split(',').map(s => s.trim()).filter(Boolean) };
})();

const CFG = {
  input: INPUT_RAW,
  outputDir: POSITIONAL[1] || YAML.output || `alhindawi_${Date.now()}`,
  rate: +FLAGS.rate || +YAML.rate || 5,
  profile: String(FLAGS.profile || YAML.profile || 'normal').toLowerCase(),
  severity: FLAGS.severity || YAML.severity || 'critical,high,medium,low',
  workers: +FLAGS.workers || +YAML.workers || 3,
  batchSize: +FLAGS.batch || +YAML.batch || 40,
  excludeTags: FLAGS['exclude-tags'] || YAML.excludeTags || 'dos,fuzz,intrusive,brute-force',
  includeTags: FLAGS['include-tags'] || YAML.includeTags || '',
  templatesDir: FLAGS.templates || process.env.TEMPLATES_DIR || '',
  headers: String(FLAGS.headers || process.env.HEADERS || '').split(';').map(s => s.trim()).filter(Boolean),
  interactsh: FLAGS.interactsh === true,
  nucleiPath: process.env.NUCLEI_PATH || 'nuclei',
  subfinderPath: process.env.SUBFINDER_PATH || 'subfinder',
  httpxPath: process.env.HTTPX_PATH || 'httpx',
  gauPath: process.env.GAU_PATH || 'gau',
  skipUpdate: process.env.NUCLEI_SKIP_UPDATE === '1' || FLAGS['skip-update'] === true,
  dryRun: process.env.DRY_RUN === '1' || FLAGS['dry-run'] === true,

  discord: process.env.DISCORD_WEBHOOK || (YAML.notifications && YAML.notifications.discord) || '',
  slack: process.env.SLACK_WEBHOOK || (YAML.notifications && YAML.notifications.slack) || '',
  tgBot: process.env.TELEGRAM_BOT || '',
  tgChat: process.env.TELEGRAM_CHAT || '',
  githubToken: process.env.GITHUB_TOKEN || '',
  dashboardPort: +FLAGS.port || 8080,

  resume: process.env.RESUME === '1' || FLAGS.resume === true,
  scopeAllow: FLAGS.scope ? (FLAGS.scope === true ? 'allow.txt' : FLAGS.scope) : ((YAML.scope && YAML.scope.allow) || ''),
  scopeDeny: FLAGS.deny ? (FLAGS.deny === true ? 'deny.txt' : FLAGS.deny) : ((YAML.scope && YAML.scope.deny) || ''),
  proxyFile: FLAGS.proxy ? (FLAGS.proxy === true ? 'proxies.txt' : FLAGS.proxy) : ((YAML.proxy && YAML.proxy.file) || ''),

  authUrl: FLAGS['auth-url'] || (YAML.auth && YAML.auth.url) || '',
  authMethod: String(FLAGS['auth-method'] || (YAML.auth && YAML.auth.method) || 'POST').toUpperCase(),
  authData: FLAGS['auth-data'] || (YAML.auth && YAML.auth.data) || '',
  authCookie: FLAGS['auth-cookie'] || (YAML.auth && YAML.auth.cookie) || '',
  authToken: FLAGS['auth-token'] || (YAML.auth && YAML.auth.token) || '',

  recon: FLAGS.recon === true,
  permute: FLAGS.permute === true,
  ctLogs: FLAGS.ct === true,
  tech: FLAGS.tech === true,
  jsSecrets: FLAGS['js-secrets'] === true,
  jsEndpoints: FLAGS['js-endpoints'] === true,
  sourceMaps: FLAGS['source-maps'] === true,
  takeover: FLAGS.takeover === true,
  cors: FLAGS.cors === true,
  graphql: FLAGS.graphql === true,
  jwt: FLAGS.jwt === true,
  dirBrute: FLAGS['dir-brute'] === true,
  openapi: FLAGS.openapi === true,
  httpMethods: FLAGS['http-methods'] === true,
  iisCheck: FLAGS.iis === true,
    headersCheck: FLAGS.headers === true,
  xssCheck: FLAGS.xss === true,
  openRedirectCheck: FLAGS['open-redirect'] === true,
  lfiCheck: FLAGS.lfi === true,
  ssrfCheck: FLAGS.ssrf === true,
  sqliCheck: FLAGS.sqli === true,
  crlfCheck: FLAGS.crlf === true,
  hostHeaderCheck: FLAGS['host-header'] === true,
  dnsSecurityCheck: FLAGS['dns-sec'] === true,
  rateLimitCheck: FLAGS['rate-limit'] === true,
  userEnumCheck: FLAGS['user-enum'] === true,
  robotsCheck: FLAGS.robots === true,
  firebaseCheck: FLAGS.firebase === true,
  s3Check: FLAGS.s3 === true,
  crawler: FLAGS.crawler === true,
  aiFilter: FLAGS['ai-filter'] !== false,
  dashboard: FLAGS.dashboard === true,

  vrt: FLAGS.vrt !== 'false',
  vrtExcludeP5: FLAGS['vrt-include-p5'] !== true,
  vrtReport: FLAGS['vrt-report'] !== 'false',

  cveFeed: FLAGS['cve-feed'] || '',
  cveFetchNVD: FLAGS['cve-fetch-nvd'] === true,
  cveFetchKEV: FLAGS['cve-kev'] === true,
  cveAPIKey: process.env.NVD_API_KEY || '',
  cveCache: FLAGS['cve-cache'] !== 'false',
  cveOnly: FLAGS['cve-only'] === true,
  cveKEVOnly: FLAGS['cve-kev-only'] === true,
  cveMinCVSS: +FLAGS['cve-min-cvss'] || 0,
  cveOverride: FLAGS['cve-override'] !== 'false',
  cveBulkLimit: +FLAGS['cve-bulk-limit'] || 50,

  fpStrict: FLAGS['fp-strict'] === true,
  fpParanoid: FLAGS['fp-paranoid'] === true,
  verifyPoc: FLAGS['verify-poc'] === true,

  sarif: FLAGS.sarif === true,
  junit: FLAGS.junit === true,
  reportFormat: FLAGS['report-format'] || 'bugcrowd'
};

const PROFILES = {
  stealth:    { rl: Math.max(1, Math.floor(CFG.rate / 2)), c: 5,  t: 20, r: 0, extra: ['-headless=false'] },
  normal:     { rl: CFG.rate,                              c: 15, t: 12, r: 1, extra: [] },
  aggressive: { rl: CFG.rate * 3,                          c: 40, t: 8,  r: 2, extra: ['-headless'] },
  ninja:      { rl: CFG.rate * 5,                          c: 80, t: 5,  r: 3, extra: ['-headless'] }
};
if (!PROFILES[CFG.profile]) {
  console.error(`❌ Unknown profile: ${CFG.profile}. Pilih: stealth|normal|aggressive|ninja`);
  process.exit(1);
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 4: BUGCROWD VRT v1.19
// ═══════════════════════════════════════════════════════════════════════════
const VRT_PRIORITY = {
  P1: { label: 'P1 · Critical', color: '#ef4444', cvss: [9.0, 10.0], bounty: [2000, 8000, 25000] },
  P2: { label: 'P2 · High',     color: '#f97316', cvss: [7.0, 8.9],  bounty: [800, 3000, 12000] },
  P3: { label: 'P3 · Medium',   color: '#eab308', cvss: [4.0, 6.9],  bounty: [200, 1000, 4000] },
  P4: { label: 'P4 · Low',      color: '#06b6d4', cvss: [0.1, 3.9],  bounty: [50, 300, 1500] },
  P5: { label: 'P5 · Info',     color: '#64748b', cvss: [0, 0],      bounty: [0, 0, 0] }
};

const VRT_RULES = [
  { re: /(rce|remote-code-exec|command-injection|cmd-injection|shellshock|log4shell|log4j)/i, p: 'P1', category: 'Server-Side Injection', vuln: 'Remote Code Execution (RCE)', variant: '' },
  { re: /(sqli|sql-injection|sql_injection)/i, p: 'P1', category: 'Server-Side Injection', vuln: 'SQL Injection', variant: '' },
  { re: /(lfi|local-file-inclusion|path-traversal|directory-traversal)/i, p: 'P1', category: 'Server-Side Injection', vuln: 'File Inclusion', variant: 'Local' },
  { re: /(xxe|xml-external-entity)/i, p: 'P1', category: 'Server-Side Injection', vuln: 'XML External Entity Injection (XXE)', variant: '' },
  { re: /(auth-bypass|authentication-bypass|login-bypass|auth_bypass)/i, p: 'P1', category: 'Broken Authentication and Session Management', vuln: 'Authentication Bypass', variant: '' },
  { re: /(idor.*sensitive|sensitive.*idor|object-reference)/i, p: 'P1', category: 'Broken Access Control (BAC)', vuln: 'Insecure Direct Object Reference (IDOR)', variant: 'Change/View Sensitive Information (Iterable)' },
  { re: /(aws-key|aws-secret|aws_access|aws-iam|iam.*public|public.*iam)/i, p: 'P1', category: 'Cloud Security', vuln: 'IAM Misconfiguration', variant: 'Publicly Accessible IAM Credentials' },
  { re: /(private-key|rsa-key|ssh-key|pem-exposed)/i, p: 'P1', category: 'Decentralized Application Misconfiguration', vuln: 'Insecure Data Storage', variant: 'Plaintext Private Key' },
  { re: /(exposed-env|env-exposure|dotenv|\.env)/i, p: 'P1', category: 'Sensitive Data Exposure', vuln: 'Disclosure of Secrets', variant: 'For Publicly Accessible Assets' },
  { re: /(default-login|default-cred|default-credentials|admin.*admin)/i, p: 'P1', category: 'Server Security Misconfiguration', vuln: 'Using Default Credentials', variant: '' },
  { re: /(exposed-admin-portal|admin-portal-exposed|open-portal-admin)/i, p: 'P1', category: 'Server Security Misconfiguration', vuln: 'Exposed Portal', variant: 'Admin Portal' },

  { re: /(xss.*stored|stored.*xss|persistent.*xss)/i, p: 'P2', category: 'Cross-Site Scripting (XSS)', vuln: 'Stored', variant: 'Non-Privileged User to Anyone' },
  { re: /(csrf|cross-site-request-forgery)/i, p: 'P2', category: 'Cross-Site Request Forgery (CSRF)', vuln: 'Application Wide', variant: '' },
  { re: /(ssrf.*internal|server-side-request-forgery)/i, p: 'P2', category: 'Server Security Misconfiguration', vuln: 'Server-Side Request Forgery (SSRF)', variant: 'Internal Data Exposure' },
  { re: /(iam.*permissive|over-permissive|iam.*role)/i, p: 'P2', category: 'Cloud Security', vuln: 'IAM Misconfiguration', variant: 'Over-Permissive IAM Role' },
  { re: /(subdomain-takeover|takeover)/i, p: 'P2', category: 'Server Security Misconfiguration', vuln: 'Misconfigured DNS', variant: 'Subdomain Takeover' },
  { re: /(oauth.*misconfig|oauth.*takeover)/i, p: 'P2', category: 'Server Security Misconfiguration', vuln: 'OAuth Misconfiguration', variant: 'Account Takeover' },
  { re: /(ssti|template-injection)/i, p: 'P2', category: 'Server-Side Injection', vuln: 'Server-Side Template Injection (SSTI)', variant: 'Basic' },
  { re: /(jwt.*alg.*none|jwt-alg-none|jwt-none)/i, p: 'P2', category: 'Broken Authentication and Session Management', vuln: 'JWT Weakness', variant: 'alg:none Accepted' },
  { re: /(graphql.*auth.*bypass|graphql.*idor)/i, p: 'P2', category: 'Broken Access Control (BAC)', vuln: 'GraphQL Authorization Bypass', variant: '' },
  { re: /(cors.*credentials|cors.*account-takeover)/i, p: 'P2', category: 'Server Security Misconfiguration', vuln: 'Unsafe Cross-Origin Resource Sharing', variant: 'Credentials + Reflected Origin' },
  { re: /(exposed.*secret|disclosure.*secret|leaked.*key|api-key)/i, p: 'P2', category: 'Sensitive Data Exposure', vuln: 'Disclosure of Secrets', variant: 'For Internal Assets' },
  { re: /(mongodb-uri|postgres-uri|database-uri|db-creds)/i, p: 'P2', category: 'Sensitive Data Exposure', vuln: 'Disclosure of Secrets', variant: 'Database Credentials' },
  { re: /(s3.*public|bucket.*public|public.*bucket|publicly-accessible.*storage|cloud-bucket)/i, p: 'P2', category: 'Cloud Security', vuln: 'Storage Misconfiguration', variant: 'Publicly Accessible Cloud Storage' },

  { re: /(xss.*reflected|reflected.*xss)/i, p: 'P3', category: 'Cross-Site Scripting (XSS)', vuln: 'Reflected', variant: 'Non-Self' },
  { re: /(^xss$|xss-injection|cross-site-scripting)/i, p: 'P3', category: 'Cross-Site Scripting (XSS)', vuln: 'Reflected', variant: 'Non-Self' },
  { re: /(open-redirect|url-redirect|unvalidated-redirect)/i, p: 'P3', category: 'Unvalidated Redirects and Forwards', vuln: 'Open Redirect', variant: 'GET-Based' },
  { re: /(crlf|http-response-splitting|response-manipulation)/i, p: 'P3', category: 'Server-Side Injection', vuln: 'HTTP Response Manipulation', variant: 'Response Splitting (CRLF)' },
  { re: /(cors-misconfig|^cors$|cors-reflected)/i, p: 'P3', category: 'Server Security Misconfiguration', vuln: 'Unsafe CORS', variant: '' },
  { re: /(graphql-introspection)/i, p: 'P3', category: 'Sensitive Data Exposure', vuln: 'GraphQL Introspection Enabled', variant: '' },
  { re: /(http-trace|trace-enabled|xst)/i, p: 'P3', category: 'Server Security Misconfiguration', vuln: 'Unsafe HTTP Method Enabled', variant: 'TRACE' },
  { re: /(http-put|put-enabled)/i, p: 'P3', category: 'Server Security Misconfiguration', vuln: 'Unsafe File Upload', variant: 'File Extension Filter Bypass' },
  { re: /(source-map|srcmap|js-map-exposed|sourcemap)/i, p: 'P3', category: 'Sensitive Data Exposure', vuln: 'Source Code Disclosure', variant: 'Via Source Map' },
  { re: /(dir-listing|directory-listing|exposed-path|dir-brute)/i, p: 'P3', category: 'Server Security Misconfiguration', vuln: 'Directory Listing Enabled', variant: 'Sensitive Data Exposure' },
  { re: /(ssrf.*scan|ssrf.*port|ssrf.*external)/i, p: 'P3', category: 'Server Security Misconfiguration', vuln: 'SSRF', variant: 'External - Low Impact' },
  { re: /(openapi-spec|swagger-exposed|api-docs-exposed|openapi)/i, p: 'P3', category: 'Sensitive Data Exposure', vuln: 'API Specification Disclosure', variant: '' },
  { re: /(password-reset|reset-token|password-reset-weak)/i, p: 'P3', category: 'Sensitive Data Exposure', vuln: 'Weak Password Reset', variant: 'Token Leakage' },

  { re: /(missing.*csp|content-security-policy.*missing|missing.*hsts|missing.*x-frame|security-header|missing.*header)/i, p: 'P4', category: 'Server Security Misconfiguration', vuln: 'Lack of Security Headers', variant: 'CSP / HSTS / X-Frame-Options' },
  { re: /(clickjack)/i, p: 'P4', category: 'Server Security Misconfiguration', vuln: 'Clickjacking', variant: 'Sensitive Click-Based Action' },
  { re: /(cookie.*secure|cookie.*httponly|missing.*cookie.*flag|session-cookie-flag)/i, p: 'P4', category: 'Server Security Misconfiguration', vuln: 'Missing Secure/HTTPOnly Cookie Flag', variant: 'Session Token' },
  { re: /(rate-limit|ratelimit|no-rate-limit)/i, p: 'P4', category: 'Server Security Misconfiguration', vuln: 'No Rate Limiting on Form', variant: 'Login/Register/Email/SMS' },
  { re: /(username-enum|user-enum|email-enum)/i, p: 'P4', category: 'Broken Access Control (BAC)', vuln: 'Username/Email Enumeration', variant: 'Non-Brute Force' },
  { re: /(session-fixation|session-not-invalidated|logout-session)/i, p: 'P4', category: 'Broken Authentication and Session Management', vuln: 'Failure to Invalidate Session', variant: 'On Logout/Password Change' },
  { re: /(weak-password-policy|password-policy|no-password-policy)/i, p: 'P4', category: 'Insufficient Security Configurability', vuln: 'No Password Policy', variant: '' },
  { re: /(2fa.*weak|weak.*2fa|no-2fa)/i, p: 'P4', category: 'Insufficient Security Configurability', vuln: 'Weak 2FA Implementation', variant: '' },
  { re: /(jwt.*no.*expiry|jwt-no-exp|jwt.*expiration)/i, p: 'P4', category: 'Broken Authentication and Session Management', vuln: 'Excessive JWT Expiry', variant: '' },
  { re: /(mail.*spoof|^spf$|^dkim$|^dmarc$|mail-misconfig)/i, p: 'P4', category: 'Server Security Misconfiguration', vuln: 'Mail Server Misconfiguration', variant: 'Missing/Misconfigured SPF/DKIM' },
  { re: /(cors.*wildcard|wildcard.*cors)/i, p: 'P4', category: 'Server Security Misconfiguration', vuln: 'Unsafe CORS', variant: 'Wildcard Origin (No Creds)' },

  { re: /(tech-detect|technologies|wappalyzer|fingerprint|banner|server-version|^tech$)/i, p: 'P5', category: 'Server Security Misconfiguration', vuln: 'Fingerprinting/Banner Disclosure', variant: '' },
  { re: /(robots-txt|robots.txt)/i, p: 'P5', category: 'Sensitive Data Exposure', vuln: 'Disclosure of Public Information', variant: 'Robots.txt' },
  { re: /(sri.*missing|subresource-integrity)/i, p: 'P5', category: 'Server Security Misconfiguration', vuln: 'Missing Subresource Integrity', variant: '' },
  { re: /(dnssec|caa-record)/i, p: 'P5', category: 'Server Security Misconfiguration', vuln: 'Missing DNSSEC/CAA', variant: '' },
  { re: /(mixed-content|https-sourcing-http)/i, p: 'P5', category: 'Sensitive Data Exposure', vuln: 'Mixed Content', variant: '' },
  { re: /(internal-ip|full-path-disclosure|stack-trace)/i, p: 'P5', category: 'Sensitive Data Exposure', vuln: 'Detailed Error/Debug Page', variant: '' },
  { re: /(self-xss|self-reflected|self-stored)/i, p: 'P5', category: 'Cross-Site Scripting (XSS)', vuln: 'Self XSS', variant: '' },
  { re: /(captcha-missing|missing-captcha)/i, p: 'P5', category: 'Server Security Misconfiguration', vuln: 'CAPTCHA Missing', variant: '' }
];

const VRT_REMEDIATION = {
  'SQL Injection': 'Gunakan parameterized queries / prepared statements. Validasi input.',
  'Remote Code Execution (RCE)': 'Hindari eval/exec pada input user. Sandboxing, patch vendor.',
  'Authentication Bypass': 'Audit flow autentikasi, enforce MFA, cek session handling.',
  'XML External Entity Injection (XXE)': 'Disable external entity processing di XML parser.',
  'File Inclusion': 'Validasi path, whitelist, jangan trust input user.',
  'Stored': 'Encode output secara kontekstual. Implement Content-Security-Policy.',
  'Reflected': 'Encode output, validasi input, gunakan CSP.',
  'Cross-Site Request Forgery (CSRF)': 'Gunakan anti-CSRF token unik per request.',
  'Server-Side Request Forgery (SSRF)': 'Whitelist URL tujuan, blokir internal IP ranges.',
  'Open Redirect': 'Whitelist redirect destination, jangan reflect langsung.',
  'Using Default Credentials': 'Ganti default credential, enforce password policy.',
  'Disclosure of Secrets': 'Rotate secret, revoke access, jangan commit ke source control.',
  'Misconfigured DNS': 'Hapus dangling DNS record atau claim resource di provider.',
  'Exposed Portal': 'Batasi akses portal dengan auth + IP whitelist.',
  'Lack of Security Headers': 'Tambahkan CSP, HSTS, X-Frame-Options, X-Content-Type-Options.',
  'Directory Listing Enabled': 'Disable autoindex pada web server.',
  'Clickjacking': 'Tambahkan X-Frame-Options: DENY atau CSP frame-ancestors.',
  'GraphQL Introspection Enabled': 'Disable introspection di production.',
  'Source Code Disclosure': 'Jangan deploy .map ke production.',
  'API Specification Disclosure': 'Batasi akses spec API dengan auth.'
};

function mapToVRT(finding) {
  try {
    const tid = finding['template-id'] || '';
    const name = (finding.info && finding.info.name) || '';
    const tags = ((finding.info && finding.info.tags) || []).join(' ');
    const haystack = `${tid} ${name} ${tags}`;
    for (const rule of VRT_RULES) {
      if (rule.re.test(haystack)) {
        return { p: rule.p, category: rule.category, vuln: rule.vuln, variant: rule.variant, matched: rule.re.source };
      }
    }
    const sev = String((finding.info && finding.info.severity) || 'info').toLowerCase();
    const map = { critical: 'P1', high: 'P2', medium: 'P3', low: 'P4', info: 'P5', unknown: 'P5' };
    return { p: map[sev] || 'P5', category: 'Uncategorized', vuln: (finding.info && finding.info.name) || 'Unknown', variant: '', matched: 'fallback', fallback: true };
  } catch { return { p: 'P5', category: 'Error', vuln: 'Unknown', variant: '' }; }
}

function enrichWithVRT(findings) {
  return findings.map(f => {
    const vrt = mapToVRT(f);
    const prio = VRT_PRIORITY[vrt.p] || VRT_PRIORITY.P5;
    return { ...f, _vrt: { ...vrt, label: prio.label, color: prio.color, cvssRange: prio.cvss, bountyRange: prio.bounty } };
  });
}

function vrtStats(findings) {
  const stats = { P1: 0, P2: 0, P3: 0, P4: 0, P5: 0 };
  const bounty = { P1: 0, P2: 0, P3: 0, P4: 0, P5: 0 };
  for (const f of findings) {
    const p = f._vrt && f._vrt.p;
    if (!p || stats[p] === undefined) continue;
    stats[p]++;
    bounty[p] += VRT_PRIORITY[p].bounty[1];
  }
  return { stats, bounty, total: Object.values(bounty).reduce((a, b) => a + b, 0) };
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 5: CVE INTELLIGENCE
// ═══════════════════════════════════════════════════════════════════════════
const SEV_MAP_LANG = {
  'kritis': 'critical', 'critical': 'critical',
  'tinggi': 'high', 'high': 'high',
  'sedang': 'medium', 'medium': 'medium',
  'rendah': 'low', 'low': 'low',
  'tidak ada skor': 'unknown', 'no score': 'unknown'
};
const CVSS_TO_SEV = s => !s ? 'unknown' : s >= 9.0 ? 'critical' : s >= 7.0 ? 'high' : s >= 4.0 ? 'medium' : s >= 0.1 ? 'low' : 'info';
const CVSS_TO_VRT = (s, kev) => kev ? (s >= 7.0 ? 'P1' : 'P2') : s >= 9.0 ? 'P1' : s >= 7.0 ? 'P2' : s >= 4.0 ? 'P3' : s >= 0.1 ? 'P4' : 'P5';

function parseTenableText(text) {
  const cves = {};
  const lines = String(text).split(/\r?\n/);
  let current = null;
  for (const raw of lines) {
    const line = raw.trim();
    if (!line) continue;
    const m = line.match(/^(CVE-\d{4}-\d{4,})\s+(.*)$/);
    if (m) {
      const id = m[1];
      const rest = m[2];
      const parts = rest.split('\t').map(s => s.trim()).filter(Boolean);
      if (parts.length >= 2) {
        const desc = parts[0];
        const sevRaw = parts[1].toLowerCase();
        const date = parts[2] || '';
        cves[id] = { id, description: desc, severity: SEV_MAP_LANG[sevRaw] || 'unknown', cvss: null, date, source: 'tenable-text', kev: false, exploit: false, references: [] };
      } else if (parts.length === 1 && current && cves[current]) {
        cves[current].description += ' ' + parts[0];
      }
      current = id;
      continue;
    }
    if (current && cves[current] && !/^Page|^PENGENAL|^Previous|^Next/i.test(line)) {
      if (cves[current].description.length < 3000) cves[current].description += ' ' + line;
    }
  }
  return cves;
}

function inferSeverity(cve) {
  if (cve.severity && cve.severity !== 'unknown') return cve.severity;
  const d = String(cve.description || '').toLowerCase();
  if (/rce|remote code exec|arbitrary code/.test(d)) return 'critical';
  if (/sql injection|authentication bypass|privilege escalation/.test(d)) return 'critical';
  if (/xss|cross.site script|csrf|ssrf|path traversal/.test(d)) return 'high';
  if (/information disclosure|info leak|denial of service/.test(d)) return 'medium';
  return 'unknown';
}

async function fetchFromNVD(cveId, apiKey = '') {
  try {
    const headers = {};
    if (apiKey) headers['apiKey'] = apiKey;
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
    const r = await new Promise(resolve => {
      const req = https.request(url, { method: 'GET', headers, timeout: 20000 }, res => {
        let b = '';
        res.on('data', c => b += c);
        res.on('end', () => resolve({ status: res.statusCode, body: b }));
      });
      req.on('error', () => resolve({ status: 0, body: '' }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: '' }); });
      req.end();
    });
    if (r.status !== 200 || !r.body) return null;
    const j = JSON.parse(r.body);
    const v = j.vulnerabilities && j.vulnerabilities[0] && j.vulnerabilities[0].cve;
    if (!v) return null;
    const m = v.metrics || {};
    const cvss = (m.cvssMetricV31 && m.cvssMetricV31[0] && m.cvssMetricV31[0].cvssData) ||
                 (m.cvssMetricV30 && m.cvssMetricV30[0] && m.cvssMetricV30[0].cvssData) ||
                 (m.cvssMetricV2 && m.cvssMetricV2[0] && m.cvssMetricV2[0].cvssData);
    const desc = (v.descriptions || []).find(d => d.lang === 'en');
    return {
      id: cveId,
      description: desc ? desc.value : '',
      severity: String((cvss && cvss.baseSeverity) || '').toLowerCase() || CVSS_TO_SEV(cvss && cvss.baseScore),
      cvss: (cvss && cvss.baseScore) || null,
      cvssVector: (cvss && cvss.vectorString) || null,
      published: v.published || '',
      modified: v.lastModified || '',
      kev: !!v.cisaExploitAdd,
      exploit: !!v.cisaExploitAdd,
      references: (v.references || []).slice(0, 10).map(r => r.url),
      cwe: (v.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(Boolean),
      source: 'nvd'
    };
  } catch { return null; }
}

async function fetchCISAKEV() {
  try {
    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    const r = await new Promise(resolve => {
      https.get(url, { timeout: 30000 }, res => {
        let b = '';
        res.on('data', c => b += c);
        res.on('end', () => resolve({ status: res.statusCode, body: b }));
      }).on('error', () => resolve({ status: 0, body: '' }));
    });
    if (r.status !== 200 || !r.body) return {};
    const j = JSON.parse(r.body);
    const out = {};
    for (const v of (j.vulnerabilities || [])) {
      out[v.cveID] = {
        kev: true, kevDate: v.dateAdded,
        ransomware: v.knownRansomwareCampaignUse === 'Known',
        vendor: v.vendorProject, product: v.product,
        requiredAction: v.requiredAction, dueDate: v.dueDate
      };
    }
    return out;
  } catch { return {}; }
}

class CVEDatabase {
  constructor() {
    this.cves = {};
    this.kev = {};
    this.stats = { parsed: 0, nvd: 0, kev: 0 };
  }
  loadFromTextFile(fp) {
    if (!fs.existsSync(fp)) return 0;
    try {
      const parsed = parseTenableText(fs.readFileSync(fp, 'utf-8'));
      let n = 0;
      for (const [id, cve] of Object.entries(parsed)) {
        cve.severity = inferSeverity(cve);
        this.cves[id] = cve; n++;
      }
      this.stats.parsed += n;
      return n;
    } catch { return 0; }
  }
  loadFromJSONFile(fp) {
    if (!fs.existsSync(fp)) return 0;
    try {
      const j = JSON.parse(fs.readFileSync(fp, 'utf-8'));
      let n = 0;
      if (Array.isArray(j)) {
        for (const c of j) if (c.id) { this.cves[c.id] = c; n++; }
      } else {
        for (const [k, v] of Object.entries(j)) {
          if (k.startsWith('CVE-')) { this.cves[k] = { id: k, ...v }; n++; }
        }
      }
      return n;
    } catch { return 0; }
  }
  loadFromFolder(dir) {
    if (!fs.existsSync(dir)) return 0;
    let t = 0;
    try {
      for (const f of fs.readdirSync(dir)) {
        const fp = path.join(dir, f);
        if (/\.json$/i.test(f)) t += this.loadFromJSONFile(fp);
        else if (/\.txt$/i.test(f)) t += this.loadFromTextFile(fp);
      }
    } catch {}
    return t;
  }
  async loadKEV() {
    const k = await fetchCISAKEV();
    this.kev = k;
    this.stats.kev = Object.keys(k).length;
    for (const [id, info] of Object.entries(k)) {
      if (!this.cves[id]) this.cves[id] = { id, description: '', severity: 'critical', cvss: null, source: 'kev' };
      Object.assign(this.cves[id], info);
    }
    return this.stats.kev;
  }
  async fetchNVD(cveId, apiKey = '') {
    if (this.cves[cveId] && this.cves[cveId].cvss) return this.cves[cveId];
    const d = await fetchFromNVD(cveId, apiKey);
    if (d) { this.cves[cveId] = { ...(this.cves[cveId] || {}), ...d }; this.stats.nvd++; }
    return this.cves[cveId] || null;
  }
  save(fp) {
    try {
      fs.writeFileSync(fp, JSON.stringify({ stats: this.stats, generated: nowISO(), cves: this.cves, kev: this.kev }, null, 2));
      return true;
    } catch { return false; }
  }
  load(fp) {
    if (!fs.existsSync(fp)) return false;
    try {
      const j = JSON.parse(fs.readFileSync(fp, 'utf-8'));
      this.cves = j.cves || {};
      this.kev = j.kev || {};
      this.stats = j.stats || { parsed: 0, nvd: 0, kev: 0 };
      return true;
    } catch { return false; }
  }
  get(id) { return this.cves[id] || null; }
  has(id) { return !!this.cves[id]; }
  size() { return Object.keys(this.cves).length; }
}

const CVE_ID_RE = /CVE-\d{4}-\d{4,}/gi;
function extractCVEIds(finding) {
  try {
    const h = [
      finding['template-id'] || '',
      (finding.info && finding.info.name) || '',
      (finding.info && finding.info.description) || '',
      ((finding.info && finding.info.tags) || []).join(' ')
    ].join(' ');
    return unique((h.match(CVE_ID_RE) || []).map(s => s.toUpperCase()));
  } catch { return []; }
}

function matchCVEsForFinding(finding, db) {
  const ids = extractCVEIds(finding);
  const matched = [];
  for (const id of ids) {
    const c = db.get(id);
    if (c) matched.push(c);
  }
  return matched;
}

function enrichFindingsWithCVE(findings, db) {
  return findings.map(f => {
    try {
      const cves = matchCVEsForFinding(f, db);
      if (!cves.length) return f;
      const sorted = cves.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
      const primary = sorted[0];
      const kev = cves.some(c => c.kev);
      const maxCVSS = Math.max(...cves.map(c => c.cvss || 0));
      const vrt = CVSS_TO_VRT(maxCVSS, kev);
      return {
        ...f,
        _cve: {
          ids: cves.map(c => c.id),
          primary: primary.id,
          cvss: maxCVSS || null,
          cvssVector: primary.cvssVector || null,
          severity: primary.severity || 'unknown',
          kev,
          kevDate: primary.kevDate || null,
          ransomware: primary.ransomware || false,
          vendor: primary.vendor || null,
          product: primary.product || null,
          requiredAction: primary.requiredAction || null,
          dueDate: primary.dueDate || null,
          description: primary.description || '',
          references: unique(cves.flatMap(c => c.references || [])).slice(0, 10),
          cwe: unique(cves.flatMap(c => c.cwe || [])),
          vrt,
          count: cves.length
        }
      };
    } catch { return f; }
  });
}

function applyCVEOverride(findings) {
  return findings.map(f => {
    try {
      if (!f._cve || !f._cve.kev || !f._vrt) return f;
      const newP = ['P3', 'P4', 'P5'].includes(f._vrt.p) ? f._cve.vrt : f._vrt.p;
      if (newP !== f._vrt.p) {
        return { ...f, _vrt: { ...f._vrt, p: newP, overridden: true, reason: 'KEV — exploited in wild' } };
      }
      return f;
    } catch { return f; }
  });
}

function cveStats(findings) {
  const stats = { total: 0, uniq: new Set(), kev: 0, ransomware: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, byVendor: {}, avgCVSS: 0 };
  let cvssSum = 0, cvssCount = 0;
  for (const f of findings) {
    if (!f._cve) continue;
    stats.total++;
    stats.uniq.add(f._cve.primary);
    if (f._cve.kev) stats.kev++;
    if (f._cve.ransomware) stats.ransomware++;
    const s = f._cve.severity || 'unknown';
    if (stats.bySeverity[s] !== undefined) stats.bySeverity[s]++;
    if (f._cve.vendor) stats.byVendor[f._cve.vendor] = (stats.byVendor[f._cve.vendor] || 0) + 1;
    if (f._cve.cvss) { cvssSum += f._cve.cvss; cvssCount++; }
  }
  stats.uniq = stats.uniq.size;
  stats.avgCVSS = cvssCount ? +(cvssSum / cvssCount).toFixed(2) : 0;
  return stats;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 6: FALSE-POSITIVE REDUCTION ENGINE
// ═══════════════════════════════════════════════════════════════════════════
function computeConfidence(f) {
  let score = 40;
  const tags = ((f.info && f.info.tags) || []).map(t => t.toLowerCase());
  const sev = String((f.info && f.info.severity) || '').toLowerCase();
  const body = String(f.response || '').toLowerCase();
  const url = String(f['matched-at'] || f.host || '').toLowerCase();

  if (f.extracted_results && f.extracted_results.length) score += 20;
  if (f._cve && f._cve.cvss && f._cve.cvss >= 7.0) score += 15;
  if (f._cve && f._cve.kev) score += 25;
  if (/rce|sql-injection|command-injection|auth-bypass|xxe|ssrf|idor|lfi/.test(tags.join(' '))) score += 15;
  if (sev === 'critical') score += 10;
  else if (sev === 'high') score += 6;
  if (f._vrt && f._vrt.p === 'P1') score += 10;
  else if (f._vrt && f._vrt.p === 'P2') score += 5;
  if (/cve/i.test(f['template-id'] || '')) score += 5;
  if (f._verify && f._verify.confirmed) score += 30;
  if (f._verify && !f._verify.confirmed) score -= 40;
  if (f._multiSignal && f._multiSignal >= 2) score += 10;

  if (/waf|access denied|forbidden|blocked|cloudflare|attention required/i.test(body)) score -= 30;
  if (/<title>error 40[0-9]|not found|404/.test(body)) score -= 25;
  if (/honeypot|decoy|test only|example\.com/i.test(url)) score -= 15;
  if (tags.includes('tech-detect') || tags.includes('detect') || tags.includes('technologies')) score -= 30;
  if (tags.includes('fingerprint') || tags.includes('banner')) score -= 25;
  if (tags.includes('self-') || tags.includes('self-xss')) score -= 20;
  if (!f['matched-at'] && !f.host) score -= 40;
  if (String(f['template-id'] || '').match(/^tech-|^detect-|^wappalyzer-/)) score -= 30;
  if (f['template-id'] && /(info$|-info$|robots|sitemap|dns-record)/.test(f['template-id'])) score -= 20;

  return clamp(score, 0, 100);
}

const soft404Cache = new Map();
async function detectSoft404(host) {
  const key = (() => { try { return new URL(host).hostname; } catch { return host; } })();
  if (soft404Cache.has(key)) return soft404Cache.get(key);
  try {
    const testUrl = `${host.replace(/\/$/, '')}/${rand(20)}-notfound`;
    const r = await httpReq(testUrl, { timeout: 6000 });
    const res = {
      status: r.status,
      len: r.body.length,
      hash: sha(r.body.slice(0, 3000)),
      isSoft: r.status === 200 && r.body.length > 100
    };
    soft404Cache.set(key, res);
    return res;
  } catch {
    const res = { status: 0, len: 0, hash: '', isSoft: false };
    soft404Cache.set(key, res);
    return res;
  }
}

async function isSoft404Match(finding) {
  try {
    const host = finding.host;
    if (!host) return false;
    const baseline = await detectSoft404(host);
    if (!baseline.isSoft) return false;
    const r = await httpReq(finding['matched-at'] || host, { timeout: 6000 });
    if (r.status !== baseline.status) return false;
    if (Math.abs(r.body.length - baseline.len) < 200) return true;
    if (sha(r.body.slice(0, 3000)) === baseline.hash) return true;
    return false;
  } catch { return false; }
}

async function reduceFalsePositives(findings, opts = {}) {
  log('FP', `🔍 FP reduction pipeline: ${findings.length} findings`);

  for (const f of findings) f._confidence = computeConfidence(f);

  let kept = findings.filter(f => f._confidence >= 25);
  const dropped1 = findings.length - kept.length;
  if (dropped1) log('FP', `  ✂️  Dropped ${dropped1} low-confidence (score < 25)`);

  const dirFindings = kept.filter(f => (f['template-id'] || '').includes('exposed-path') || (f['template-id'] || '').includes('dir'));
  const otherFindings = kept.filter(f => !dirFindings.includes(f));
  const dirFiltered = [];
  for (const f of dirFindings) {
    if (!await isSoft404Match(f)) dirFiltered.push(f);
  }
  const soft404Dropped = dirFindings.length - dirFiltered.length;
  if (soft404Dropped) log('FP', `  ✂️  Dropped ${soft404Dropped} soft-404 wildcards`);
  kept = [...dirFiltered, ...otherFindings];

  if (opts.strict) {
    const before = kept.length;
    kept = kept.filter(f => f._confidence >= 60 || (f._cve && f._cve.kev));
    log('FP', `  🔒 Strict: ${before} → ${kept.length}`);
  }

  if (opts.paranoid) {
    const before = kept.length;
    kept = kept.filter(f => f._confidence >= 80 || (f._cve && f._cve.kev) || (f._vrt && f._vrt.p === 'P1'));
    log('FP', `  🛡️  Paranoid: ${before} → ${kept.length}`);
  }

  if (opts.verifyPoc) {
    const toVerify = kept.filter(f => ['critical', 'high'].includes(String((f.info && f.info.severity) || '').toLowerCase()));
    log('FP', `  🧪 Verifying ${toVerify.length} critical/high findings...`);
    for (const f of toVerify) {
      try {
        const r = await httpReq(f['matched-at'] || f.host, { timeout: 10000 });
        f._verify = {
          confirmed: r.status >= 200 && r.status < 500 && r.body.length > 0,
          status: r.status,
          ts: nowISO()
        };
        if (!f._verify.confirmed) f._confidence -= 30;
        await sleep(300);
      } catch {
        f._verify = { confirmed: false, status: 0, ts: nowISO() };
      }
    }
    const verified = kept.filter(f => f._verify && f._verify.confirmed).length;
    log('FP', `  ✓ ${verified}/${toVerify.length} confirmed`);
  }

  for (const f of kept) {
    f._confidence = clamp(f._confidence, 0, 100);
    f._verdict = f._confidence >= 75 ? 'high-confidence'
              : f._confidence >= 50 ? 'needs-review'
              : 'low-confidence';
  }

  log('FP', `✓ Final: ${kept.length} findings (avg confidence ${Math.round(kept.reduce((a, f) => a + f._confidence, 0) / Math.max(kept.length, 1))}%)`);
  return kept;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 7: CORE CLASSES
// ═══════════════════════════════════════════════════════════════════════════
class Checkpoint {
  constructor(dir) {
    this.file = path.join(dir, '.checkpoint.json');
    try {
      if (CFG.resume && fs.existsSync(this.file)) {
        this.state = JSON.parse(fs.readFileSync(this.file, 'utf-8'));
        log('CHECKPOINT', `↻ Resume: ${(this.state.done || []).length} batch selesai`);
      } else {
        this.state = { done: [], started: nowISO() };
      }
    } catch { this.state = { done: [], started: nowISO() }; }
    this._timer = setInterval(() => this.save(), 10000);
  }
  isDone(k) { return this.state.done.includes(k); }
  mark(k) { if (!this.state.done.includes(k)) { this.state.done.push(k); this.save(); } }
  save() { try { fs.writeFileSync(this.file, JSON.stringify(this.state, null, 2)); } catch {} }
  stop() { if (this._timer) clearInterval(this._timer); this.save(); }
}

class AdaptiveRateLimiter {
  constructor(rps) {
    this.baseRps = Math.max(0.1, rps);
    this.buckets = new Map();
    this.globalBackoff = 0;
    this.consecutive429 = new Map();
  }
  hostOf(t) { try { return new URL(t).hostname; } catch { return t; } }
  async acquire(target) {
    const now0 = Date.now();
    if (this.globalBackoff > now0) await sleep(this.globalBackoff - now0);
    const h = this.hostOf(target);
    const now = Date.now();
    if (!this.buckets.has(h)) this.buckets.set(h, { tokens: this.baseRps, last: now });
    const b = this.buckets.get(h);
    b.tokens = Math.min(this.baseRps, b.tokens + (now - b.last) / 1000 * this.baseRps);
    b.last = now;
    if (b.tokens < 1) {
      await sleep(((1 - b.tokens) / this.baseRps) * 1000);
      return this.acquire(target);
    }
    b.tokens -= 1;
  }
  reportStatus(target, status) {
    const h = this.hostOf(target);
    if (status === 429 || status === 503) {
      const n = (this.consecutive429.get(h) || 0) + 1;
      this.consecutive429.set(h, n);
      if (n >= 3) {
        log('RATE', `⚠️  ${h}: ${n}× 429 → global backoff 60s, rate halved`);
        this.globalBackoff = Date.now() + 60000;
        this.baseRps = Math.max(0.5, this.baseRps / 2);
        this.consecutive429.set(h, 0);
      }
    } else if (status === 200 || status === 301 || status === 302) {
      this.consecutive429.set(h, 0);
    }
  }
}

class ScopeGuard {
  constructor(allowFile, denyFile) {
    this.allow = allowFile && fs.existsSync(allowFile)
      ? fs.readFileSync(allowFile, 'utf-8').split(/\r?\n/).map(s => s.trim()).filter(l => l && !l.startsWith('#'))
      : null;
    this.deny = denyFile && fs.existsSync(denyFile)
      ? fs.readFileSync(denyFile, 'utf-8').split(/\r?\n/).map(s => s.trim()).filter(l => l && !l.startsWith('#'))
      : [];
    if (this.allow) log('SCOPE', `✓ Allowlist: ${this.allow.length}`);
    if (this.deny.length) log('SCOPE', `✓ Denylist: ${this.deny.length}`);
  }
  host(t) { try { return new URL(t).hostname.toLowerCase(); } catch { return t.toLowerCase(); } }
  match(h, pats) {
    return pats.some(p => {
      const pat = p.toLowerCase();
      if (pat === '*') return true;
      if (pat.startsWith('*.')) {
        const b = pat.slice(2);
        return h === b || h.endsWith('.' + b);
      }
      return h === pat || h.endsWith('.' + pat);
    });
  }
  isAllowed(t) {
    const h = this.host(t);
    if (this.deny.length && this.match(h, this.deny)) return false;
    if (this.allow && !this.match(h, this.allow)) return false;
    return true;
  }
  filter(ts) {
    return ts.filter(t => {
      if (this.isAllowed(t)) return true;
      log('SCOPE', `❌ Out-of-scope: ${t}`);
      return false;
    });
  }
}

class FindingDB {
  constructor(file) {
    this.file = file;
    try {
      this.data = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf-8')) : { scans: [], findings: {} };
    } catch { this.data = { scans: [], findings: {} }; }
  }
  key(f) { return sha(`${f['template-id']}|${f.host}|${f['matched-at']}`).slice(0, 32); }
  isDup(f) { return !!this.data.findings[this.key(f)]; }
  record(f) {
    try {
      const k = this.key(f);
      const ts = nowISO();
      if (!this.data.findings[k]) {
        this.data.findings[k] = {
          template: f['template-id'], host: f.host, matched: f['matched-at'],
          severity: f.info && f.info.severity, firstSeen: ts, lastSeen: ts, seenCount: 0
        };
      }
      this.data.findings[k].lastSeen = ts;
      this.data.findings[k].seenCount++;
    } catch {}
  }
  recordScan(findings) {
    const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => {
      const s = String((f.info && f.info.severity) || 'info').toLowerCase();
      if (stats[s] !== undefined) stats[s]++;
    });
    this.data.scans.push({ ts: nowISO(), total: findings.length, stats });
  }
  save() { try { fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2)); } catch {} }
  trend() {
    const s = this.data.scans.slice(-10);
    if (s.length < 2) return null;
    const first = s[0], last = s[s.length - 1];
    return { scans: s.length, trend: Object.keys(first.stats).reduce((o, k) => { o[k] = last.stats[k] - first.stats[k]; return o; }, {}) };
  }
  total() { return Object.keys(this.data.findings).length; }
}

class ProxyPool {
  constructor(file) {
    this.list = file && fs.existsSync(file)
      ? fs.readFileSync(file, 'utf-8').split(/\r?\n/).map(s => s.trim()).filter(s => s && !s.startsWith('#'))
      : [];
    this.dead = new Set();
    this.idx = 0;
  }
  get enabled() { return this.list.length > 0; }
  next() {
    const alive = this.list.filter(p => !this.dead.has(p));
    if (!alive.length) return null;
    return alive[this.idx++ % alive.length];
  }
  markDead(p) { if (p) this.dead.add(p); }
  async healthCheck() {
    if (!this.enabled) return;
    log('PROXY', `Health check ${this.list.length} proxy...`);
    for (const p of this.list) {
      if (!await this.probe(p)) { this.markDead(p); log('PROXY', `✗ ${p}`); }
    }
    log('PROXY', `✓ Alive: ${this.list.length - this.dead.size}/${this.list.length}`);
  }
  probe(proxy) {
    return new Promise(res => {
      try {
        const u = new URL(proxy.startsWith('http') ? proxy : `http://${proxy}`);
        const req = http.request({ host: u.hostname, port: u.port || 8080, method: 'CONNECT', path: 'www.google.com:443', timeout: 5000 });
        req.on('connect', () => { req.destroy(); res(true); });
        req.on('error', () => res(false));
        req.on('timeout', () => { req.destroy(); res(false); });
        req.end();
      } catch { res(false); }
    });
  }
}

class AuthFlow {
  constructor() {
    this.cookies = CFG.authCookie || '';
    this.token = CFG.authToken || '';
  }
  async login() {
    if (!CFG.authUrl) return;
    log('AUTH', `Login ke ${CFG.authUrl}`);
    try {
      const r = await httpReq(CFG.authUrl, {
        method: CFG.authMethod,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: CFG.authData,
        timeout: 15000
      });
      if (r.headers['set-cookie']) {
        this.cookies = r.headers['set-cookie'].map(c => c.split(';')[0]).join('; ');
        log('AUTH', `✓ Cookies obtained`);
      }
      const tok = r.body.match(/["'](?:token|access_token|jwt)["']\s*:\s*["']([^"']+)["']/i);
      if (tok) { this.token = tok[1]; log('AUTH', '✓ Token extracted'); }
    } catch (e) { log('AUTH', `⚠️  ${e.message}`); }
  }
  headers() {
    const h = [];
    if (this.cookies) h.push(`Cookie: ${this.cookies}`);
    if (this.token) h.push(`Authorization: Bearer ${this.token}`);
    return h;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 8: CONSTANTS FOR SCANNING
// ═══════════════════════════════════════════════════════════════════════════
const WAF_SIGS = [
  { name: 'Cloudflare', hdr: /cf-ray|cf-cache-status|cloudflare/i, strong: true },
  { name: 'Akamai', hdr: /akamai|x-akamai/i, strong: true },
  { name: 'AWS WAF', hdr: /x-amzn-requestid|x-amz-cf-id/i, strong: false },
  { name: 'Azure FD', hdr: /x-azure-ref|x-fd-/i, strong: true },
  { name: 'Fastly', hdr: /x-served-by.*fastly|fastly/i, strong: true },
  { name: 'Imperva', hdr: /x-iinfo|incap_ses/i, strong: true },
  { name: 'F5 BIG-IP', hdr: /bigipserver|ts[0-9a-f]{8}/i, strong: true },
  { name: 'Sucuri', hdr: /x-sucuri/i, strong: true }
];

const PERM_WORDS = [
  'dev', 'staging', 'stage', 'stg', 'test', 'testing', 'qa', 'uat', 'prod', 'preprod', 'preview',
  'demo', 'sandbox', 'lab', 'canary', 'beta', 'alpha', 'old', 'new',
  'api', 'api-v1', 'api-v2', 'api-v3', 'api-dev', 'api-stg',
  'internal', 'intranet', 'private', 'admin', 'portal', 'dashboard', 'panel', 'backend', 'frontend',
  'app', 'web', 'mobile', 'static', 'assets', 'cdn', 'media', 'img', 'files', 'upload', 'uploads',
  'docs', 'wiki', 'help', 'support', 'status', 'monitor', 'metrics',
  'grafana', 'kibana', 'jenkins', 'gitlab', 'git', 'ci', 'cd',
  'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
  'auth', 'sso', 'login', 'oauth', 'id', 'identity', 'account',
  'mail', 'smtp', 'webmail', 'mx', 'vpn', 'proxy', 'gateway',
  'backup', 'bak', 'archive', 'temp', 'tmp', 'cache',
  'blog', 'news', 'shop', 'store', 'payment', 'checkout',
  'k8s', 'kubernetes', 'docker', 'registry', 'jira', 'confluence'
];

const COMMON_DIRS = [
  '.git/HEAD', '.git/config', '.env', '.env.bak', '.env.local', '.env.production',
  'admin', 'administrator', 'admin.php', 'admin/login', 'wp-admin', 'wp-login.php',
  'config', 'config.php', 'config.json', 'config.yaml', 'config.yml',
  'backup', 'backups', 'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql', 'dump.sql',
  'phpinfo.php', 'info.php', 'test.php', 'debug', 'debug.log', 'server-status',
  'api', 'api/v1', 'api/v2', 'swagger.json', 'openapi.json', 'swagger-ui.html', 'api-docs', 'graphql', 'graphiql',
  'robots.txt', 'sitemap.xml', '.well-known/security.txt',
  '.htaccess', '.htpasswd', '.DS_Store', 'web.config', 'package.json', 'composer.json',
  'Dockerfile', 'docker-compose.yml', '.gitignore', 'README.md',
  'logs', 'log', 'error.log', 'access.log',
  'uploads', 'files', 'temp', 'tmp', 'cache', 'storage',
  'portal', 'dashboard', 'console', 'manage', 'management', 'cpanel',
  'jenkins', '.travis.yml', '.gitlab-ci.yml',
  'metrics', 'health', 'healthz', 'ping', 'status', 'version',
  'user', 'users', 'profile', 'account', 'login', 'signin', 'signup', 'register',
  'install', 'setup', 'upgrade', 'update', 'migrate', 'maintenance',
  'vendor', 'node_modules', 'dist', 'build', 'public', 'static',
  'id_rsa', '.ssh/id_rsa', '.aws/credentials', 'credentials', 'secrets',
  'key.pem', 'cert.pem', 'private.key', 'private.pem', 'server.key'
];

const JS_PATTERNS = [
  { name: 'AWS Access Key', re: /AKIA[0-9A-Z]{16}/g, sev: 'critical' },
  { name: 'Google API Key', re: /AIza[0-9A-Za-z\-_]{35}/g, sev: 'high' },
  { name: 'GitHub Token', re: /gh[pousr]_[A-Za-z0-9_]{36,255}/g, sev: 'critical' },
  { name: 'Slack Token', re: /xox[baprs]-[0-9a-zA-Z-]{10,}/g, sev: 'critical' },
  { name: 'Stripe Live', re: /sk_live_[0-9a-zA-Z]{24,}/g, sev: 'critical' },
  { name: 'SendGrid', re: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g, sev: 'high' },
  { name: 'Private Key', re: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, sev: 'critical' },
  { name: 'JWT', re: /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g, sev: 'high' },
  { name: 'Firebase URL', re: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g, sev: 'medium' },
  { name: 'MongoDB URI', re: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\/\s]+/gi, sev: 'critical' },
  { name: 'Postgres URI', re: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\/\s]+/gi, sev: 'critical' },
  { name: 'API Key', re: /(?:api[_-]?key|apikey)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]/gi, sev: 'medium' }
];

// ═══ IIS-SPECIFIC TESTS (NEW) ═══
const IIS_TESTS = [
  { name: 'web.config exposed',        path: '/web.config',           sev: 'critical', desc: 'Config file berisi DB password.', match: r => r.status === 200 && /<configuration|<connectionStrings|<appSettings/i.test(r.body) },
  { name: 'web.config.bak exposed',    path: '/web.config.bak',       sev: 'critical', desc: 'Backup config file.', match: r => r.status === 200 && r.body.length > 100 },
  { name: 'App_Data exposed',          path: '/App_Data/',            sev: 'critical', desc: 'Folder database ASP.NET.', match: r => r.status === 200 && (/Index of|Directory|\.mdf|\.ldf/i.test(r.body) || r.body.length < 200) },
  { name: 'App_Data web.config',       path: '/App_Data/web.config',  sev: 'high',     desc: 'DB config di App_Data.', match: r => r.status === 200 && /<configuration/i.test(r.body) },
  { name: 'trace.axd exposed',         path: '/trace.axd',            sev: 'critical', desc: 'ASP.NET trace log — bocorin session data.', match: r => r.status === 200 && /Application Trace|Trace Information|Physical Directory/i.test(r.body) },
  { name: 'elmah.axd exposed',         path: '/elmah.axd',            sev: 'critical', desc: 'Error log ASP.NET.', match: r => r.status === 200 && /Error Log|ELMAH|Powered by ELMAH/i.test(r.body) },
  { name: 'glimpse.axd exposed',       path: '/glimpse.axd',          sev: 'high',     desc: 'Glimpse debug panel.', match: r => r.status === 200 && /Glimpse|Turn Glimpse/i.test(r.body) },
  { name: 'bin/ directory listing',    path: '/bin/',                 sev: 'critical', desc: 'Folder DLL.', match: r => r.status === 200 && /Index of|Directory listing|<a href/i.test(r.body) },
  { name: 'bin/*.dll exposed',         path: '/bin/App_Code.dll',     sev: 'critical', desc: 'Compiled DLL.', match: r => r.status === 200 && r.body.length > 1000 },
  { name: 'aspnet_client exposed',     path: '/aspnet_client/',       sev: 'low',      desc: 'Folder standar ASP.NET.', match: r => r.status === 200 || r.status === 403 },
  { name: 'IIS shortname (~)',         path: '/~1',                  sev: 'medium',   desc: 'IIS tilde — bocorin nama file.', match: r => r.status === 200 || (r.status === 404 && !/404/.test(r.body)) },
  { name: 'Default.asp exposed',       path: '/default.asp',          sev: 'low',      desc: 'Halaman default ASP.', match: r => r.status === 200 },
  { name: 'iisstart.htm exposed',      path: '/iisstart.htm',         sev: 'low',      desc: 'Halaman default IIS.', match: r => r.status === 200 && /IIS Windows Server|Welcome/i.test(r.body) },
  { name: 'iisstart.png exposed',      path: '/iisstart.png',         sev: 'low',      desc: 'IIS default image.', match: r => r.status === 200 && (r.headers['content-type'] || '').includes('image') },
  { name: 'IIS version disclosure',    path: '/',                     sev: 'low',      desc: 'Version IIS di header.', match: r => /IIS\/[\d.]+/i.test(JSON.stringify(r.headers)) },
  { name: 'ASP.NET version in header', path: '/',                     sev: 'low',      desc: 'X-AspNet-Version header.', match: r => /X-AspNet-Version|x-powered-by.*asp/i.test(JSON.stringify(r.headers)) },
  { name: 'X-Powered-By disclosure',   path: '/',                     sev: 'low',      desc: 'X-Powered-By header.', match: r => !!r.headers['x-powered-by'] },
  { name: 'Server header IIS',         path: '/',                     sev: 'low',      desc: 'Server: Microsoft-IIS.', match: r => /Microsoft-IIS/i.test(r.headers.server || '') },
  { name: 'Global.asax exposed',       path: '/Global.asax',          sev: 'medium',   desc: 'Global application file.', match: r => r.status === 200 && /Application_|Session_/i.test(r.body) },
  { name: 'packages.config exposed',   path: '/packages.config',      sev: 'medium',   desc: 'NuGet packages.', match: r => r.status === 200 && /<packages|<package/i.test(r.body) },
  { name: 'Web.Debug.config',          path: '/Web.Debug.config',     sev: 'medium',   desc: 'Debug config.', match: r => r.status === 200 && /<configuration/i.test(r.body) },
  { name: 'Web.Release.config',        path: '/Web.Release.config',   sev: 'medium',   desc: 'Release config.', match: r => r.status === 200 && /<configuration/i.test(r.body) },
  { name: 'NLog.config',               path: '/NLog.config',          sev: 'low',      desc: 'Log config.', match: r => r.status === 200 && /<nlog/i.test(r.body) },
  { name: 'log4net.config',            path: '/log4net.config',       sev: 'low',      desc: 'Log4net config.', match: r => r.status === 200 && /<log4net/i.test(r.body) },
  { name: '.git/HEAD',                 path: '/.git/HEAD',            sev: 'critical', desc: 'Git repo exposed.', match: r => r.status === 200 && /ref:/i.test(r.body) },
  { name: '.env exposed',              path: '/.env',                 sev: 'critical', desc: 'Environment file.', match: r => r.status === 200 && /=\w/i.test(r.body) },
  { name: 'backup.zip',                path: '/backup.zip',           sev: 'high',     desc: 'Backup file.', match: r => r.status === 200 && r.body.length > 1000 },
  { name: 'db.sql',                    path: '/db.sql',               sev: 'critical', desc: 'Database dump.', match: r => r.status === 200 && /CREATE TABLE|INSERT INTO/i.test(r.body) }
];

const TAKEOVER_SIGS = [
  { name: 'AWS S3', body: /NoSuchBucket|does not exist/i, cname: /s3.*amazonaws|\.s3-website/i },
  { name: 'GitHub Pages', body: /There isn't a GitHub Pages site here/i, cname: /github\.io|github\.com/i },
  { name: 'Heroku', body: /No such app|herokucdn\.com\/error/i, cname: /herokuapp\.com/i },
  { name: 'Shopify', body: /Sorry, this shop is currently unavailable/i, cname: /myshopify\.com/i },
  { name: 'Fastly', body: /Fastly error: unknown domain/i, cname: /fastly\.net/i },
  { name: 'Azure', body: /404 Web Site not found|This site is temporarily unavailable/i, cname: /azurewebsites\.net|cloudapp\.net/i },
  { name: 'Netlify', body: /Not Found - Request ID/i, cname: /netlify\.app/i },
  { name: 'Vercel', body: /DEPLOYMENT_NOT_FOUND/i, cname: /vercel\.app/i }
];

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 9: RECON MODULES
// ═══════════════════════════════════════════════════════════════════════════
function loadTargets() {
  let lines = [];
  if (INPUT.isFile) {
    if (!fs.existsSync(INPUT.file)) throw new Error(`File not found: ${INPUT.file}`);
    lines = fs.readFileSync(INPUT.file, 'utf-8').split(/\r?\n/);
  } else lines = INPUT.domains;
  const targets = unique(
    lines.map(l => String(l).trim())
      .filter(l => l && !l.startsWith('#'))
      .map(l => /^https?:\/\//i.test(l) ? l : `https://${l}`)
  );
  if (!targets.length) throw new Error('Tidak ada target valid.');
  log('INFO', `Loaded ${targets.length} target`);
  return targets;
}

async function runRecon(targets) {
  log('RECON', `🛰️  Recon ${targets.length} target`);
  const dir = path.join(CFG.outputDir, 'recon');
  ensureDir(dir);
  const domains = unique(targets.map(t => {
    try { return new URL(t).hostname.replace(/^www\./, '').split('.').slice(-2).join('.'); }
    catch { return null; }
  }).filter(Boolean));
  const all = new Set(targets.map(t => { try { return new URL(t).hostname; } catch { return t; } }));

  if (toolExists(CFG.subfinderPath) && domains.length) {
    log('RECON', `→ subfinder`);
    const f = path.join(dir, 'subfinder.txt');
    fs.writeFileSync(path.join(dir, 'domains.txt'), domains.join('\n'));
    await new Promise(r => {
      try {
        const p = spawn(CFG.subfinderPath, ['-dL', path.join(dir, 'domains.txt'), '-silent', '-all', '-o', f], { stdio: 'ignore' });
        p.on('close', r); p.on('error', r);
        setTimeout(() => { try { p.kill(); } catch {} }, 300000);
      } catch { r(); }
    });
    if (fs.existsSync(f)) {
      fs.readFileSync(f, 'utf-8').split('\n').filter(Boolean).forEach(h => all.add(h.trim()));
    }
  }

  const result = [...all].map(h => `https://${h}`);
  let live = result;

  if (toolExists(CFG.httpxPath)) {
    log('RECON', `→ httpx`);
    const inF = path.join(dir, 'hosts_in.txt');
    const outF = path.join(dir, 'live.txt');
    fs.writeFileSync(inF, [...all].join('\n'));
    await new Promise(r => {
      try {
        const p = spawn(CFG.httpxPath, ['-l', inF, '-silent', '-o', outF, '-sc', '-title', '-td'], { stdio: 'ignore' });
        p.on('close', r); p.on('error', r);
        setTimeout(() => { try { p.kill(); } catch {} }, 300000);
      } catch { r(); }
    });
    if (fs.existsSync(outF)) {
      live = fs.readFileSync(outF, 'utf-8').split('\n')
        .map(l => l.trim().split(/\s+/)[0]).filter(Boolean)
        .map(h => h.startsWith('http') ? h : `https://${h}`);
    }
  }
  log('RECON', `✓ ${live.length} live host`);
  return unique(live);
}

async function ctLogs(targets) {
  log('CT', `🔐 CT logs`);
  const domains = unique(targets.map(t => {
    try { return new URL(t).hostname.replace(/^www\./, '').split('.').slice(-2).join('.'); }
    catch { return null; }
  }).filter(Boolean));
  const all = new Set();
  for (const d of domains.slice(0, 5)) {
    try {
      const r = await httpReq(`https://crt.sh/?q=%25.${d}&output=json`, { timeout: 25000 });
      if (r.body && r.body.startsWith('[')) {
        const rows = JSON.parse(r.body);
        rows.forEach(row => String(row.name_value || '').split('\n').forEach(n => {
          const h = n.trim().toLowerCase();
          if (h && !h.includes('*')) all.add(h);
        }));
        log('CT', `  ${d}: ${rows.length} entries`);
      }
    } catch {}
    await sleep(500);
  }
  log('CT', `✓ ${all.size} subdomain`);
  return [...all].map(h => `https://${h}`);
}

async function permute(targets) {
  log('PERMUTE', `🌱 Permutasi subdomain`);
  const candidates = new Set();
  for (const t of targets.slice(0, 30)) {
    try {
      const host = new URL(t).hostname;
      const parts = host.split('.');
      if (parts.length < 2) continue;
      const base = parts.slice(-2).join('.');
      const sub = parts.slice(0, -2).join('.');
      for (const w of PERM_WORDS) {
        candidates.add(`${w}.${base}`);
        if (sub) {
          candidates.add(`${sub}-${w}.${base}`);
          candidates.add(`${w}-${sub}.${base}`);
        }
      }
    } catch {}
  }
  log('PERMUTE', `→ ${candidates.size} kandidat`);
  const live = [];
  const arr = [...candidates];
  let idx = 0;
  async function worker() {
    while (idx < arr.length && live.length < 200) {
      const c = arr[idx++];
      try { await dns.resolve4(c); live.push(`https://${c}`); } catch {}
    }
  }
  await Promise.all(Array.from({ length: 30 }, worker));
  log('PERMUTE', `✓ ${live.length} live`);
  return live;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 10: ANALYSIS MODULES
// ═══════════════════════════════════════════════════════════════════════════

async function techFingerprint(targets) {
  log('TECH', `🧬 Tech fingerprint`);
  const out = [];
  const f = path.join(CFG.outputDir, 'tmp', 'tech.txt');
  ensureDir(path.dirname(f));
  fs.writeFileSync(f, targets.join('\n'));
  const args = ['-l', f, '-jsonl', '-silent', '-nc', '-no-color',
    '-tags', 'tech,detect,technologies', '-rl', '100', '-c', '20', '-timeout', '8', '-etags', 'dos,fuzz'];
  await new Promise(resolve => {
    try {
      const p = spawn(CFG.nucleiPath, args, { stdio: ['ignore', 'pipe', 'ignore'] });
      const rl = readline.createInterface({ input: p.stdout });
      rl.on('line', l => { try { out.push(JSON.parse(l)); } catch {} });
      p.on('close', () => { rl.close(); resolve(); });
      p.on('error', () => resolve());
    } catch { resolve(); }
  });
  log('TECH', `✓ ${out.length} findings`);
  return out;
}

async function jsSecrets(targets) {
  log('JS', `🧬 JS secrets + endpoints`);
  const findings = [];
  const endpoints = new Set();
  const seen = new Set();
  for (const t of targets.slice(0, 80)) {
    try {
      const base = await httpReq(t, { timeout: 8000 });
      if (!base.body) continue;
      const jsUrls = unique(
        (base.body.match(/<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi) || [])
          .map(m => m.match(/src=["']([^"']+)["']/)[1])
          .map(u => { try { return new URL(u, t).href; } catch { return null; } })
          .filter(Boolean)
      );
      for (const jsu of jsUrls.slice(0, 12)) {
        if (seen.has(jsu)) continue;
        seen.add(jsu);
        const r = await httpReq(jsu, { timeout: 10000 });
        if (!r.body) continue;
        for (const pat of JS_PATTERNS) {
          const m = r.body.match(pat.re);
          if (!m) continue;
          for (const val of unique(m).slice(0, 3)) {
            const masked = val.length > 60 ? val.slice(0, 25) + '...' + val.slice(-10) : val;
            log('JS', `  🚨 [${pat.sev.toUpperCase()}] ${pat.name}: ${masked}`);
            findings.push({
              'template-id': `js-secret-${pat.name.toLowerCase().replace(/\s+/g, '-')}`,
              'matched-at': jsu, host: t,
              info: { name: `JS Secret: ${pat.name}`, severity: pat.sev, tags: ['js-secret', 'exposure'], description: `${pat.name} in JS file.` },
              extracted_results: [masked]
            });
          }
        }
        if (CFG.jsEndpoints) {
          const eps = r.body.match(/["'`]((?:\/|https?:\/\/)[^"'`\s]{3,120})["'`]/g) || [];
          for (const mm of eps) {
            const ep = mm.slice(1, -1);
            if (/\.(png|jpg|gif|svg|css|woff|ttf|ico)/i.test(ep) || ep.length < 4) continue;
            try {
              const abs = new URL(ep, jsu).href;
              if (abs.includes(new URL(t).hostname)) endpoints.add(abs);
            } catch {}
          }
        }
      }
    } catch {}
    await sleep(150);
  }
  log('JS', `✓ ${findings.length} secrets, ${endpoints.size} endpoints`);
  return { findings, endpoints: [...endpoints] };
}

async function sourceMaps(targets) {
  log('SRCMAP', `🗺️  Source map hunt`);
  const findings = [];
  const seen = new Set();
  for (const t of targets.slice(0, 60)) {
    try {
      const base = await httpReq(t, { timeout: 8000 });
      if (!base.body) continue;
      const jsUrls = (base.body.match(/<script[^>]+src=["']([^"']+\.js)["']/gi) || [])
        .map(m => m.match(/src=["']([^"']+)["']/)[1])
        .map(u => { try { return new URL(u, t).href; } catch { return null; } })
        .filter(Boolean);
      for (const jsu of jsUrls.slice(0, 8)) {
        if (seen.has(jsu)) continue;
        seen.add(jsu);
        const mapUrl = jsu + '.map';
        const r = await httpReq(mapUrl, { timeout: 6000 });
        if (r.status !== 200 || !r.body.includes('"sources"')) continue;
        log('SRCMAP', `  🚨 ${mapUrl}`);
        findings.push({
          'template-id': 'source-map-exposed', 'matched-at': mapUrl, host: t,
          info: { name: 'Source Map Exposed', severity: 'medium', tags: ['source-map', 'exposure'], description: 'File .js.map tersedia.' }
        });
        try {
          const map = JSON.parse(r.body);
          const content = (map.sourcesContent || []).join('\n');
          for (const pat of JS_PATTERNS) {
            const m = content.match(pat.re);
            if (m) for (const val of unique(m).slice(0, 2)) {
              log('SRCMAP', `  🚨 [${pat.sev}] ${pat.name} in source map!`);
              findings.push({
                'template-id': `sourcemap-secret-${pat.name.toLowerCase().replace(/\s+/g, '-')}`,
                'matched-at': mapUrl, host: t,
                info: { name: `Source Map Secret: ${pat.name}`, severity: pat.sev, tags: ['source-map', 'secret', 'exposure'], description: `${pat.name} in source map.` },
                extracted_results: [val.slice(0, 80)]
              });
            }
          }
        } catch {}
      }
    } catch {}
    await sleep(150);
  }
  log('SRCMAP', `✓ ${findings.length}`);
  return findings;
}

async function takeoverCheck(targets) {
  log('TAKEOVER', `👻 Subdomain takeover`);
  const findings = [];
  for (const t of targets.slice(0, 150)) {
    try {
      const host = new URL(t).hostname;
      const cnames = await dns.resolveCname(host).catch(() => []);
      if (!cnames.length) continue;
      const cname = cnames[0];
      const sig = TAKEOVER_SIGS.find(s => s.cname.test(cname));
      if (!sig) continue;
      const r = await httpReq(t, { timeout: 6000 });
      if (sig.body.test(r.body) || r.status === 404) {
        log('TAKEOVER', `  🚨 ${host} → ${cname} (${sig.name})`);
        findings.push({
          'template-id': `subdomain-takeover-${sig.name.toLowerCase().replace(/\s+/g, '-')}`,
          'matched-at': t, host: t,
          info: { name: `Subdomain Takeover (${sig.name})`, severity: 'high', tags: ['subdomain-takeover', 'takeover'], description: `CNAME dangling ke ${sig.name}.` },
          extracted_results: [cname]
        });
      }
    } catch {}
    await sleep(100);
  }
  log('TAKEOVER', `✓ ${findings.length}`);
  return findings;
}

async function corsTest(targets) {
  log('CORS', `🌐 CORS misconfig`);
  const findings = [];
  for (const t of targets.slice(0, 60)) {
    let host;
    try { host = new URL(t).hostname; } catch { continue; }
    const origins = ['https://evil.com', `https://${host}.evil.com`, `https://evil.${host}`, `https://${host.replace('.', '.evil.')}`, 'null'];
    for (const o of origins) {
      try {
        const r = await httpReq(t, { headers: { Origin: o }, timeout: 5000 });
        const acao = r.headers['access-control-allow-origin'];
        const acac = r.headers['access-control-allow-credentials'];
        if (!acao) continue;
        const reflected = acao === o;
        const wildcard = acao === '*';
        const creds = acac === 'true';
        if ((reflected || wildcard) && creds) {
          log('CORS', `  🚨 ${t} | ${o} → ${acao}`);
          findings.push({
            'template-id': 'cors-with-credentials', 'matched-at': t, host: t,
            info: { name: 'CORS with Credentials', severity: 'high', tags: ['cors', 'misconfig'], description: `ACAO reflects ${o} + credentials.` },
            extracted_results: [`Origin: ${o}`, `ACAO: ${acao}`, `ACAC: ${acac}`]
          });
          break;
        }
        if (reflected && o.includes('evil')) {
          findings.push({
            'template-id': 'cors-reflected-origin', 'matched-at': t, host: t,
            info: { name: 'CORS Arbitrary Origin', severity: 'medium', tags: ['cors', 'misconfig'], description: `ACAO reflects ${o}.` },
            extracted_results: [`Origin: ${o}`, `ACAO: ${acao}`]
          });
          break;
        }
      } catch {}
      await sleep(50);
    }
  }
  log('CORS', `✓ ${findings.length}`);
  return findings;
}

async function graphqlTest(targets) {
  log('GRAPHQL', `🧬 GraphQL introspection`);
  const findings = [];
  const paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/gql'];
  const introspection = JSON.stringify({ query: '{ __schema { types { name } } }' });
  for (const t of targets.slice(0, 50)) {
    const base = t.replace(/\/$/, '');
    for (const p of paths) {
      const url = base + p;
      try {
        const r = await httpReq(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: introspection, timeout: 6000
        });
        if (r.status === 200 && /__schema|"types"/.test(r.body)) {
          log('GRAPHQL', `  🚨 ${url}`);
          findings.push({
            'template-id': 'graphql-introspection', 'matched-at': url, host: base,
            info: { name: 'GraphQL Introspection Enabled', severity: 'medium', tags: ['graphql', 'introspection'], description: 'Schema dapat di-enumerate.' }
          });
          break;
        }
      } catch {}
      await sleep(100);
    }
  }
  log('GRAPHQL', `✓ ${findings.length}`);
  return findings;
}

async function jwtTest(targets) {
  log('JWT', `🔑 JWT analyzer`);
  const findings = [];
  const re = /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g;
  for (const t of targets.slice(0, 50)) {
    try {
      const r = await httpReq(t, { timeout: 8000 });
      const found = (r.body + JSON.stringify(r.headers)).match(re) || [];
      for (const tok of unique(found).slice(0, 3)) {
        const parts = tok.split('.');
        let h = {};
        try { h = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); } catch {}
        const alg = String(h.alg || '').toLowerCase();
        if (alg === 'none' || !alg) {
          findings.push({
            'template-id': 'jwt-alg-none', 'matched-at': t, host: t,
            info: { name: 'JWT alg:none', severity: 'critical', tags: ['jwt', 'auth-bypass'], description: 'JWT tanpa signature.' }
          });
        }
        const noneH = Buffer.from(JSON.stringify({ ...h, alg: 'none' })).toString('base64url');
        const forged = `${noneH}.${parts[1]}.`;
        const test = await httpReq(t, { headers: { Authorization: `Bearer ${forged}` }, timeout: 5000 });
        if (test.status === 200 && !/invalid|unauthorized|expired/i.test(test.body)) {
          log('JWT', `  🚨 alg:none ACCEPTED: ${t}`);
          findings.push({
            'template-id': 'jwt-alg-none-accepted', 'matched-at': t, host: t,
            info: { name: 'JWT alg:none Accepted', severity: 'critical', tags: ['jwt', 'auth-bypass'], description: 'Server menerima token tanpa signature!' }
          });
        }
      }
    } catch {}
    await sleep(150);
  }
  log('JWT', `✓ ${findings.length}`);
  return findings;
}

async function dirBrute(targets) {
  log('DIR', `📁 Directory brute force`);
  const findings = [];
  for (const t of targets.slice(0, 20)) {
    try {
      const base = t.replace(/\/$/, '');
      const notfound = await httpReq(`${base}/${rand(24)}`, { timeout: 5000 });
      const bl = { status: notfound.status, len: notfound.body.length };
      log('DIR', `  Scanning ${base}`);

      const batches = chunk(COMMON_DIRS, 20);
      for (const batch of batches) {
        await Promise.all(batch.map(async p => {
          const url = `${base}/${p}`;
          try {
            const r = await httpReq(url, { timeout: 5000 });
            if (r.status === 0 || r.status === bl.status) return;
            if (r.status === 200 && Math.abs(r.body.length - bl.len) < 50) return;
            if (![200, 301, 302, 401, 403, 500].includes(r.status)) return;
            const interesting = r.status === 200 || r.status === 401 ||
              /\.(env|git|sql|bak|zip|log|json|yaml|pem|key)/i.test(p);
            if (!interesting) return;
            const sev = /\.env|\.git|id_rsa|credentials|\.sql|backup|private\.key|\.pem/i.test(p) ? 'high'
              : r.status === 200 ? 'medium' : 'low';
            log('DIR', `  [${r.status}] ${url} (${sev})`);
            findings.push({
              'template-id': 'exposed-path', 'matched-at': url, host: t,
              info: { name: `Exposed: /${p}`, severity: sev, tags: ['exposure', 'discovery'], description: `Path /${p} → ${r.status}` },
              extracted_results: [`Status: ${r.status}`]
            });
          } catch {}
        }));
        await sleep(150);
      }
    } catch {}
  }
  log('DIR', `✓ ${findings.length}`);
  return findings;
}

async function openapiScan(targets) {
  log('OPENAPI', `📄 OpenAPI/Swagger`);
  const findings = [];
  const specPaths = ['/openapi.json', '/swagger.json', '/api-docs', '/v2/api-docs', '/api/swagger.json', '/swagger/v1/swagger.json'];
  for (const t of targets.slice(0, 40)) {
    const base = t.replace(/\/$/, '');
    for (const p of specPaths) {
      try {
        const r = await httpReq(base + p, { timeout: 6000 });
        if (r.status !== 200) continue;
        if (!/"openapi"|"swagger"|"paths"/.test(r.body)) continue;
        log('OPENAPI', `  🚨 ${base + p}`);
        let spec;
        try { spec = JSON.parse(r.body); } catch { continue; }
        const paths = Object.keys(spec.paths || {});
        findings.push({
          'template-id': 'openapi-spec-exposed', 'matched-at': base + p, host: t,
          info: { name: 'OpenAPI Spec Exposed', severity: 'medium', tags: ['openapi', 'swagger', 'exposure'], description: `Spec dengan ${paths.length} endpoint.` },
          extracted_results: paths.slice(0, 30)
        });
        break;
      } catch {}
      await sleep(100);
    }
  }
  log('OPENAPI', `✓ ${findings.length}`);
  return findings;
}

async function httpMethodsTest(targets) {
  log('HTTPM', `🔧 HTTP methods`);
  const findings = [];
  const methods = ['OPTIONS', 'TRACE', 'PUT', 'DELETE'];
  for (const t of targets.slice(0, 30)) {
    for (const m of methods) {
      try {
        const r = await httpReq(t, { method: m, timeout: 6000 });
        if (r.status === 200 && m === 'TRACE') {
          findings.push({
            'template-id': 'http-trace-enabled', 'matched-at': t, host: t,
            info: { name: 'HTTP TRACE Enabled', severity: 'medium', tags: ['http', 'trace'], description: 'TRACE enabled → XST attack.' }
          });
        }
        if (r.status === 200 && m === 'PUT') {
          findings.push({
            'template-id': 'http-put-enabled', 'matched-at': t, host: t,
            info: { name: 'HTTP PUT Enabled', severity: 'high', tags: ['http', 'put'], description: 'PUT enabled.' }
          });
        }
      } catch {}
      await sleep(60);
    }
  }
  log('HTTPM', `✓ ${findings.length}`);
  return findings;
}

// ═══ IIS CHECK (NEW) ═══
async function iisCheck(targets) {
  log('IIS', `🎯 IIS-specific checks`);
  const findings = [];
  for (const t of targets.slice(0, 60)) {
    const base = t.replace(/\/$/, '');
    let baseline = { status: 0, len: 0 };
    try {
      const baseR = await httpReq(`${base}/${rand(24)}-notfound`, { timeout: 5000 });
      baseline = { status: baseR.status, len: baseR.body.length };
    } catch {}
    for (const test of IIS_TESTS) {
      const url = base + test.path;
      try {
        const r = await httpReq(url, { timeout: 8000 });
        if (r.status === baseline.status && Math.abs(r.body.length - baseline.len) < 50 && r.status !== 200) continue;
        if (test.match(r)) {
          const sevColor = { critical: C.red, high: C.mag, medium: C.yel, low: C.cyn, info: C.gry }[test.sev];
          log('IIS', `  ${sevColor}[${test.sev.toUpperCase()}]${C.r} ${test.name} → ${url}`);
          findings.push({
            'template-id': `iis-${test.name.toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '')}`,
            'matched-at': url, host: t,
            info: { name: `IIS: ${test.name}`, severity: test.sev, tags: ['iis', 'aspnet', 'microsoft', 'misconfig'], description: test.desc },
            extracted_results: [r.body.slice(0, 500)],
            response: r.body.slice(0, 1000),
            _iisTest: test.name
          });
        }
      } catch {}
      await sleep(80);
    }
  }
  log('IIS', `✓ ${findings.length} IIS findings`);
  return findings;
}

async function crawler(seeds, depth = 2, maxPages = 200) {
  log('CRAWL', `🕷️  Crawler depth=${depth}`);
  const seen = new Set();
  const found = new Set(seeds);
  const queue = seeds.map(u => ({ url: u, d: 0 }));
  while (queue.length && seen.size < maxPages) {
    const { url, d } = queue.shift();
    if (seen.has(url) || d > depth) continue;
    seen.add(url);
    try {
      const r = await httpReq(url, { timeout: 8000 });
      if (!r.body || r.status === 0) continue;
      const links = r.body.match(/<a[^>]+href=["']([^"']+)["']/gi) || [];
      const forms = r.body.match(/<form[^>]+action=["']([^"']+)["']/gi) || [];
      const all = [...links, ...forms].map(m => {
        const mm = m.match(/["']([^"']+)["']/);
        return mm ? mm[1] : null;
      }).filter(Boolean);
      for (const l of all) {
        try {
          const abs = new URL(l, url).href;
          if (new URL(abs).hostname !== new URL(url).hostname) continue;
          if (/\.(png|jpg|gif|svg|css|woff|ttf|ico|pdf|zip)/i.test(abs)) continue;
          if (!found.has(abs) && found.size < maxPages) {
            found.add(abs);
            if (d + 1 <= depth) queue.push({ url: abs, d: d + 1 });
          }
        } catch {}
      }
    } catch {}
    await sleep(100);
  }
  const result = [...found];
  log('CRAWL', `✓ ${result.length} URL`);
  ensureDir(path.join(CFG.outputDir, 'recon'));
  fs.writeFileSync(path.join(CFG.outputDir, 'recon', 'crawled.txt'), result.join('\n'));
  return result;
}

async function wafScan(targets) {
  log('WAF', `🛡️  WAF probe`);
  const skip = [];
  for (const t of targets.slice(0, 200)) {
    try {
      const r = await httpReq(t, { timeout: 6000, method: 'HEAD' });
      if (!r.status) continue;
      const hdr = JSON.stringify(r.headers).toLowerCase();
      const detected = WAF_SIGS.filter(w => w.hdr.test(hdr));
      if (detected.length) {
        const strong = detected.some(w => w.strong);
        log('WAF', `  ${t} → ${detected.map(w => w.name).join(', ')}${strong ? ' (strong)' : ''}`);
        if (strong) skip.push(t);
      }
    } catch {}
    await sleep(100);
  }
  log('WAF', `✓ ${skip.length} host akan di-skip`);
  return skip;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 11: NUCLEI RUNNER
// ═══════════════════════════════════════════════════════════════════════════
function checkNuclei() {
  try {
    const r = spawnSync(CFG.nucleiPath, ['-version'], { encoding: 'utf-8' });
    if (r.error) throw r.error;
    const verText = ((r.stdout || '') + (r.stderr || '')).trim().split('\n').find(l => /version/i.test(l)) || 'unknown';
    log('INFO', `Nuclei: ${verText}`);
    return true;
  } catch {
    log('ERROR', `❌ Nuclei tidak ada. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`);
    return false;
  }
}

async function updateTemplates() {
  if (CFG.skipUpdate) return;
  log('INFO', 'Update templates...');
  return new Promise(r => {
    try {
      const p = spawn(CFG.nucleiPath, ['-update-templates', '-silent', '-nc'], { stdio: 'ignore' });
      p.on('close', r);
      p.on('error', r);
      setTimeout(() => { try { p.kill(); } catch {} r(); }, 180000);
    } catch { r(); }
  });
}

async function nucleiScan(targets, rateLimiter, ckpt, auth, proxyPool) {
  const profile = PROFILES[CFG.profile];
  const batches = chunk(targets, CFG.batchSize);
  const all = [];
  let cursor = 0;

  log('INFO', `Nuclei: ${targets.length} host, ${batches.length} batch, ${CFG.workers} workers`);

  async function worker(wid) {
    while (cursor < batches.length) {
      const idx = cursor++;
      const ckKey = `batch_${idx}`;
      if (CFG.resume && ckpt.isDone(ckKey)) {
        log('CHECKPOINT', `[W${wid}] Skip batch ${idx + 1}`);
        continue;
      }
      const batch = batches[idx];
      const bFile = path.join(CFG.outputDir, 'tmp', `b_${idx}.txt`);
      ensureDir(path.dirname(bFile));
      fs.writeFileSync(bFile, batch.join('\n'));

      const args = ['-l', bFile, '-jsonl', '-severity', CFG.severity,
        '-rl', String(profile.rl), '-c', String(profile.c), '-timeout', String(profile.t), '-retries', String(profile.r),
        '-silent', '-nc', '-no-color'];
      if (CFG.excludeTags) args.push('-etags', CFG.excludeTags);
      if (CFG.includeTags) args.push('-tags', CFG.includeTags);
      if (CFG.templatesDir) args.push('-t', CFG.templatesDir);
      if (CFG.interactsh) args.push('-interactsh-url', '');
      else args.push('-no-interactsh');
      CFG.headers.forEach(h => args.push('-H', h));
      auth.headers().forEach(h => args.push('-H', h));
      profile.extra.forEach(e => args.push(e));

      const proxy = proxyPool.enabled ? proxyPool.next() : null;
      if (proxy) args.push('-proxy', proxy);

      if (CFG.dryRun) {
        log('INFO', `[DRY] ${CFG.nucleiPath} ${args.join(' ')}`);
        ckpt.mark(ckKey);
        continue;
      }

      await new Promise(resolve => {
        try {
          const proc = spawn(CFG.nucleiPath, args, { stdio: ['ignore', 'pipe', 'ignore'] });
          const rl = readline.createInterface({ input: proc.stdout });
          let count = 0;
          rl.on('line', line => {
            try {
              const j = JSON.parse(line);
              all.push(j);
              count++;
              const sev = String((j.info && j.info.severity) || 'unknown').toLowerCase();
              const sevColor = { critical: C.red, high: C.mag, medium: C.yel, low: C.cyn, info: C.gry, unknown: C.gry }[sev] || '';
              log('FINDING', `${sevColor}[${sev.toUpperCase()}]${C.r} ${j['template-id']} → ${j.host || j['matched-at']}`);
              rateLimiter.reportStatus(j.host || j['matched-at'] || '', 200);
            } catch {}
          });
          proc.on('close', () => {
            rl.close();
            try { fs.unlinkSync(bFile); } catch {}
            ckpt.mark(ckKey);
            log('INFO', `[W${wid}] Batch ${idx + 1}/${batches.length} (${count} findings)`);
            resolve();
          });
          proc.on('error', () => { rl.close(); resolve(); });
        } catch { resolve(); }
      });
    }
  }
  await Promise.all(Array.from({ length: Math.min(CFG.workers, batches.length) }, (_, i) => worker(i + 1)));
  return all;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 12: REPORTS
// ═══════════════════════════════════════════════════════════════════════════
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function buildHTML(findings, stats, trend) {
  const vstats = vrtStats(findings);
  const cstats = cveStats(findings);

  let cards = '';
  for (const p of ['P1', 'P2', 'P3', 'P4']) {
    const prio = VRT_PRIORITY[p];
    cards += `<div class="card" style="border-left-color:${prio.color}">
      <div class="n" style="color:${prio.color}">${vstats.stats[p]}</div>
      <div class="l">${prio.label}</div>
      <div class="b">$${vstats.bounty[p].toLocaleString()}</div>
    </div>`;
  }
  cards += `<div class="card" style="border-left-color:#ffb700">
    <div class="n" style="color:#ffb700">$${vstats.total.toLocaleString()}</div>
    <div class="l">TOTAL</div>
    <div class="b">${findings.length} findings</div>
  </div>`;

  const sorted = [...findings].sort((a, b) => {
    const pa = VRT_PRIORITY[a._vrt?.p || 'P5'].bounty[1];
    const pb = VRT_PRIORITY[b._vrt?.p || 'P5'].bounty[1];
    if (pa !== pb) return pb - pa;
    return (b._confidence || 0) - (a._confidence || 0);
  });

  let rows = '';
  for (const f of sorted) {
    const v = f._vrt || { p: 'P5', category: '-', vuln: f.info?.name || '-', variant: '', color: '#64748b' };
    const bounty = VRT_PRIORITY[v.p]?.bounty[1] || 0;
    const conf = f._confidence !== undefined ? `<span class="conf c${Math.round(f._confidence / 10)}">${f._confidence}%</span>` : '';
    const cveTag = f._cve
      ? `<div class="cve-tag">${f._cve.kev ? '🔥 ' : ''}${esc(f._cve.primary)}${f._cve.cvss ? ` · CVSS ${f._cve.cvss}` : ''}${f._cve.ransomware ? ' 🚨' : ''}</div>`
      : '';
    const kevRow = f._cve?.kev ? ' kev-row' : '';
    const verifyBadge = f._verify ? (f._verify.confirmed ? '<span class="vf ok">✓</span>' : '<span class="vf no">✗</span>') : '';
    rows += `<tr class="${kevRow}">
      <td><span class="vb" style="background:${v.color}22;color:${v.color};border:1px solid ${v.color}">${v.p}</span></td>
      <td class="bnt">$${bounty.toLocaleString()}</td>
      <td>${conf}</td>
      <td><code>${esc(f['template-id'])}</code>${cveTag}</td>
      <td>${esc(v.category)}</td>
      <td>${esc(v.vuln)}${v.variant ? ' — ' + esc(v.variant) : ''}</td>
      <td>${esc(f.host || '')}${verifyBadge}</td>
      <td><a href="${esc(f['matched-at'])}" target="_blank" rel="noopener">${esc(String(f['matched-at'] || '').slice(0, 60))}</a></td>
    </tr>`;
  }

  const trendHtml = trend ? `<section><h2>📈 Trend vs Previous Scans</h2><div class="trend">${
    Object.entries(trend.trend).map(([k, val]) => {
      const cls = val > 0 ? 'up' : val < 0 ? 'down' : 'flat';
      const arrow = val > 0 ? '📈' : val < 0 ? '📉' : '➖';
      return `<div class="tchip ${cls}">${arrow} <b>${k.toUpperCase()}</b> ${val > 0 ? '+' : ''}${val}</div>`;
    }).join('')
  }</div></section>` : '';

  const cveBlock = cstats.total ? `
    <section><h2>🛡️ CVE Intelligence</h2>
    <div class="stats">
      <div class="card"><div class="n">${cstats.total}</div><div class="l">CVE-LINKED</div></div>
      <div class="card"><div class="n">${cstats.uniq}</div><div class="l">UNIQUE CVEs</div></div>
      <div class="card" style="border-left-color:#ef4444"><div class="n" style="color:#ef4444">${cstats.kev}</div><div class="l">🔥 KEV (Exploited)</div></div>
      <div class="card" style="border-left-color:#ef4444"><div class="n" style="color:#ef4444">${cstats.ransomware}</div><div class="l">🚨 Ransomware</div></div>
      <div class="card"><div class="n">${cstats.avgCVSS}</div><div class="l">AVG CVSS</div></div>
    </div></section>` : '';

  const mods = Object.entries(stats).filter(([, v]) => v > 0).map(([k, v]) => `<div class="mod"><b>${esc(k)}</b>${v}</div>`).join('');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>🏆 ALHINDAWI HUNTER — Report</title>
<style>
:root{--bg:#0a0d13;--panel:#131822;--line:#232c3e;--txt:#e6e9f0;--mut:#8892a6;--accent:#4f9eff;--gold:#ffb700}
*{box-sizing:border-box}
body{margin:0;font:14px/1.55 system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--txt)}
header{padding:36px 44px;border-bottom:1px solid var(--line);background:linear-gradient(135deg,#0a0d13,#151e33)}
h1{margin:0;font-size:28px;letter-spacing:-.5px}
h1 .x{background:linear-gradient(90deg,#4f9eff,#ec4899);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.meta{color:var(--mut);margin-top:10px;font-size:13px}
main{padding:28px 44px;max-width:1600px;margin:0 auto}
section{margin-bottom:36px}
h2{font-size:17px;border-bottom:1px solid var(--line);padding-bottom:8px;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px}
.card{background:var(--panel);border-radius:10px;padding:18px;border-left:4px solid var(--line)}
.card .n{font-size:32px;font-weight:700}
.card .l{color:var(--mut);font-size:11px;letter-spacing:1.5px;margin-top:6px}
.card .b{color:var(--gold);font-size:13px;font-weight:600;margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:10px;overflow:hidden;font-size:12.5px}
th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line)}
th{background:#0f131b;color:var(--mut);text-transform:uppercase;font-size:10px;letter-spacing:1px;font-weight:600}
tr:hover{background:#1a2130}
code{background:#0f131b;padding:2px 6px;border-radius:4px;color:#93c5fd;font-size:11.5px;font-family:ui-monospace}
a{color:var(--accent);text-decoration:none}
.vb{padding:3px 9px;border-radius:6px;font-size:10px;font-weight:700}
.bnt{color:var(--gold);font-weight:700;text-align:center}
.conf{padding:2px 7px;border-radius:5px;font-size:10px;font-weight:700;background:#475569;color:#e5e7eb}
.conf.c7,.conf.c8,.conf.c9{background:#14532d;color:#bbf7d0}
.conf.c5,.conf.c6{background:#713f12;color:#fef08a}
.conf.c0,.conf.c1,.conf.c2,.conf.c3,.conf.c4{background:#7f1d1d;color:#fecaca}
.total{background:radial-gradient(circle at 30% 30%,#1e2740,#0d1220);padding:32px;border-radius:16px;text-align:center;border:1px solid var(--line);margin-bottom:24px}
.total .big{font-size:48px;font-weight:800;background:linear-gradient(90deg,#ffb700,#ec4899);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.total .lbl{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:3px;margin-bottom:6px}
.modgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
.mod{background:var(--panel);padding:12px 16px;border-radius:8px;font-size:12px;border-left:3px solid #ec4899}
.mod b{color:var(--accent);display:block;font-size:11px;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}
.trend{display:flex;gap:10px;flex-wrap:wrap}
.tchip{padding:8px 16px;border-radius:8px;background:var(--panel);font-size:13px;border:1px solid var(--line)}
.tchip.up{border-color:#ef4444;color:#fecaca}
.tchip.down{border-color:#10b981;color:#a7f3d0}
.tchip.flat{border-color:#475569;color:#94a3b8}
.cve-tag{margin-top:4px;font-size:10.5px;color:#fbbf24;font-family:ui-monospace}
.kev-row{background:linear-gradient(90deg,rgba(239,68,68,0.08),transparent)!important;border-left:3px solid #ef4444}
.vf{font-size:11px;padding:1px 5px;border-radius:3px;margin-left:4px;font-weight:700}
.vf.ok{background:#14532d;color:#bbf7d0}
.vf.no{background:#7f1d1d;color:#fecaca}
footer{color:var(--mut);text-align:center;padding:24px;font-size:12px;border-top:1px solid var(--line);margin-top:40px}
@media print{body{background:#fff;color:#000}header,main,.total,.card,table{background:#fff!important;color:#000!important;border-color:#ccc!important}}
</style></head><body>
<header>
<h1>🏆 ALHINDAWI HUNTER <span class="x">v10.0 FUSION</span></h1>
<div class="meta">by <b>ALHINDAWI</b> · Generated: <b>${esc(nowISO())}</b> · Profile: <b>${esc(CFG.profile)}</b> · Bugcrowd VRT v1.19</div>
</header>
<main>
<section><h2>📊 Bugcrowd VRT Summary</h2><div class="stats">${cards}</div></section>
<section><div class="total"><div class="lbl">💰 Estimated Bounty</div><div class="big">$${vstats.total.toLocaleString()}</div></div></section>
${cveBlock}
${trendHtml}
${mods ? `<section><h2>🔧 Modules Activated</h2><div class="modgrid">${mods}</div></section>` : ''}
<section><h2>📋 Findings (${findings.length}) — sorted by VRT priority</h2>
<table><thead><tr><th>VRT</th><th>Bounty</th><th>Conf</th><th>Template</th><th>Category</th><th>Vulnerability</th><th>Host</th><th>Matched</th></tr></thead>
<tbody>${rows}</tbody></table></section>
</main>
<footer>🏆 <b>ALHINDAWI HUNTER v10.0 FUSION</b> · by <b>ALHINDAWI</b> · Nuclei + VRT + CVE Intel + FP Engine</footer>
</body></html>`;
}

function buildBugcrowdReport(f) {
  const vrt = f._vrt || mapToVRT(f);
  const prio = VRT_PRIORITY[vrt.p];
  const url = f['matched-at'] || f.host;
  const evidence = (f.extracted_results || []).join('\n') || 'See raw JSON';
  const cveBlock = f._cve ? `
## 🛡️ CVE Intelligence

**CVE:** ${f._cve.ids.join(', ')}  
**CVSS v3.1:** ${f._cve.cvss || 'N/A'} (${String(f._cve.severity || '').toUpperCase()})${f._cve.kev ? '  \n**🔥 CISA KEV — Exploited in the Wild**' : ''}${f._cve.ransomware ? '  \n**🚨 Used in ransomware campaigns**' : ''}
${f._cve.vendor ? `**Vendor:** ${f._cve.vendor}  ` : ''}
${f._cve.product ? `**Product:** ${f._cve.product}  ` : ''}

${f._cve.description}
` : '';

  return `# ${vrt.vuln}${vrt.variant ? ' — ' + vrt.variant : ''}

**Priority:** ${prio.label}  
**Confidence:** ${f._confidence || '?'}% (${f._verdict || 'unclassified'})  
**VRT Category:** ${vrt.category}  
**VRT Vulnerability:** ${vrt.vuln}  
**VRT Variant:** ${vrt.variant || 'N/A'}  
**CVSS Range:** ${prio.cvss[0]} – ${prio.cvss[1]}  
**Estimated Bounty:** $${prio.bounty[1]} (max $${prio.bounty[2]})

**Asset:** \`${f.host}\`  
**Endpoint:** \`${url}\`  
**Template:** \`${f['template-id']}\`
${cveBlock}
---

## Summary

${(f.info && f.info.description) || `${vrt.vuln} terdeteksi pada asset.`}

## Steps to Reproduce

1. Akses endpoint: \`${url}\`
2. Amati indikator:

\`\`\`
${String(evidence).slice(0, 1500)}
\`\`\`

3. Verifikasi:
\`\`\`bash
curl -s '${url}' \\
  -H 'User-Agent: Mozilla/5.0 (compatible; SecurityResearch)'
\`\`\`

## Impact

Berdasarkan Bugcrowd VRT, temuan ini diklasifikasikan sebagai **${vrt.category} → ${vrt.vuln}** dengan prioritas **${vrt.p}**.

${(f.info && f.info.impact) || 'Attacker dapat mengeksploitasi temuan untuk mendapatkan akses tidak sah atau mengungkap data sensitif.'}

## Remediation

${(f.info && f.info.remediation) || VRT_REMEDIATION[vrt.vuln] || 'Apply vendor patch / configuration hardening.'}

## References

- Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy
- Category: \`${vrt.category}\`
- Vulnerability: \`${vrt.vuln}\`
- Tags: ${((f.info && f.info.tags) || []).join(', ') || 'N/A'}

---

*Discovered by ALHINDAWI HUNTER v10.0 — by ALHINDAWI*
`;
}

function buildBugcrowdSummary(findings) {
  const vs = vrtStats(findings);
  let md = `# 🎯 Bugcrowd VRT Report\n\n`;
  md += `**By:** ALHINDAWI HUNTER v10.0  \n`;
  md += `**Generated:** ${nowISO()}  \n`;
  md += `**VRT Version:** 1.19  \n\n`;
  md += `## 📊 Executive Summary\n\n`;
  md += `| Priority | CVSS | Count | Est. Bounty |\n|----------|------|-------|-------------|\n`;
  for (const p of ['P1', 'P2', 'P3', 'P4']) {
    if (vs.stats[p] === 0) continue;
    md += `| **${VRT_PRIORITY[p].label}** | ${VRT_PRIORITY[p].cvss.join('–')} | ${vs.stats[p]} | $${vs.bounty[p].toLocaleString()} |\n`;
  }
  md += `| | | **${findings.length}** | **$${vs.total.toLocaleString()}** |\n\n`;

  const byCategory = {};
  for (const f of findings) {
    const cat = (f._vrt && f._vrt.category) || 'Uncategorized';
    (byCategory[cat] = byCategory[cat] || []).push(f);
  }
  md += `## 📋 Findings by VRT Category\n\n`;
  for (const [cat, list] of Object.entries(byCategory)) {
    md += `### ${cat} (${list.length})\n\n`;
    for (const f of list) {
      const v = f._vrt;
      md += `- **[${v.p}] ${v.vuln}**${v.variant ? ' — ' + v.variant : ''}  \n`;
      md += `  - Host: \`${f.host}\`  \n`;
      md += `  - Endpoint: \`${f['matched-at'] || '-'}\`  \n`;
      md += `  - Confidence: ${f._confidence || '?'}%  \n`;
      md += `  - Est. bounty: $${VRT_PRIORITY[v.p].bounty[1].toLocaleString()}\n\n`;
    }
  }
  md += `\n---\n\n*Report by **ALHINDAWI HUNTER v10.0** — Manual reproduction required before submission.*\n`;
  return md;
}

function buildCVESummary(findings) {
  const s = cveStats(findings);
  let md = `# 🛡️ CVE Intelligence Summary\n\n`;
  md += `**By:** ALHINDAWI HUNTER v10.0  \n`;
  md += `**Generated:** ${nowISO()}  \n\n`;
  md += `## 📊 Statistics\n\n`;
  md += `- **CVE-linked findings:** ${s.total}\n`;
  md += `- **Unique CVEs:** ${s.uniq}\n`;
  md += `- **CISA KEV:** ${s.kev} 🔥\n`;
  md += `- **Ransomware-linked:** ${s.ransomware} 🚨\n`;
  md += `- **Average CVSS:** ${s.avgCVSS}\n\n`;
  md += `## 📈 By Severity\n\n| Severity | Count |\n|----------|-------|\n`;
  for (const [sev, n] of Object.entries(s.bySeverity)) {
    if (n) md += `| ${sev.toUpperCase()} | ${n} |\n`;
  }
  md += `\n`;
  const kevFindings = findings.filter(f => f._cve?.kev);
  if (kevFindings.length) {
    md += `## 🔥 CISA KEV — Exploited in the Wild (${kevFindings.length})\n\n`;
    for (const f of kevFindings) {
      md += `### ${f._cve.primary}${f._cve.ransomware ? ' 🚨 RANSOMWARE' : ''}\n`;
      md += `- **CVSS:** ${f._cve.cvss || 'N/A'}\n`;
      md += `- **Host:** \`${f.host}\`\n`;
      md += `- **Endpoint:** \`${f['matched-at']}\`\n`;
      md += `- **Description:** ${String(f._cve.description || '').slice(0, 300)}\n\n`;
    }
  }
  return md;
}

function buildSarif(findings) {
  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name: 'ALHINDAWI HUNTER',
          version: '10.0',
          informationUri: 'https://github.com/projectdiscovery/nuclei',
          rules: unique(findings.map(f => f['template-id'])).map(id => ({ id, name: id }))
        }
      },
      results: findings.map(f => ({
        ruleId: f['template-id'],
        level: ({ P1: 'error', P2: 'error', P3: 'warning', P4: 'note', P5: 'note' })[f._vrt?.p] || 'warning',
        message: { text: `${(f._vrt && f._vrt.vuln) || (f.info && f.info.name) || f['template-id']} at ${f['matched-at'] || f.host}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f['matched-at'] || f.host || 'unknown' } } }]
      }))
    }]
  };
}

function buildJunit(findings) {
  const escXml = s => String(s).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));
  const byHost = {};
  for (const f of findings) (byHost[f.host || 'unknown'] = byHost[f.host || 'unknown'] || []).push(f);
  let xml = `<?xml version="1.0" encoding="UTF-8"?>\n<testsuites tests="${findings.length}" failures="${findings.length}">\n`;
  for (const [host, list] of Object.entries(byHost)) {
    xml += `  <testsuite name="${escXml(host)}" tests="${list.length}" failures="${list.length}">\n`;
    for (const f of list) {
      xml += `    <testcase name="${escXml(f['template-id'])}" classname="${escXml(host)}">\n`;
      xml += `      <failure message="${escXml((f.info && f.info.name) || '')}" type="${escXml(f._vrt?.p || 'unknown')}">${escXml(f['matched-at'] || '')}</failure>\n`;
      xml += `    </testcase>\n`;
    }
    xml += `  </testsuite>\n`;
  }
  xml += `</testsuites>`;
  return xml;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 13: DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════
function startDashboard() {
  const server = http.createServer((req, res) => {
    if (req.url === '/api/feed') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify(liveBus.slice(-200)));
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!doctype html><html><head><meta charset="utf-8"><title>🏆 ALHINDAWI HUNTER — Live</title>
<style>
body{font-family:system-ui;background:#0a0d13;color:#e6e9f0;margin:0;padding:20px}
h1{background:linear-gradient(90deg,#4f9eff,#ec4899);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin:0 0 6px}
.meta{color:#8892a6;font-size:13px;margin-bottom:16px}
.feed{background:#131822;padding:16px;border-radius:10px;font-family:ui-monospace;font-size:12.5px;line-height:1.7;height:82vh;overflow-y:auto}
.line{padding:3px 0;border-bottom:1px solid #1a2130}
.lvl{display:inline-block;min-width:100px;padding:1px 8px;border-radius:4px;font-size:10px;font-weight:700;margin-right:8px}
.INFO{background:#1e3a8a;color:#bfdbfe}.FINDING{background:#14532d;color:#bbf7d0}
.WARN,.WAF,.DIR,.RATE,.FP{background:#713f12;color:#fef08a}
.ERROR,.TAKEOVER{background:#7f1d1d;color:#fecaca}
.RECON,.PERMUTE,.CT,.CRAWL,.TECH,.OPENAPI,.PROXY,.AUTH,.DASH{background:#0e7490;color:#cffafe}
.CORS,.GRAPHQL,.JWT,.JS,.SRCMAP,.NOTIFY,.IIS{background:#831843;color:#fbcfe8}
.CVE{background:#4a044e;color:#f5d0fe}.VRT{background:#14532d;color:#bbf7d0}
</style></head><body>
<h1>🏆 ALHINDAWI HUNTER v10.0 FUSION — Live</h1>
<div class="meta">by ALHINDAWI · Bugcrowd VRT v1.19 · <span id="cnt">0 events</span></div>
<div class="feed" id="feed"></div>
<script>
const f=document.getElementById('feed'),s=new Set();let c=0;
setInterval(async()=>{try{
const r=await fetch('/api/feed');const d=await r.json();
for(const e of d){const k=e.ts+e.msg;if(s.has(k))continue;s.add(k);c++;
const el=document.createElement('div');el.className='line';
el.innerHTML='<span class="lvl '+e.lvl+'">'+e.lvl+'</span>'+e.msg.replace(/</g,'&lt;');
f.appendChild(el)}
document.getElementById('cnt').textContent=c+' events';f.scrollTop=f.scrollHeight}catch(e){}},1200);
</script></body></html>`);
  });
  server.listen(CFG.dashboardPort, () => log('DASH', `📊 Live: http://localhost:${CFG.dashboardPort}`));
  return server;
}

// ═══════════════════════════════════════════════════════════════════════════
//  SECTION 14: MAIN
// ═══════════════════════════════════════════════════════════════════════════
async function main() {
  console.log(`${C.cyn}${C.b}`);
  console.log('╔═══════════════════════════════════════════════════════════════════════╗');
  console.log('║                                                                       ║');
  console.log('║        🏆  A L H I N D A W I   H U N T E R   v10.0   🏆              ║');
  console.log('║                                                                       ║');
  console.log('║     Nuclei + Bugcrowd VRT v1.19 + CVE Intel + FP Reduction            ║');
  console.log('║                                                                       ║');
  console.log('║     by ALHINDAWI                                                      ║');
  console.log('║                                                                       ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════╝');
  console.log(`${C.r}`);
  console.log(`${C.yel}⚠️  LEGAL: Scan hanya target dengan izin tertulis.${C.r}\n`);

  if (!checkNuclei()) process.exit(1);

  ensureDir(CFG.outputDir);
  initLogger(CFG.outputDir);
  log('INFO', `Profile: ${CFG.profile} · Rate: ${CFG.rate} req/s · Workers: ${CFG.workers}`);
  if (CFG.vrt) log('VRT', `Bugcrowd VRT v1.19 · P5 ${CFG.vrtExcludeP5 ? 'excluded' : 'included'}`);
  if (CFG.fpParanoid) log('FP', `🛡️  Paranoid mode`);
  else if (CFG.fpStrict) log('FP', `🔒 Strict mode`);

  const scope = new ScopeGuard(CFG.scopeAllow, CFG.scopeDeny);
  const auth = new AuthFlow();
  await auth.login();
  const proxyPool = new ProxyPool(CFG.proxyFile);
  await proxyPool.healthCheck();
  const db = new FindingDB(path.join(CFG.outputDir, 'findings_db.json'));
  log('DUP', `📚 Finding DB: ${db.total()} total lintas sesi`);

  const cveDB = new CVEDatabase();
  const cveCache = path.join(CFG.outputDir, 'cve_cache.json');
  if (CFG.cveCache && fs.existsSync(cveCache)) {
    if (cveDB.load(cveCache)) log('CVE', `📚 CVE cache loaded: ${cveDB.size()}`);
  }
  if (CFG.cveFeed) {
    let n = 0;
    try {
      if (fs.statSync(CFG.cveFeed).isDirectory()) n = cveDB.loadFromFolder(CFG.cveFeed);
      else if (CFG.cveFeed.endsWith('.json')) n = cveDB.loadFromJSONFile(CFG.cveFeed);
      else n = cveDB.loadFromTextFile(CFG.cveFeed);
      log('CVE', `📥 ${n} CVE dari ${CFG.cveFeed}`);
    } catch (e) { log('CVE', `⚠️  ${e.message}`); }
  }
  if (CFG.cveFetchKEV) {
    log('CVE', `🔥 Fetching CISA KEV...`);
    const n = await cveDB.loadKEV();
    log('CVE', `✓ KEV: ${n} known exploited vulnerabilities`);
  }

  let targets = loadTargets();
  targets = scope.filter(targets);

  if (CFG.dashboard) startDashboard();

  const allFindings = [];
  const stats = {};
  const ckpt = new Checkpoint(CFG.outputDir);

  // ══ RECON PHASE ══
  if (CFG.recon) { targets = await runRecon(targets); stats['Recon'] = targets.length; }
  if (CFG.ctLogs) { const ct = await ctLogs(targets); targets = unique([...targets, ...ct]); stats['CT'] = ct.length; }
  if (CFG.permute) { const p = await permute(targets); targets = unique([...targets, ...p]); stats['Permute'] = p.length; }
  targets = scope.filter(targets);
  log('INFO', `Targets final: ${targets.length}`);

  if (CFG.crawler) {
    const c = await crawler(targets.slice(0, 20), 2, 200);
    stats['Crawl'] = c.length;
    targets = unique([...targets, ...c]);
  }

  if (targets.length > 3) {
    const wafSkip = await wafScan(targets);
    if (wafSkip.length) {
      targets = targets.filter(t => !wafSkip.includes(t));
      stats['WAF-skip'] = wafSkip.length;
    }
  }

  // ══ ANALYSIS PHASE ══
  if (CFG.tech) { const r = await techFingerprint(targets); allFindings.push(...r); stats['Tech'] = r.length; }
  if (CFG.jsSecrets || CFG.jsEndpoints) {
    const r = await jsSecrets(targets);
    allFindings.push(...r.findings);
    stats['JS'] = r.findings.length;
    if (CFG.jsEndpoints && r.endpoints.length) {
      targets = unique([...targets, ...r.endpoints]);
      stats['JS-EP'] = r.endpoints.length;
    }
  }
  if (CFG.sourceMaps) { const r = await sourceMaps(targets); allFindings.push(...r); stats['SrcMap'] = r.length; }
  if (CFG.takeover) { const r = await takeoverCheck(targets); allFindings.push(...r); stats['Takeover'] = r.length; }
  if (CFG.cors) { const r = await corsTest(targets); allFindings.push(...r); stats['CORS'] = r.length; }
  if (CFG.graphql) { const r = await graphqlTest(targets); allFindings.push(...r); stats['GraphQL'] = r.length; }
  if (CFG.jwt) { const r = await jwtTest(targets); allFindings.push(...r); stats['JWT'] = r.length; }
  if (CFG.dirBrute) { const r = await dirBrute(targets); allFindings.push(...r); stats['Dir'] = r.length; }
  if (CFG.openapi) { const r = await openapiScan(targets); allFindings.push(...r); stats['OpenAPI'] = r.length; }
  if (CFG.httpMethods) { const r = await httpMethodsTest(targets); allFindings.push(...r); stats['HTTP'] = r.length; }
  if (CFG.iisCheck) { const r = await iisCheck(targets); allFindings.push(...r); stats['IIS'] = r.length; }

  // ══ NUCLEI ══
  await updateTemplates();
  const rateLimiter = new AdaptiveRateLimiter(CFG.rate);
  const nf = await nucleiScan(targets, rateLimiter, ckpt, auth, proxyPool);
  allFindings.push(...nf);
  stats['Nuclei'] = nf.length;
  ckpt.stop();

  // ══ DEDUP ══
  const seen = new Set();
  let findings = [];
  for (const f of allFindings) {
    const k = `${f['template-id']}|${f.host}|${f['matched-at']}`;
    if (!seen.has(k)) { seen.add(k); findings.push(f); }
  }
  log('INFO', `Total unik: ${findings.length}`);

  const novel = findings.filter(f => !db.isDup(f));
  findings.forEach(f => db.record(f));
  db.recordScan(findings);
  db.save();
  stats['Novel'] = novel.length;
  stats['Dup'] = findings.length - novel.length;
  findings = novel;

  // ══ VRT ENRICHMENT ══
  if (CFG.vrt) {
    findings = enrichWithVRT(findings);
    if (CFG.vrtExcludeP5) {
      const before = findings.length;
      findings = findings.filter(f => f._vrt.p !== 'P5');
      const dropped = before - findings.length;
      if (dropped) log('VRT', `Dropped ${dropped} P5 informational`);
    }
  }

  // ══ CVE ENRICHMENT ══
  if (cveDB.size() > 0 || CFG.cveFetchNVD) {
    if (CFG.cveFetchNVD) {
      const toFetch = new Set();
      for (const f of findings) {
        for (const id of extractCVEIds(f)) {
          if (!cveDB.has(id) || !cveDB.get(id).cvss) toFetch.add(id);
        }
      }
      const list = [...toFetch].slice(0, CFG.cveBulkLimit);
      if (list.length) {
        log('CVE', `🌐 Fetching ${list.length} CVEs from NVD...`);
        for (const id of list) {
          await cveDB.fetchNVD(id, CFG.cveAPIKey);
          await sleep(CFG.cveAPIKey ? 700 : 6500);
        }
      }
    }

    findings = enrichFindingsWithCVE(findings, cveDB);
    const cveLinked = findings.filter(f => f._cve).length;
    log('CVE', `🎯 ${cveLinked}/${findings.length} findings ter-link ke CVE`);

    if (CFG.cveOverride) {
      findings = applyCVEOverride(findings);
      const kevCount = findings.filter(f => f._cve?.kev).length;
      if (kevCount) log('CVE', `🔥 ${kevCount} findings KEV (priority overridden)`);
    }

    if (CFG.cveKEVOnly) {
      findings = findings.filter(f => f._cve?.kev);
      log('CVE', `🎯 KEV-only: ${findings.length}`);
    } else if (CFG.cveOnly) {
      findings = findings.filter(f => f._cve);
      log('CVE', `🎯 CVE-only: ${findings.length}`);
    } else if (CFG.cveMinCVSS) {
      findings = findings.filter(f => !f._cve || (f._cve.cvss || 0) >= CFG.cveMinCVSS);
      log('CVE', `🎯 Min CVSS ${CFG.cveMinCVSS}: ${findings.length}`);
    }

    if (CFG.cveCache) cveDB.save(cveCache);
  }

  // ══ FP REDUCTION ══
  findings = await reduceFalsePositives(findings, {
    strict: CFG.fpStrict,
    paranoid: CFG.fpParanoid,
    verifyPoc: CFG.verifyPoc
  });

  // ══ STATS + REPORTS ══
  const cs = cveStats(findings);
  stats['CVE-linked'] = cs.total;
  stats['CVE-uniq'] = cs.uniq;
  stats['CVE-KEV'] = cs.kev;
  if (cs.ransomware) stats['CVE-Ransomware'] = cs.ransomware;

  const vs = vrtStats(findings);
  stats['VRT-P1'] = vs.stats.P1;
  stats['VRT-P2'] = vs.stats.P2;
  stats['VRT-P3'] = vs.stats.P3;
  stats['VRT-P4'] = vs.stats.P4;

  const trend = db.trend();

  const rd = path.join(CFG.outputDir, 'reports');
  ensureDir(rd);

  fs.writeFileSync(path.join(rd, 'findings.json'), JSON.stringify(findings, null, 2));
  fs.writeFileSync(path.join(rd, 'report.html'), buildHTML(findings, stats, trend));

  if (CFG.vrt && CFG.vrtReport) {
    const bcDir = path.join(rd, 'bugcrowd');
    ensureDir(bcDir);
    fs.writeFileSync(path.join(rd, 'bugcrowd_summary.md'), buildBugcrowdSummary(findings));
    for (const f of findings.filter(f => ['P1', 'P2', 'P3'].includes(f._vrt?.p))) {
      const name = `${f._vrt.p}_${f._vrt.vuln.replace(/[^a-z0-9]+/gi, '_')}_${sha(f.host || '').slice(0, 6)}.md`;
      fs.writeFileSync(path.join(bcDir, name), buildBugcrowdReport(f));
    }
    fs.writeFileSync(path.join(rd, 'bugcrowd_findings.json'),
      JSON.stringify(findings.map(f => ({
        vrt: f._vrt, host: f.host, endpoint: f['matched-at'],
        template: f['template-id'], confidence: f._confidence,
        severity: f.info?.severity
      })), null, 2));
    log('VRT', `📄 Bugcrowd reports → reports/bugcrowd/ + bugcrowd_summary.md`);
  }

  if (cveDB.size() > 0) {
    const cveDir = path.join(rd, 'cve');
    ensureDir(cveDir);
    fs.writeFileSync(path.join(rd, 'cve_summary.md'), buildCVESummary(findings));
    fs.writeFileSync(path.join(rd, 'cve_findings.json'),
      JSON.stringify(findings.filter(f => f._cve).map(f => ({
        cve: f._cve, host: f.host, endpoint: f['matched-at'],
        template: f['template-id'], vrt: f._vrt?.p
      })), null, 2));
    log('CVE', `📄 CVE reports → reports/cve/ + cve_summary.md`);
  }

  if (CFG.sarif) fs.writeFileSync(path.join(rd, 'report.sarif'), JSON.stringify(buildSarif(findings), null, 2));
  if (CFG.junit) fs.writeFileSync(path.join(rd, 'report.junit.xml'), buildJunit(findings));

  const hot = findings.filter(f => ['P1', 'P2'].includes(f._vrt?.p || ''));
  if (hot.length && CFG.discord) {
    await httpPost(CFG.discord, {
      content: `🏆 **ALHINDAWI HUNTER** — ${hot.length} P1/P2 findings\n${hot.slice(0, 8).map(f => `• [${f._vrt.p}] ${f._vrt.vuln} @ ${f.host} (${f._confidence}%)`).join('\n')}`
    });
  }
  if (hot.length && CFG.tgBot && CFG.tgChat) {
    await httpPost(`https://api.telegram.org/bot${CFG.tgBot}/sendMessage`, {
      chat_id: CFG.tgChat, parse_mode: 'Markdown',
      text: `🏆 *ALHINDAWI HUNTER*\n${hot.length} P1/P2 findings\n${hot.slice(0, 8).map(f => `• [${f._vrt.p}] ${f._vrt.vuln} @ ${f.host}`).join('\n')}`
    });
  }

  showSummary(findings, stats, vs, cs, trend);
}

function showSummary(findings, stats, vs, cs, trend) {
  console.log(`\n${C.mag}${C.b}${'═'.repeat(72)}${C.r}`);
  console.log(`${C.b}  🏆 ALHINDAWI HUNTER v10.0 FUSION — COMPLETE${C.r}`);
  console.log(`${C.mag}${C.b}${'═'.repeat(72)}${C.r}`);

  console.log(`\n  ${C.b}Bugcrowd VRT v1.19:${C.r}`);
  for (const p of ['P1', 'P2', 'P3', 'P4']) {
    if (vs.stats[p] === 0) continue;
    const prio = VRT_PRIORITY[p];
    const color = { P1: C.red, P2: C.mag, P3: C.yel, P4: C.cyn }[p];
    console.log(`  ${color}${prio.label.padEnd(14)}${C.r} │ ${String(vs.stats[p]).padStart(4)} │ ${C.yel}$${vs.bounty[p].toLocaleString()}${C.r}`);
  }
  console.log(`  ${C.b}${'TOTAL'.padEnd(14)}${C.r} │ ${String(findings.length).padStart(4)} │ ${C.yel}$${vs.total.toLocaleString()}${C.r}`);  

  if (cs.total) {
    console.log(`\n  ${C.b}CVE Intelligence:${C.r}`);
    console.log(`  ${'CVE-linked'.padEnd(14)} │ ${String(cs.total).padStart(4)} (uniq: ${cs.uniq}, avg CVSS: ${cs.avgCVSS})`);
    if (cs.kev) console.log(`  ${C.red}${'KEV 🔥'.padEnd(14)}${C.r} │ ${String(cs.kev).padStart(4)} (exploited in wild)`);
    if (cs.ransomware) console.log(`  ${C.red}${'Ransomware 🚨'.padEnd(14)}${C.r} │ ${String(cs.ransomware).padStart(4)}`);
  }

  if (trend) {
    console.log(`\n  📈 Trend: ${Object.entries(trend.trend).map(([k, v]) => `${k} ${v >= 0 ? '+' : ''}${v}`).join(' · ')}`);
  }

  console.log(`\n  ${C.cyn}Modules:${C.r} ${Object.entries(stats).filter(([, v]) => v > 0).map(([k, v]) => `${k}=${v}`).join(' · ')}`);
  console.log(`\n  📁 ${C.cyn}${CFG.outputDir}${C.r}`);
  console.log(`  📊 ${C.cyn}${path.join(CFG.outputDir, 'reports', 'report.html')}${C.r}`);
  if (CFG.vrt) console.log(`  🎯 Bugcrowd: reports/bugcrowd_summary.md + reports/bugcrowd/`);
  if (cs.total) console.log(`  🛡️  CVE: reports/cve_summary.md + reports/cve/`);
  if (CFG.sarif) console.log(`  📄 SARIF: reports/report.sarif`);
  if (CFG.junit) console.log(`  📄 JUnit: reports/report.junit.xml`);
  if (CFG.dashboard) console.log(`  🌐 Dashboard: http://localhost:${CFG.dashboardPort}`);
  console.log(`\n  ${C.yel}⚠️  REPRODUCE setiap finding secara manual sebelum submit!${C.r}`);
  console.log(`${C.mag}${C.b}${'═'.repeat(72)}${C.r}\n`);
}

process.on('SIGINT', () => {
  log('WARN', '⛔ Dibatalkan (SIGINT)');
  if (logStream) logStream.end();
  process.exit(130);
});

process.on('uncaughtException', e => {
  log('ERROR', `💥 ${e.stack || e.message}`);
  if (logStream) logStream.end();
  process.exit(1);
});

main()
  .then(() => { if (logStream) logStream.end(); })
  .catch(e => {
    log('ERROR', `❌ ${e.stack || e.message}`);
    if (logStream) logStream.end();
    process.exit(1);
  });