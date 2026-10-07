# ALHINDAWI HUNTER v10.0

**Nuclei + Bugcrowd VRT v1.19 + CVE Intelligence + False-Positive Reduction Engine**

[![Version](https://img.shields.io/badge/version-10.0.0-blue.svg)](https://github.com/USERNAME/alhindawi-hunter/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen.svg)](https://nodejs.org)

by **ALHINDAWI**

---

## LEGAL DISCLAIMER

> Scan HANYA target yang kamu punya izin tertulis.
> Unauthorized scanning = pelanggaran hukum (CFAA, UU ITE Pasal 30, dll).

---

## Features

- Nuclei Engine - Multi-worker batching, adaptive rate-limit, resume checkpoint
- Bugcrowd VRT v1.19 - Auto-map finding ke VRT category + priority P1-P5
- CVE Intelligence - NVD API 2.0, CISA KEV, Tenable export parser
- FP Reduction Engine - Confidence scoring, soft-404 detection, PoC verification
- Recon - Subfinder, httpx, crt.sh CT logs, subdomain permutasi
- JS Analysis - Secret detection, endpoint mining, source maps
- Deep Checks - CORS, GraphQL, JWT, Open Redirect, XSS, LFI, SSRF, SQLi, CRLF
- IIS Pack - web.config, trace.axd, elmah.axd, App_Data, bin/ exposure
- Reports - HTML, Markdown, Bugcrowd, SARIF, JUnit XML
- Live Dashboard - Real-time web feed

---

## Installation

Prasyarat:
- Node.js >= 18
- Nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

git clone https://github.com/USERNAME/alhindawi-hunter.git
cd alhindawi-hunter
node alhindawi.js targets.txt

---

## Usage

# Scan dasar
node alhindawi.js targets.txt

# Recon menyeluruh
node alhindawi.js targets.txt --recon --ct --permute --crawler

# JS analysis
node alhindawi.js targets.txt --js-secrets --js-endpoints --source-maps

# Deep checks
node alhindawi.js targets.txt --cors --graphql --jwt --takeover

# Injection suite
node alhindawi.js targets.txt --xss --sqli --lfi --ssrf

# CVE enrichment
node alhindawi.js targets.txt --cve-kev --cve-fetch-nvd

# Full hunt
node alhindawi.js targets.txt --recon --ct --cors --takeover --js-secrets --cve-kev --vrt --dashboard

---

## License

MIT - see LICENSE file.
