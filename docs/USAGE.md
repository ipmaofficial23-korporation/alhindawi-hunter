# Usage Guide

## Basic Scan
node alhindawi.js targets.txt

## Profiles
node alhindawi.js targets.txt --profile=stealth
node alhindawi.js targets.txt --profile=normal
node alhindawi.js targets.txt --profile=aggressive
node alhindawi.js targets.txt --profile=ninja

## Recon
node alhindawi.js targets.txt --recon --ct --permute --crawler --tech

## JS Analysis
node alhindawi.js targets.txt --js-secrets --js-endpoints --source-maps

## Injection
node alhindawi.js targets.txt --xss --sqli --lfi --ssrf --crlf

## CVE
node alhindawi.js targets.txt --cve-kev --cve-min-cvss=7.0

## Reports
node alhindawi.js targets.txt --vrt --sarif --junit
