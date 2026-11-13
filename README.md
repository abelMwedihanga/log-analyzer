# Log Analyzer - Brute Force Detector

A Python SOC tool that scans login logs and detects brute-force attacks.

## What it does
- Reads sample.log
- Counts failed logins per IP
- Flags IPs with 5+ failed attempts as possible brute-force attack
- Detects logins at unusual hours

## How to run
python log-analyzer.py
