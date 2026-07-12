# Firewall Analyzer

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg) ![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Analyze and audit firewall rules for security vulnerabilities.

## Features

- Rule parsing: iptables, pf, Cisco ASA
- Detect overly permissive rules
- Shadow rule detection
- Compliance checks: CIS, NIST, PCI-DSS
- JSON report generation

## Quick Start

```bash
pip install -r requirements.txt
python -m src.main --file rules.txt --format iptables
```

## License

MIT
