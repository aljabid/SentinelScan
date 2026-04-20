# Installation Guide

## Requirements

- Python 3.9 or higher
- pip

## Install from Source

```bash
git clone https://github.com/yourusername/sentinelscan.git
cd sentinelscan
pip install -e .
```

## Install with DNS Support

DNS checks (SPF, DMARC) require `dnspython`:

```bash
pip install -e ".[dns]"
```

## Install for Development

```bash
pip install -e ".[dev]"
```

This installs: `pytest`, `pytest-cov`, `black`, `ruff`.

## Verify Installation

```bash
sentinelscan --version
# SentinelScan 2.0.0
```

## Windows Notes

Ensure Python Scripts directory is in your PATH:

```powershell
# Add to PATH if sentinelscan command is not found
$env:PATH += ";$env:APPDATA\Python\Python313\Scripts"
# Or for system Python:
$env:PATH += ";C:\Users\<you>\AppData\Local\Programs\Python\Python313\Scripts"
```

## Upgrading from v1.0.0

Simply reinstall:

```bash
pip install -e . --upgrade
```

All new modules (cookies, cors, dns, ports) are enabled by default when using `-m all`.
