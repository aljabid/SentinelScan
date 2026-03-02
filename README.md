# SentinelScan

## Overview
SentinelScan is a **modular cybersecurity reconnaissance and vulnerability scanning framework** built in Python. It is designed for educational and professional use, providing a structured way to perform port scanning, subdomain enumeration, web reconnaissance, and vulnerability checks.  

This project emphasizes:
- **Modularity**: Each feature is in its own module (`modules/`).
- **Professional polish**: Configurable via `config.yaml`, with reporting in TXT, JSON, and HTML.
- **Test coverage**: Full pytest suite in `tests/`.
- **CI/CD readiness**: Easily integrated with GitHub Actions.

---

## Features
- **Port Scanner**
  - Multithreaded TCP scanning
  - Banner grabbing
  - Common ports scan
  - Stealth mode (delayed scans)
  - Basic UDP scanning

- **Subdomain Enumeration**
  - Wordlist-based (multithreaded)
  - HTTP/HTTPS liveness checks
  - Brute force mode
  - Passive enumeration via `crt.sh`
  - Hybrid scan combining all methods

- **Web Reconnaissance**
  - Header analysis (security headers)
  - Technology detection (PHP, ASP.NET, etc.)
  - SSL/TLS certificate analysis
  - CORS misconfiguration checks
  - Cookie security flag checks

- **Vulnerability Checks**
  - Admin panel detection
  - Sensitive file checks (`robots.txt`, `.git/`, backups)
  - Open port checks
  - Security header checks
  - Directory listing detection
  - Default server page detection (Apache/IIS)
  - Basic CVE pattern checks (WordPress/Joomla)

- **Engine Orchestration**
  - Unified runner (`core/engine.py`)
  - Configurable modules
  - Reporting in TXT, JSON, HTML

- **Testing Suite**
  - Pytest coverage for all modules
  - CI/CD ready

---

## Project Structure


## 📁 Project Structure

```bash
PythonProject/
├── core/
│   ├── __init__.py
│   └── engine.py
│
├── modules/
│   ├── __init__.py
│   ├── port_scanner.py
│   ├── subdomain.py
│   ├── web_recon.py
│   └── vuln_checks.py
│
├── tests/
│   ├── __init__.py
│   ├── test_engine.py
│   ├── test_port_scanner.py
│   ├── test_subdomain.py
│   ├── test_web_recon.py
│   └── test_vuln_checks.py
│
├── scanner.py
├── config.yaml
├── requirements.txt
└── .gitignore
```

---

### 🔎 Structure Explanation

- **core/** → Main engine logic and scanner orchestration  
- **modules/** → Independent scanning modules (modular architecture)  
- **tests/** → Unit tests for CI/CD automation  
- **scanner.py** → CLI entry point  
- **config.yaml** → Configuration settings  
- **requirements.txt** → Project dependencies  
- **.gitignore** → Files ignored by Git  



# ⚙️ Installation

## 1️⃣ Clone Repository

```bash
git clone https://github.com/yourusername/SentinelScan.git
cd SentinelScan
```

## 2️⃣ Create Virtual Environment

```bash
python -m venv .venv
```

Activate:

Linux / Mac:
```bash
source .venv/bin/activate
```

Windows:
```bash
.venv\Scripts\activate
```

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Usage

## CLI Entry Point

```bash
python scanner.py --target example.com --ports 1-100 --subdomains --web --vuln --output report.txt --format txt
```

---

## Available Options

| Option | Description |
|--------|-------------|
| --target | Target domain or IP |
| --ports | Port range (e.g., 1-1000) |
| --subdomains | Enable subdomain enumeration |
| --web | Enable web reconnaissance |
| --vuln | Enable vulnerability checks |
| --output | Save report to file |
| --format | Report format (txt, json, html) |

---

# 🛠 Configuration

Edit `config.yaml`:

```yaml
default_ports: "1-1000"
timeout: 0.5
wordlist: "wordlists/subdomains.txt"
output_format: "json"

modules:
  port_scanner: true
  subdomain: true
  web_recon: true
  vuln_checks: true

reporting:
  save_logs: true
  log_file: "reports/scan.log"
```

---

# 📊 Reporting

SentinelScan supports:

- ✅ TXT (Human-readable)
- ✅ JSON (Automation-friendly)
- ✅ HTML (Browser viewable)

Example TXT output:

```
=== Ports ===
[+] Port 80 OPEN | Banner: Apache/2.4.41
[+] Port 443 OPEN | Banner: nginx

=== Subdomains ===
[+] Found: www.example.com -> 93.184.216.34
[+] Alive: https://www.example.com (Status 200)

=== Web Recon ===
[+] Server: Apache
[!] Missing HSTS (SSL stripping risk)

=== Vulnerabilities ===
[+] Found admin panel: http://example.com/admin (Status 200)
```

---

# 🧪 Testing

Run all tests:

```bash
pytest tests/
```

Verbose:

```bash
pytest -v
```

Generate JUnit report:

```bash
pytest --junitxml=reports/test_results.xml
```

---

# 🔁 CI/CD Integration

Create:

`.github/workflows/ci.yml`

```yaml
name: SentinelScan CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install -r requirements.txt
      - run: pytest tests/ --maxfail=1 --disable-warnings -q
```

---

# 🧠 Development Philosophy

- Modular architecture
- Extensible plugin system
- Clean separation of core and modules
- Designed for learning secure development practices

---

# ⚖️ Ethical Disclaimer

SentinelScan is intended for educational and professional security research only.

Do NOT scan systems without explicit authorization.

Unauthorized scanning may violate laws.

---

# 🗺 Roadmap

- [ ] DNS Enumeration
- [ ] CVE checks via NVD API
- [ ] Web screenshot capture
- [ ] Docker support
- [ ] Risk scoring system
- [ ] AI-based anomaly scoring

---

# 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Commit with clear messages
4. Submit pull request

---

# 📜 License

MIT License

---

# 👨‍💻 Author

Developed as part of an Information Security Systems academic project.