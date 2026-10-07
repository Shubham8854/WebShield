cd ~/WebShield

cat > README.md <<'EOF'
# 🛡 WebShield 2.0

### Web Security Assessment Framework

WebShield 2.0 is a Python-based web security assessment framework designed to automate reconnaissance, security configuration analysis, vulnerability identification, risk scoring, and security reporting.

It combines web reconnaissance, security-header analysis, SSL/TLS validation, technology detection, network exposure analysis, and live NVD/CVE intelligence into a single terminal-based security assessment workflow.

---

## 🚀 Features

- 🌐 HTTP/HTTPS target assessment
- 🔐 Security headers analysis
- 🛡 SSL/TLS certificate validation
- 🔎 DNS reconnaissance
- 👤 WHOIS lookup
- ⚙️ Web technology and version detection
- 🔌 Common TCP port scanning
- 🧩 CPE-based product/version validation
- 🐛 Live NVD/CVE vulnerability lookup
- 📊 CVSS severity and score extraction
- 🔍 Automated security finding generation
- 🎯 Risk scoring
- 📋 Security recommendations
- 📄 JSON security reports
- 🌐 HTML security reports
- 🎨 Rich terminal interface
- 📝 Security assessment logging

---

## 🔎 Vulnerability Intelligence

WebShield 2.0 integrates with the NIST National Vulnerability Database (NVD) to identify vulnerabilities associated with detected technologies.

The vulnerability workflow includes:

    Technology Detection
            ↓
    Product + Version
            ↓
    NVD CVE Search
            ↓
    CPE Validation
            ↓
    Version Range Validation
            ↓
    Confirmed CVE
            ↓
    CVSS Severity
            ↓
    Risk Scoring
            ↓
    Security Report

This helps reduce false-positive CVE matches by validating both the detected product and affected version information.

---

## 📊 Assessment Workflow

    Target
      │
      ├── HTTP/HTTPS Analysis
      │
      ├── Security Headers
      │
      ├── SSL/TLS
      │
      ├── DNS / WHOIS
      │
      ├── Technology Detection
      │
      ├── Port Scanning
      │
      ├── NVD / CVE Analysis
      │
      ├── Finding Engine
      │
      ├── Risk Scoring
      │
      └── JSON + HTML Report

---

## 🧰 Technologies

- Python 3
- Requests
- Rich
- PyFiglet
- dnspython
- python-whois
- NIST NVD API
- CPE vulnerability matching
- CVSS
- HTML / JSON reporting

---

## 📁 Project Structure

    WebShield/
    │
    ├── webshield.py
    │
    ├── core/
    │   └── engine.py
    │
    ├── modules/
    │   ├── discovery/
    │   ├── network/
    │   │   └── port_scan.py
    │   │
    │   ├── reconnaissance/
    │   │   ├── dns_lookup.py
    │   │   ├── tech_detector.py
    │   │   └── whois_lookup.py
    │   │
    │   ├── reporting/
    │   │   ├── findings.py
    │   │   ├── html_report.py
    │   │   ├── results.py
    │   │   └── summary.py
    │   │
    │   ├── vulnerability/
    │   │   ├── cpe_validator.py
    │   │   ├── cve_engine.py
    │   │   └── nvd_client.py
    │   │
    │   ├── web/
    │   │   ├── headers.py
    │   │   └── ssl_checker.py
    │   │
    │   ├── report.py
    │   └── scanner.py
    │
    ├── tests/
    │   └── test_scanner.py
    │
    ├── utils/
    │   ├── helpers.py
    │   ├── logger.py
    │   └── ui.py
    │
    ├── requirements.txt
    ├── .gitignore
    └── README.md

---

## ⚙️ Installation

Clone the repository:

    git clone <YOUR_GITHUB_REPOSITORY_URL>
    cd WebShield

Create a virtual environment:

    python3 -m venv venv

Activate it:

    source venv/bin/activate

Install dependencies:

    pip install -r requirements.txt

---

## ▶️ Usage

Start WebShield:

    python3 webshield.py

Enter an authorized target when prompted:

    Enter target (domain, URL, or IP):

Example:

    example.com

or:

    192.168.1.1

---

## 📄 Reports

WebShield generates security assessment reports in:

    reports/

Supported formats:

    webshield_report.json
    webshield_report.html

Generated reports are excluded from version control by `.gitignore`.

---

## 📊 Risk Assessment

WebShield calculates an overall security score using detected security weaknesses including:

- Missing security headers
- Invalid SSL/TLS configuration
- Exposed network services
- Confirmed CVEs

The framework then assigns an overall risk level based on the calculated security score.

---

## 🧪 Example Vulnerability Detection

Example detected technology:

    Web Server: Boa/0.93.15

WebShield can query the NVD and validate the detected product/version against CPE information.

Example:

    CVE-2007-4915
    Product: Boa
    Version: 0.93.15
    CVSS: 10.0
    Severity: HIGH
    Status: CONFIRMED

---

## 🔐 Responsible Use

WebShield is intended for:

- Authorized security assessments
- Lab environments
- CTFs
- Security research
- Defensive security testing
- Systems owned or explicitly authorized for testing

Do not use this framework against systems without permission.

The author is not responsible for misuse of this software.

---

## 📌 Project Status

**WebShield 2.0 — Active Development**

The core assessment, vulnerability analysis, risk scoring, and reporting pipeline is implemented.

Future improvements may include additional security checks, expanded technology fingerprints, enhanced reporting, and further terminal UI improvements.

---

## 👨‍💻 Author

**Voidryn**

Cybersecurity | Python | Security Automation

---

## 📜 License

MIT License
EOF

echo
echo "=========================================="
echo "  WebShield 2.0 - Project Verification"
echo "=========================================="
echo

echo "[1/4] Checking entry point..."
python3 -m py_compile webshield.py

if [ $? -ne 0 ]; then
    echo "[!] webshield.py compilation failed."
    exit 1
fi

echo "[+] webshield.py OK"

echo
echo "[2/4] Compiling project..."
python3 -m compileall -q core modules utils webshield.py

if [ $? -ne 0 ]; then
    echo "[!] Project compilation failed."
    exit 1
fi

echo "[+] Project compilation OK"

echo
echo "[3/4] Staging Git changes..."
git add .

echo "[+] Git changes staged"

echo
echo "[4/4] Final Git status..."
echo "=========================================="
git status
echo "=========================================="

echo
echo "[+] WebShield 2.0 is ready for final Git review."
echo "[!] No commit or push was performed."
