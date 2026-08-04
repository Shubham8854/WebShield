# 🛡️ WebShield - Website Security Scanner

WebShield is a Python-based Website Security Scanner designed to perform a basic security assessment of web applications. It analyzes a website's security configuration, checks for common security headers, inspects SSL certificates, performs DNS and WHOIS lookups, detects basic web technologies, scans common ports, and generates reports.

This project was built as a cybersecurity learning project to understand how security assessment tools work while improving Python programming and networking skills.

---

# ✨ Features

* 🌐 Website HTTP Scanner
* 🔒 Security Header Analysis
* 📊 Security Score Calculation
* 🔐 SSL Certificate Inspection
* 🌍 WHOIS Lookup
* 📡 DNS Lookup
* 🖥️ Basic Technology Detection
* 🚪 Common Port Scanner
* 📄 JSON Report Generation
* 🌐 HTML Report Generation
* 📝 Scan Logging
* ⚠️ Error Handling

---

# 🛠️ Technologies Used

* Python 3
* Requests
* Socket
* SSL
* python-whois
* JSON
* Logging
* Datetime

---

# 📂 Project Structure

```text
WebShield/
│
├── logs/
│   └── webshield.log
│
├── modules/
│   ├── scanner.py
│   ├── headers.py
│   ├── ssl_checker.py
│   ├── dns_lookup.py
│   ├── whois_lookup.py
│   ├── tech_detector.py
│   ├── port_scan.py
│   ├── report.py
│   ├── html_report.py
│   └── results.py
│
├── reports/
│   ├── webshield_report.json
│   └── webshield_report.html
│
├── utils/
│   ├── helpers.py
│   └── logger.py
│
├── main.py
├── requirements.txt
└── README.md
```

---

# ⚙️ Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/WebShield.git
```

## 2. Move into the project

```bash
cd WebShield
```

## 3. Create a Virtual Environment

Linux / macOS

```bash
python3 -m venv venv
```

Windows

```powershell
python -m venv venv
```

---

## 4. Activate the Virtual Environment

Linux / macOS

```bash
source venv/bin/activate
```

Windows

```powershell
venv\Scripts\activate
```

---

## 5. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Usage

Run the scanner:

```bash
python main.py
```

Enter the target website when prompted.

Example:

```text
Enter website URL:
https://google.com
```

WebShield will automatically perform:

* HTTP Scan
* Security Header Analysis
* SSL Certificate Inspection
* WHOIS Lookup
* DNS Lookup
* Technology Detection
* Port Scan

After the scan completes, reports and logs are generated automatically.

---

# 📄 Reports

Reports are stored inside:

```text
reports/
```

Generated reports:

* webshield_report.json
* webshield_report.html

---

# 📝 Logs

Scan logs are stored in:

```text
logs/webshield.log
```

---

# 📊 Example Output

```text
[+] Website: https://google.com
[+] Status Code: 200

[+] Security Header Analysis

[-] Strict-Transport-Security
[+] X-Frame-Options
[-] Referrer-Policy

[+] SSL Certificate Valid

[+] DNS Lookup

[+] Technology Detection

[+] Port Scan

[+] Scan completed successfully

[+] Report saved to reports/webshield_report.json
```

---

# 📚 What I Learned

This project helped me understand:

* HTTP Requests and Responses
* Security Headers
* SSL Certificate Validation
* DNS Resolution
* WHOIS Information
* Port Scanning
* Logging
* JSON and HTML Report Generation
* Python Project Structure
* Error Handling
* Modular Programming

---

# 🔮 Future Improvements

* Multi-threaded Port Scanning
* PDF Report Generation
* Command-Line Arguments
* Cookie Security Analysis
* Redirect Analysis
* Subdomain Enumeration
* CVE Lookup
* Dark Mode HTML Reports

---

# ⚠️ Disclaimer

This project is intended for educational purposes only.

Only scan websites and systems that you own or have explicit permission to test. Unauthorized security testing may be illegal.

---

# 📜 License

This project is licensed under the MIT License.

---

# 👨‍💻 Author

**Light Yagami**

Cybersecurity Enthusiast • Python Developer • Ethical Hacking Learner

If you like this project, consider giving it a ⭐ on GitHub.
