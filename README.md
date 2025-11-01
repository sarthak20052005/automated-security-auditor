# 🔒 Automated Security Auditor

The **Automated Security Auditor** is a lightweight web-based security auditing tool built using **Flask**. It automates common website security checks such as SSL/TLS analysis, HTTP header inspection, and vulnerability scanning — and then generates a detailed HTML report summarizing potential risks.

---

## 🚀 Features

- **SSL/TLS Scanner** – Analyzes SSL configurations and highlights weak protocols or cipher suites.
- **HTTP Header Analyzer** – Checks security headers like CSP, HSTS, X-Frame-Options, etc.
- **Vulnerability Scanner** – Performs basic scans for reflected XSS, open redirects, and form security.
- **Comprehensive Reporting** – Generates a professional HTML report for each scan.
- **Flask Web Interface** – Simple, interactive web UI for launching and reviewing scans.

---

## 🧩 Project Structure

```
automated-security-auditor/
│
├── modules/                         # Core scanning and reporting modules
│   ├── __init__.py
│   ├── core_scanner.py              # Main scanning orchestration logic
│   ├── header_analyzer.py           # Performs HTTP header security checks
│   ├── reporting.py                 # Generates HTML/PDF reports
│   ├── ssl_scanner.py               # Performs SSL/TLS security scans
│   └── vuln_scanner.py              # Detects potential web vulnerabilities
│
├── reports/                         # Folder where generated reports are saved
│
├── templates/                       # Jinja2 templates for web rendering
│   └── report.html
│
├── venv/                            # Virtual environment (ignored in .gitignore)
│
├── .gitignore                       # Git ignore configuration file
├── main.py                          # CLI entry point (optional)
├── web_app.py                       # Flask web application entry point
├── README.md                        # Project documentation
└── requirements.txt                 # Python dependencies
```

---

## ⚙️ Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/{username}/automated-security-auditor.git
cd automated-security-auditor
```

### 2. Create a virtual environment
```bash
python -m venv venv
```

### 3. Activate the virtual environment
```bash
venv\Scripts\activate       # On Windows
# or
source venv/bin/activate      # On Linux/Mac
```

### 4. Install dependencies
```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Application

### Option 1: Run the Flask Web App
```bash
python web_app.py
```
Now open your browser and visit:
```
http://localhost:5000
```

### Option 2: Generate a Scan Report via CLI (optional)
```bash
python main.py https://example.com
```

---

## 📂 Output Reports

All scan results are saved under the `reports/` directory as HTML files.  
Each report includes summaries, findings, and recommendations for mitigation.

---

## 🧠 Future Enhancements

- Integration with **OWASP ZAP** for deeper scanning  
- Exporting reports as PDF  
- Scheduled scans with email alerts  
- Advanced dashboard with charts and trends

---

## 🛡️ License

This project is released under the **MIT License**.  
You are free to modify and distribute it with attribution.
