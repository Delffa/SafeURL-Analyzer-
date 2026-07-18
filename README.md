SafeURL Analyzer

SafeURL Analyzer is a lightweight Python-based tool that performs basic URL safety analysis.

The tool checks URLs for several potentially suspicious indicators such as:

- HTTPS usage
- IP address instead of a domain
- Unusually long URLs
- Unusually long domain names
- "@" symbol usage
- Excessive subdomains
- Punycode domains
- Suspicious characters
- Multiple security-related keywords

«Disclaimer: SafeURL Analyzer is a basic URL analysis tool. It is not a phishing detector and cannot guarantee that a URL is safe or malicious.»

---

Features

- Basic URL safety analysis
- Risk score from "0" to "100"
- LOW, MEDIUM and HIGH risk levels
- HTTPS detection
- IP address detection
- Suspicious URL pattern detection
- JSON report export
- Command-line interface
- No external dependencies

---

Installation

Clone the repository:

git clone https://github.com/YOUR_USERNAME/SafeURL-Analyzer.git

Enter the project directory:

cd SafeURL-Analyzer

No additional Python packages are required.

---

Usage

Run the tool:

python main.py

Or analyze a URL directly:

python main.py -u https://example.com

Export the result as JSON:

python main.py -u https://example.com -o report.json

---

Example

============================================================

TARGET: https://example.com
RISK SCORE: 0/100
RISK LEVEL: LOW

[+] CHECKS

  [OK] HTTPS is enabled
  [OK] A domain name is used
  [OK] URL length is normal

[!] WARNINGS

  No suspicious indicators found

============================================================

Basic URL analysis only. This tool is not a phishing detector.

---

Project Structure

SafeURL-Analyzer/
│
├── main.py          # Command-line interface
├── analyzer.py      # URL analysis engine
├── README.md        # Project documentation
└── .gitignore       # Ignored files

---

Risk Scoring

The tool calculates a basic risk score based on detected indicators.

Score| Level
0-24| LOW
25-49| MEDIUM
50-100| HIGH

The score is only an indicator based on URL characteristics. It should not be treated as a definitive security verdict.

---

Disclaimer

This project is intended for educational and defensive purposes.

SafeURL Analyzer performs basic static URL analysis. It does not verify whether a website is actually malicious, does not guarantee safety, and should not replace professional security tools or analysis.

---

License

This project is licensed under the MIT License.
