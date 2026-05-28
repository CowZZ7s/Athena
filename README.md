# Project Athena

> *A modular home-lab penetration testing framework built around Metasploit.*

---

## ⚠️ Legal Disclaimer

**This tool is intended for authorised security testing and educational use only.**

- You must have **explicit written permission** from the system owner before running any module against a target.
- This toolkit is designed for use in **isolated home lab environments** (e.g. VMs, CTF platforms, HackTheBox, TryHackMe).
- The author(s) accept **no responsibility** for misuse or for any damage caused by this software.
- Unauthorised use against systems you do not own or have permission to test **is illegal** under the Computer Misuse Act 1990 (UK), the CFAA (US), and equivalent laws worldwide.

> **By using this software you confirm you are acting lawfully and with appropriate authorisation.**

---

## Overview

Project Athena is a modular penetration testing assistant for home lab environments. It provides a structured kill-chain workflow across four phases:

```
Reconnaissance → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting
```

Each phase is handled by a dedicated module with validated inputs, session persistence between phases, and automatic HTML/PDF report generation at the end. Athena is designed to help you practise structured pentesting methodology in a repeatable, documented way — not just run tools ad hoc.

<!-- ADD ANY ADDITIONAL CONTEXT HERE — e.g. what inspired it, your lab setup, which CTF platforms it suits -->

### Modules

| Module | File | Description |
|---|---|---|
| Attack | `attack.py` | Payload generation and Metasploit RC script builder |
| Gather | `gather.py` | Post-exploitation: privilege escalation, credential harvesting, pivoting |
| Report | `report.py` | Unified HTML/PDF pentest report generator |
| Validators | `validators.py` | Shared input validation and sanitisation utilities |

---

## Requirements

- Python 3.8+
- Metasploit Framework (`msfconsole`, `msfvenom`)
- Optional for PDF export: `weasyprint` or `pdfkit` + `wkhtmltopdf`

```bash
pip install -r requirements.txt
```

<!-- ADD a requirements.txt to your repo listing any Python dependencies -->

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/project-athena.git
cd project-athena
pip install -r requirements.txt
```

<!-- Replace YOUR_USERNAME with your GitHub username once published -->

---

## Usage

Each module is run independently. Sessions are saved automatically and later phases load context from earlier ones — so running Attack after Chase will pre-populate the target and vulnerability list.

### Attack Mode
```bash
python attack.py
```
Generates Metasploit RC scripts and msfvenom payloads for a given target. Supports meterpreter reverse shells, bind shells, web shells (PHP/ASPX/JSP), and custom msfvenom formats. Requires explicit target IP entry and a `CONFIRMED` target-lock prompt before any output is generated.

### Gather Mode
```bash
python gather.py
```
Post-exploitation module. Loads the most recent Attack session automatically, or accepts a new target. Covers privilege escalation suggestions, credential harvesting, and network pivot RC generation.

### Report Mode
```bash
python report.py
```
Aggregates session data from all previous phases and generates a formatted pentest report. Outputs a standalone HTML file by default; PDF export is available if `weasyprint` or `pdfkit` is installed.

---

## Project Structure

```
project-athena/
├── attack.py               # Attack mode — payload builder
├── gather.py               # Gather mode — post-exploitation
├── report.py               # Report mode — HTML/PDF output
├── validators.py           # Shared input validation utilities
├── attack_payloads.py      # Payload and RC script generation logic
├── attack_reporter.py      # Attack session logging
├── reports/                # [gitignored] Generated session JSON + HTML reports
├── rc_scripts/             # [gitignored] Generated Metasploit RC scripts
└── web_shells/             # [gitignored] Generated web shell files
```

---

## Security Notes

- All user inputs are validated before use (IPs, ports, CIDR ranges, module paths, filenames, session IDs)
- File paths are sanitised to prevent path traversal attacks
- HTML report output is fully escaped to prevent injection
- RC scripts spool to a project-local `reports/` directory, not world-readable `/tmp`
- Generated RC scripts, session data, and web shells are excluded from version control via `.gitignore`
- Target lock confirmation (`CONFIRMED`) is required before any exploit module runs

---

## Author

<!-- ADD YOUR NAME / HANDLE / LINKS HERE -->
<!-- e.g. **Your Name** — [@yourhandle](https://github.com/yourhandle) -->

---

## Licence

<!-- CHOOSE YOUR LICENCE AND ADD IT HERE -->
<!-- Common choices for security tools: MIT, GPL-3.0, or a custom educational-use-only clause -->
<!-- e.g. This project is licensed under the MIT Licence — see [LICENSE](LICENSE) for details. -->

---

## Acknowledgements

<!-- ADD ANYTHING YOU WANT TO CREDIT HERE -->
<!-- e.g. tools, platforms (HackTheBox, TryHackMe), courses, or people who helped -->
