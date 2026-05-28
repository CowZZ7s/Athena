#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║        A T H E N A  —  R E P O R T  M O D E          ║
║    Unified Pentest Report — HTML + PDF Export         ║
╚═══════════════════════════════════════════════════════╝

Linux/cross-platform compatible.
Run with:  python3 report.py
"""

import sys
import os
import re
import json
import datetime
import html as html_module

# ─── Path Resolution ─────────────────────────────────────────────────────────
_BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BASE_DIR)

REPORTS_DIR = os.path.join(_BASE_DIR, "reports")
RC_DIR      = os.path.join(_BASE_DIR, "rc_scripts")

# ─── Colour Support ───────────────────────────────────────────────────────────

def _supports_colour():
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return os.environ.get("TERM", "") != "dumb"

_C     = _supports_colour()
GREEN  = "\033[92m" if _C else ""
YELLOW = "\033[93m" if _C else ""
RED    = "\033[91m" if _C else ""
RESET  = "\033[0m"  if _C else ""

# ─── HTML Escape ─────────────────────────────────────────────────────────────

def _e(value):
    """HTML-escape any value before inserting into report template."""
    return html_module.escape(str(value), quote=True)

# ─── Banner ──────────────────────────────────────────────────────────────────

BANNER = f"""
{GREEN}
 ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗
 ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
 ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║   
 ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║   
 ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║   
 ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
              M O D E  v1.0
{RESET}"""

# ─── Input Helper ─────────────────────────────────────────────────────────────

def prompt(label, default=""):
    val = input(f"{GREEN}[?]  {label}{' ['+default+']' if default else ''}: {RESET}").strip()
    return val if val else default

# ─── Session Loader ───────────────────────────────────────────────────────────

_IP_RE    = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
_HNAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,253}$')

def load_json(prefix):
    if not os.path.isdir(REPORTS_DIR):
        return None
    files = sorted(
        [f for f in os.listdir(REPORTS_DIR) if f.startswith(prefix) and f.endswith(".json")],
        reverse=True
    )
    if not files:
        return None
    path = os.path.join(REPORTS_DIR, files[0])
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        # Validate target field in loaded session
        target = data.get("target","")
        if target:
            if not (_IP_RE.match(target) or _HNAME_RE.match(target)):
                print(f"{YELLOW}[!]  Session {files[0]}: target field failed validation — redacted.{RESET}")
                data["target"] = "[REDACTED]"
        return data
    except (json.JSONDecodeError, OSError) as e:
        print(f"{YELLOW}[!]  Failed to load session {files[0]}: {e}{RESET}")
        return None

def load_all_sessions():
    return {
        "athena": load_json("athena_"),
        "chase":  load_json("chase_"),
        "attack": load_json("attack_"),
        "gather": load_json("gather_"),
    }

# ─── HTML Report ──────────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    "CRITICAL": ("bg:#2d0a0a", "color:#f87171"),
    "HIGH":     ("bg:#2d1a05", "color:#fbbf24"),
    "MEDIUM":   ("bg:#1a1a05", "color:#fde047"),
    "LOW":      ("bg:#0c1a2d", "color:#60a5fa"),
}

def _badge(sev):
    bg, fg = SEVERITY_STYLE.get(sev.upper(), ("bg:#1a1e28","color:#9ca3af"))
    return (f'<span style="background:{bg[3:]};color:{fg[6:]};padding:2px 10px;'
            f'border-radius:4px;font-family:IBM Plex Mono,monospace;font-size:10px;'
            f'font-weight:500;">{sev}</span>')

def generate_html(sessions, meta):
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target   = _e(meta.get("target","unknown"))
    tester   = _e(meta.get("tester","Athena Operator"))
    scope    = _e(meta.get("scope","Isolated home lab environment"))
    start_dt = _e(meta.get("start_date", ts[:10]))
    end_dt   = _e(meta.get("end_date",   ts[:10]))

    athena = sessions.get("athena") or {}
    chase  = sessions.get("chase")  or {}
    attack = sessions.get("attack") or {}
    gather = sessions.get("gather") or {}

    vulns     = chase.get("vulns", [])
    n_crit    = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    n_high    = sum(1 for v in vulns if v.get("severity") == "HIGH")
    n_med     = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    n_low     = sum(1 for v in vulns if v.get("severity") == "LOW")
    n_hosts   = athena.get("hosts_found", 0)
    n_ports   = athena.get("open_count", 0)
    n_attacks = len(attack.get("attempts", []))

    vuln_rows = ""
    for v in vulns:
        ports = _e(", ".join(str(p) for p in v.get("ports",[v.get("source_port","?")])))
        vuln_rows += f"""
        <tr>
          <td>{_badge(v.get("severity","INFO"))}<br>
              <b style="font-size:12px;">{_e(v.get('vulnerability',''))}</b><br>
              <span style="font-family:IBM Plex Mono,monospace;font-size:10px;color:#60a5fa;">{_e(v.get('cve',''))}</span></td>
          <td style="font-family:IBM Plex Mono,monospace;font-size:10px;">{ports}</td>
          <td style="font-size:12px;">{_e(v.get('method','N/A')[:120])}</td>
          <td style="font-family:IBM Plex Mono,monospace;font-size:10px;color:#a3e635;">{_e(v.get('msf_module','N/A'))}</td>
          <td style="font-size:11px;color:#9ca3af;">{_e(_remediation(v))}</td>
        </tr>"""

    attempt_rows = ""
    for a in attack.get("attempts",[]):
        attempt_rows += f"""
        <tr>
          <td style="font-family:IBM Plex Mono,monospace;font-size:11px;">{_e(a.get('timestamp','')[:19])}</td>
          <td style="font-size:12px;">{_e(a.get('payload_type',''))}</td>
          <td style="font-family:IBM Plex Mono,monospace;font-size:11px;">{_e(a.get('target',''))}:{_e(a.get('lport',''))}</td>
          <td style="font-family:IBM Plex Mono,monospace;font-size:11px;color:#a3e635;">{_e(a.get('module','')[:50])}</td>
          <td><span style="background:#052e16;color:#4ade80;padding:2px 8px;border-radius:4px;font-size:10px;font-family:IBM Plex Mono,monospace;">{_e(a.get('status','generated'))}</span></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Athena Pentest Report — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=DM+Sans:wght@300;400;500&display=swap');
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{font-family:'DM Sans',sans-serif;background:#fff;color:#111;padding:3rem 2rem;}}
  @media print{{body{{padding:1rem;}}}}
  .shell{{max-width:1000px;margin:0 auto;}}
  .cover{{border-bottom:3px solid #111;padding-bottom:2rem;margin-bottom:2.5rem;}}
  .cover-badge{{display:inline-block;background:#0d0f14;color:#4ade80;font-family:'IBM Plex Mono',monospace;font-size:11px;padding:4px 12px;border-radius:4px;margin-bottom:12px;}}
  h1{{font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:500;margin-bottom:8px;}}
  .cover-meta{{font-size:13px;color:#555;font-family:'IBM Plex Mono',monospace;}}
  .warning-box{{background:#fef3c7;border-left:4px solid #d97706;padding:.9rem 1rem;margin-bottom:2rem;font-size:13px;color:#92400e;}}
  .stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:2.5rem;}}
  .stat{{border:1px solid #e5e7eb;border-radius:8px;padding:1rem;text-align:center;}}
  .stat-val{{font-family:'IBM Plex Mono',monospace;font-size:28px;font-weight:500;}}
  .stat-val.red{{color:#dc2626;}} .stat-val.amber{{color:#d97706;}}
  .stat-val.yellow{{color:#ca8a04;}} .stat-val.green{{color:#16a34a;}}
  .stat-label{{font-size:11px;color:#6b7280;margin-top:4px;}}
  h2{{font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:500;border-bottom:1px solid #e5e7eb;padding-bottom:8px;margin:2rem 0 1rem;}}
  h3{{font-size:14px;font-weight:500;margin:1.5rem 0 .75rem;}}
  p{{font-size:13px;line-height:1.7;color:#374151;margin-bottom:.75rem;}}
  table{{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:1.5rem;}}
  th{{background:#f9fafb;text-align:left;padding:8px 12px;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:#6b7280;border-bottom:2px solid #e5e7eb;}}
  td{{padding:10px 12px;border-bottom:1px solid #f3f4f6;vertical-align:top;}}
  tr:hover td{{background:#f9fafb;}}
  .finding{{background:#f9fafb;border:1px solid #e5e7eb;border-left:4px solid #dc2626;border-radius:4px;padding:1rem;margin-bottom:1rem;}}
  .finding.high{{border-left-color:#d97706;}}
  .finding.medium{{border-left-color:#ca8a04;}}
  .finding.low{{border-left-color:#2563eb;}}
  .finding-title{{font-size:13px;font-weight:500;margin-bottom:4px;}}
  .finding-meta{{font-size:11px;color:#6b7280;font-family:'IBM Plex Mono',monospace;}}
  code{{font-family:'IBM Plex Mono',monospace;font-size:11px;background:#f3f4f6;padding:1px 5px;border-radius:3px;}}
  pre{{font-family:'IBM Plex Mono',monospace;font-size:11px;background:#f3f4f6;padding:1rem;border-radius:6px;white-space:pre-wrap;word-break:break-all;margin-bottom:1rem;}}
  footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid #e5e7eb;font-size:11px;color:#9ca3af;font-family:'IBM Plex Mono',monospace;text-align:center;}}
  .toc{{background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:1.25rem;margin-bottom:2rem;}}
  .toc-title{{font-size:12px;font-weight:500;font-family:'IBM Plex Mono',monospace;margin-bottom:8px;color:#374151;}}
  .toc a{{display:block;font-size:12px;color:#2563eb;padding:3px 0;text-decoration:none;}}
  .toc a:hover{{text-decoration:underline;}}
  .page-break{{page-break-before:always;}}
</style>
</head>
<body>
<div class="shell">

  <div class="cover">
    <div class="cover-badge">ATHENA RECON — PENTEST REPORT</div>
    <h1>Security Assessment Report</h1>
    <div class="cover-meta">
      Target: {target} &nbsp;|&nbsp; Tester: {tester} &nbsp;|&nbsp;
      Period: {start_dt} – {end_dt} &nbsp;|&nbsp; Generated: {ts}
    </div>
  </div>

  <div class="warning-box">
    &#9888; CONFIDENTIAL — This report contains sensitive vulnerability and exploit data.
    For authorised home lab use only. Do not distribute.
  </div>

  <div class="toc">
    <div class="toc-title">Contents</div>
    <a href="#exec-summary">1. Executive Summary</a>
    <a href="#scope">2. Scope & Methodology</a>
    <a href="#recon">3. Reconnaissance Findings</a>
    <a href="#vulns">4. Vulnerability Findings</a>
    <a href="#attack">5. Attack Attempts</a>
    <a href="#gather">6. Post-Exploitation (Gather)</a>
    <a href="#remediation">7. Remediation Recommendations</a>
  </div>

  <h2 id="exec-summary">1. Executive Summary</h2>
  <p>This report documents the findings of a security assessment conducted against
  <strong>{target}</strong> in an isolated home lab environment. The assessment covered
  reconnaissance, vulnerability identification, controlled exploitation, and
  post-exploitation data gathering.</p>

  <div class="stat-grid">
    <div class="stat"><div class="stat-val red">{n_crit}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-val amber">{n_high}</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-val yellow">{n_med}</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-val green">{n_low}</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-val" style="color:#374151;">{n_hosts}</div><div class="stat-label">Hosts found</div></div>
    <div class="stat"><div class="stat-val" style="color:#374151;">{n_ports}</div><div class="stat-label">Open ports</div></div>
    <div class="stat"><div class="stat-val" style="color:#374151;">{n_attacks}</div><div class="stat-label">Exploits run</div></div>
  </div>

  <h2 id="scope">2. Scope &amp; Methodology</h2>
  <p><strong>Target:</strong> {target}<br>
  <strong>Scope:</strong> {scope}<br>
  <strong>Tester:</strong> {tester}<br>
  <strong>Period:</strong> {start_dt} to {end_dt}</p>
  <p>Assessment followed a structured kill-chain methodology: Reconnaissance (Athena) →
  Enumeration &amp; Vulnerability Analysis (Chase) → Exploitation (Attack) →
  Post-Exploitation (Gather). All activity was performed on owned/authorised equipment.</p>

  <h2 id="recon">3. Reconnaissance Findings</h2>
  <p><strong>{n_hosts}</strong> host(s) discovered. <strong>{n_ports}</strong> open port(s) identified.</p>
  {"<p><em>No Athena session data loaded.</em></p>" if not athena else ""}

  <h2 id="vulns">4. Vulnerability Findings</h2>
  {"<p><em>No Chase session data loaded.</em></p>" if not vulns else f'''
  <p><strong>{len(vulns)}</strong> vulnerability/vulnerabilities identified across {len(set(v.get("source_port") for v in vulns))} service(s).</p>
  <table>
    <thead><tr>
      <th>Vulnerability</th><th>Port</th><th>Method</th>
      <th>MSF Module</th><th>Remediation</th>
    </tr></thead>
    <tbody>{vuln_rows}</tbody>
  </table>'''}

  <div class="page-break"></div>
  <h2 id="attack">5. Attack Attempts</h2>
  {"<p><em>No Attack session data loaded.</em></p>" if not attack.get("attempts") else f'''
  <table>
    <thead><tr><th>Time</th><th>Payload</th><th>Target:Port</th><th>Module</th><th>Status</th></tr></thead>
    <tbody>{attempt_rows}</tbody>
  </table>'''}

  <h2 id="gather">6. Post-Exploitation (Gather)</h2>
  {"<p><em>No Gather session data loaded.</em></p>" if not gather else f'''
  <p>Post-exploitation modules executed: {", ".join(gather.get("sections",{{}}).keys()) or "none recorded"}.</p>
  <p>Target OS context: <code>{gather.get("target_os","unknown")}</code></p>
  '''}

  <h2 id="remediation">7. Remediation Recommendations</h2>
  {_remediation_section(vulns)}

  <footer>athena-recon v1.0 &mdash; {tester} &mdash; {ts} &mdash; confidential</footer>
</div>
</body>
</html>"""
    return html

# ─── Remediation ─────────────────────────────────────────────────────────────

def _remediation(vuln):
    remap = {
        "ftp":    "Disable FTP, use SFTP. Disable anonymous login.",
        "ssh":    "Enforce key-based auth. Disable password login. Update OpenSSH.",
        "smb":    "Patch MS17-010. Disable SMBv1. Apply MS security updates.",
        "http":   "Patch web framework. Apply input validation. Enable security headers.",
        "mysql":  "Restrict remote access. Enforce strong credentials. Patch MySQL.",
        "rdp":    "Patch BlueKeep (KB4499175). Use NLA. Limit RDP exposure.",
        "vnc":    "Set strong VNC password. Restrict access by IP. Use SSH tunnel.",
        "redis":  "Require AUTH. Bind to localhost only. Disable CONFIG commands.",
        "smtp":   "Disable VRFY/EXPN. Require SMTP authentication.",
        "telnet": "Disable Telnet entirely. Replace with SSH.",
    }
    for k, v in remap.items():
        if k in vuln.get("source_service","").lower() or k in " ".join(vuln.get("tags",[])):
            return v
    return "Apply vendor patch. Restrict service access. Review configuration."

def _remediation_section(vulns):
    if not vulns:
        return "<p><em>No vulnerabilities to remediate.</em></p>"
    seen = set()
    out  = ""
    for v in vulns:
        if v.get("id") in seen:
            continue
        seen.add(v.get("id"))
        sev = v.get("severity","LOW").lower()
        cls = "finding" + (" high" if sev=="high" else " medium" if sev=="medium" else " low" if sev=="low" else "")
        out += f"""
        <div class="{cls}">
          <div class="finding-title">{_e(v.get('vulnerability',''))}</div>
          <div class="finding-meta">{_e(v.get('cve',''))} | CVSS {_e(v.get('cvss','N/A'))} | Port {_e(v.get('source_port','?'))}</div>
          <p style="margin-top:8px;font-size:12px;">{_e(_remediation(v))}</p>
        </div>"""
    return out

# ─── PDF Export ───────────────────────────────────────────────────────────────

def export_pdf(html_path, pdf_path):
    """
    Export HTML to PDF.
    Tries weasyprint first (best on Linux), then pdfkit (requires wkhtmltopdf).
    Falls back to printing instructions for the user.
    """
    # weasyprint — installs cleanly on Linux via pip
    try:
        import weasyprint
        print(f"{GREEN}[*]  Generating PDF via weasyprint...{RESET}")
        weasyprint.HTML(filename=html_path).write_pdf(pdf_path)
        return True, "weasyprint"
    except ImportError:
        pass
    except Exception as e:
        print(f"{YELLOW}[!]  weasyprint failed: {e}{RESET}")

    # pdfkit — requires wkhtmltopdf binary on PATH
    try:
        import pdfkit
        print(f"{GREEN}[*]  Generating PDF via pdfkit (wkhtmltopdf)...{RESET}")
        pdfkit.from_file(html_path, pdf_path)
        return True, "pdfkit"
    except ImportError:
        pass
    except Exception as e:
        print(f"{YELLOW}[!]  pdfkit failed: {e}{RESET}")

    # Fallback: platform-specific install guidance
    print(f"{YELLOW}[!]  PDF export not available. Install one of:{RESET}")
    print(f"{YELLOW}     pip install weasyprint{RESET}")
    if sys.platform.startswith("linux"):
        print(f"{YELLOW}     # Debian/Ubuntu/Kali:{RESET}")
        print(f"{YELLOW}     sudo apt install wkhtmltopdf && pip install pdfkit{RESET}")
    elif sys.platform == "darwin":
        print(f"{YELLOW}     brew install wkhtmltopdf && pip install pdfkit{RESET}")
    else:
        print(f"{YELLOW}     pip install pdfkit  (+ wkhtmltopdf from wkhtmltopdf.org){RESET}")
    print(f"{GREEN}[*]  Tip: Open the HTML report in your browser → Print → Save as PDF{RESET}")
    return False, None

# ─── Platform-aware Browser Open ─────────────────────────────────────────────

def open_in_browser(html_path):
    """
    Open the HTML report in the default browser.
    On headless Linux servers this is skipped gracefully.
    """
    abs_path = os.path.abspath(html_path)
    url      = f"file://{abs_path}"

    # On headless Linux (no DISPLAY and not WSL) skip silently
    if sys.platform.startswith("linux"):
        display = os.environ.get("DISPLAY","")
        wayland = os.environ.get("WAYLAND_DISPLAY","")
        if not display and not wayland:
            print(f"{YELLOW}[!]  No display detected (headless server). Browser open skipped.{RESET}")
            print(f"{GREEN}[*]  Report path: {abs_path}{RESET}")
            print(f"{GREEN}[*]  Transfer to your workstation with: scp user@host:{abs_path} ./{RESET}")
            return

    import webbrowser
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"{YELLOW}[!]  Could not open browser: {e}{RESET}")
        print(f"{GREEN}[*]  Open manually: {url}{RESET}")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if sys.version_info < (3, 8):
        print("[-]  Python 3.8 or higher is required.")
        sys.exit(1)

    print(BANNER)
    print(f"{GREEN}  Unified Pentest Report Generator{RESET}\n")
    os.makedirs(REPORTS_DIR, exist_ok=True)

    print(f"{GREEN}[*]  Loading session data from all phases...{RESET}")
    sessions = load_all_sessions()
    loaded   = [k for k,v in sessions.items() if v]
    print(f"{GREEN}[✓]  Sessions found: {', '.join(loaded) if loaded else 'none — report will be template only'}{RESET}\n")

    # Infer target from whichever session has one
    target = ""
    for key in ["athena","chase","attack","gather"]:
        s = sessions.get(key)
        if s and s.get("target"):
            target = s["target"]
            break

    target   = prompt("Target IP / hostname", target or "unknown")
    tester   = prompt("Tester name", "Athena Operator")
    scope    = prompt("Scope description", "Isolated home lab — owned equipment")
    start_dt = prompt("Assessment start date", datetime.date.today().strftime("%Y-%m-%d"))
    end_dt   = prompt("Assessment end date",   datetime.date.today().strftime("%Y-%m-%d"))

    meta = {"target":target,"tester":tester,"scope":scope,"start_date":start_dt,"end_date":end_dt}

    print(f"\n{GREEN}[*]  Generating report...{RESET}")
    html = generate_html(sessions, meta)

    ts        = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(REPORTS_DIR, f"pentest_report_{ts}.html")
    pdf_path  = os.path.join(REPORTS_DIR, f"pentest_report_{ts}.pdf")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    # Restrict report to owner on Linux
    try:
        os.chmod(html_path, 0o600)
    except OSError:
        pass
    print(f"{GREEN}[✓]  HTML report: {html_path}{RESET}")

    want_pdf = input(f"{GREEN}[?]  Attempt PDF export? [y/N]: {RESET}").strip().lower()
    if want_pdf == "y":
        ok, method = export_pdf(html_path, pdf_path)
        if ok:
            try:
                os.chmod(pdf_path, 0o600)
            except OSError:
                pass
            print(f"{GREEN}[✓]  PDF report ({method}): {pdf_path}{RESET}")

    open_now = input(f"{GREEN}[?]  Open HTML report in browser? [Y/n]: {RESET}").strip().lower()
    if open_now != "n":
        open_in_browser(html_path)

if __name__ == "__main__":
    main()
