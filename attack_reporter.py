"""
Athena Attack — Session Reporter
Logs all payload attempts and saves generated RC scripts.

Linux/cross-platform compatible.
"""

import os
import sys
import json
import datetime
import re

# ─── Path Resolution ─────────────────────────────────────────────────────────
# Use the directory of THIS file as the anchor so the tool works regardless
# of the working directory it is launched from — important on Linux where
# users may call `python /opt/athena/attack_reporter.py` from any cwd.

_BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(_BASE_DIR, "reports")
RC_DIR      = os.path.join(_BASE_DIR, "rc_scripts")
SHELLS_DIR  = os.path.join(_BASE_DIR, "web_shells")

# ─── Colour Support ───────────────────────────────────────────────────────────

def _supports_colour():
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return os.environ.get("TERM", "") != "dumb"

_C = _supports_colour()
GREEN  = "\033[92m" if _C else ""
YELLOW = "\033[93m" if _C else ""
PURPLE = "\033[95m" if _C else ""
GREY   = "\033[90m" if _C else ""
RESET  = "\033[0m"  if _C else ""

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _safe_filename(name, max_len=64):
    """Strip path separators and unsafe chars. Prevent traversal."""
    # Normalise both slash types before basename (Linux uses /, Windows uses \)
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r'[^\w\.\-]', '_', name)
    name = re.sub(r'_+', '_', name)
    name = name.lstrip('.')
    return name[:max_len] or "output"

# ─── Reporter Class ───────────────────────────────────────────────────────────

class AttackReporter:
    def __init__(self, target):
        self.target     = target
        self.session_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.attempts   = []
        # Ensure output dirs exist with secure permissions on Linux (0o700)
        for d in (RC_DIR, SHELLS_DIR, REPORTS_DIR):
            os.makedirs(d, mode=0o700, exist_ok=True)

    def save_rc(self, label, rc_content):
        safe_label = _safe_filename(label)
        filename   = f"athena_{safe_label}_{self.session_id}.rc"
        path       = os.path.join(RC_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(rc_content)
        # Restrict RC scripts to owner-only on Linux
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        print(f"{GREEN}[✓]  RC script saved: {path}{RESET}")
        return path

    def save_shell(self, filename, shell_code):
        safe_name = _safe_filename(filename)
        path      = os.path.join(SHELLS_DIR, safe_name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(shell_code)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        print(f"{GREEN}[✓]  Shell file saved: {path}{RESET}")
        return path

    def log_attempt(self, payload_type, target, lhost, lport, os_type, module, rc_path):
        self.attempts.append({
            "timestamp":    datetime.datetime.now().isoformat(),
            "payload_type": payload_type,
            "target":       target,
            "lhost":        lhost,
            "lport":        lport,
            "os_type":      os_type,
            "module":       module,
            "rc_path":      rc_path,
            "status":       "generated"
        })
        print(f"{GREEN}[✓]  Attempt logged: {payload_type} → {target}{RESET}")

    def list_rc_scripts(self):
        if not os.path.isdir(RC_DIR):
            print(f"{YELLOW}[!]  No RC scripts directory found.{RESET}")
            return
        scripts = [f for f in os.listdir(RC_DIR) if f.endswith(".rc")]
        if not scripts:
            print(f"{YELLOW}[!]  No RC scripts generated yet.{RESET}")
            return
        print(f"\n{PURPLE}  Generated RC scripts:{RESET}\n")
        for s in sorted(scripts, reverse=True):
            path = os.path.join(RC_DIR, s)
            size = os.path.getsize(path)
            print(f"  {YELLOW}{s}{RESET}  ({size}b)")
            print(f"    {GREY}msfconsole -r \"{path}\"{RESET}")
        print()

    def save_session(self):
        session = {
            "session_id": self.session_id,
            "target":     self.target,
            "timestamp":  datetime.datetime.now().isoformat(),
            "attempts":   self.attempts
        }
        path = os.path.join(REPORTS_DIR, f"attack_{self.session_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(session, f, indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        print(f"{GREEN}[✓]  Attack session saved: {path}{RESET}")
        return path
