#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║         A T H E N A  —  G A T H E R  M O D E         ║
║    Post-Exploitation: Escalate, Harvest, Pivot        ║
║         Authorised home lab use only                  ║
╚═══════════════════════════════════════════════════════╝

Linux/cross-platform compatible.
Run with:  python3 gather.py
"""

import sys
import os
import json
import datetime

# ─── Path Resolution ─────────────────────────────────────────────────────────
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _BASE_DIR)

from gather_modules import PrivEsc, CredHarvest, Pivot
from gather_reporter import GatherReporter
from validators import (
    validate_ip, validate_cidr, validate_session_id,
    prompt_validated, CYAN, YELLOW, GREEN, RED, GREY, RESET
)

# ─── Directories ─────────────────────────────────────────────────────────────

REPORTS_DIR = os.path.join(_BASE_DIR, "reports")
RC_DIR      = os.path.join(_BASE_DIR, "rc_scripts")

# ─── Banner & Menu ───────────────────────────────────────────────────────────

BANNER = f"""
{CYAN}
  ██████╗  █████╗ ████████╗██╗  ██╗███████╗██████╗ 
 ██╔════╝ ██╔══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
 ██║  ███╗███████║   ██║   ███████║█████╗  ██████╔╝
 ██║   ██║██╔══██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
 ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
              M O D E  v1.0
{RESET}
{YELLOW}  [!] Post-exploitation phase. Active session required.
  [!] Authorised lab targets only.{RESET}
"""

GATHER_MENU = f"""
{CYAN}┌──────────────────────────────────────────────┐
│           GATHER MODE                        │
├──────────────────────────────────────────────┤
│  [1]  Privilege Escalation                   │
│  [2]  Credential Harvesting                  │
│  [3]  Network Pivoting & Lateral Movement    │
│  [4]  Full Gather  (1 + 2 + 3)              │
│  [5]  Generate Gather RC script              │
│  [6]  View session notes                     │
│  [0]  Exit                                   │
└──────────────────────────────────────────────┘{RESET}
"""

# ─── Target Lock ─────────────────────────────────────────────────────────────

def target_lock(target):
    print(f"\n{CYAN}╔══════════════════════════════════════════════╗")
    print(f"║  ⚠  TARGET LOCK REQUIRED                    ║")
    print(f"║     Target : {target:<32}║")
    print(f"╚══════════════════════════════════════════════╝{RESET}")
    ans = input("  Type CONFIRMED to continue: ").strip()
    if ans.upper() == "CONFIRMED":
        print(f"{GREEN}[✓]  Target locked → {target}{RESET}\n")
        return True
    print(f"{RED}[-]  Aborted.{RESET}\n")
    return False

# ─── Prompt Helper ────────────────────────────────────────────────────────────

def prompt(label, default=""):
    val = input(f"{CYAN}[?]  {label}{' ['+default+']' if default else ''}: {RESET}").strip()
    return val if val else default

# ─── Session Loader ───────────────────────────────────────────────────────────

def load_attack_session():
    if not os.path.isdir(REPORTS_DIR):
        return None
    jsons = sorted(
        [f for f in os.listdir(REPORTS_DIR) if f.startswith("attack_") and f.endswith(".json")],
        reverse=True
    )
    if not jsons:
        return None
    path = os.path.join(REPORTS_DIR, jsons[0])
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"{YELLOW}[!]  Could not load attack session: {e}{RESET}")
        return None

# ─── OS & Session Selection ──────────────────────────────────────────────────

def select_os_context():
    print(f"\n{CYAN}  Target OS context:{RESET}")
    print("  [1] Windows   [2] Linux")
    c = input(f"{CYAN}[?]  [1]: {RESET}").strip() or "1"
    return "windows" if c == "1" else "linux"

def select_session_id():
    return prompt_validated(
        "Meterpreter session ID (from sessions -l)",
        validate_session_id,
        default="1",
        color=CYAN
    )

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    if sys.version_info < (3, 8):
        print("[-]  Python 3.8 or higher is required.")
        sys.exit(1)

    print(BANNER)
    os.makedirs(RC_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    # Validate target from attack session JSON before trusting it
    target = ""
    attack_session = load_attack_session()
    if attack_session:
        raw = attack_session.get("target", "")
        ok, result = validate_ip(raw)
        if ok:
            target = result
            print(f"{GREEN}[✓]  Loaded validated target from Attack session: {target}{RESET}")
        else:
            print(f"{YELLOW}[!]  Attack session target failed validation ({result}) — ignoring.{RESET}")

    if not target:
        target = prompt_validated(
            "Enter target IP (no default — must be explicit)",
            validate_ip,
            color=CYAN
        )

    if not target_lock(target):
        sys.exit(0)

    target_os  = select_os_context()
    session_id = select_session_id()

    priv_esc   = PrivEsc(target_os)
    cred_harv  = CredHarvest(target_os)
    pivot      = Pivot(target, target_os)
    reporter   = GatherReporter(target, target_os, session_id)

    print(f"\n{CYAN}[*]  Gather context: {target} | OS: {target_os} | Session: {session_id}{RESET}\n")

    while True:
        print(GATHER_MENU)
        choice = input(f"{CYAN}[?]  Choice: {RESET}").strip()

        if choice == "0":
            reporter.save_session()
            print(f"{GREEN}[✓]  Gather session saved.{RESET}\n")
            sys.exit(0)

        elif choice == "1":
            print(f"\n{CYAN}── Privilege Escalation ───────────────────────{RESET}\n")
            results = priv_esc.run(session_id)
            reporter.add_section("privesc", results)
            priv_esc.print_summary(results)

        elif choice == "2":
            print(f"\n{CYAN}── Credential Harvesting ──────────────────────{RESET}\n")
            results = cred_harv.run(session_id)
            reporter.add_section("creds", results)
            cred_harv.print_summary(results)

        elif choice == "3":
            print(f"\n{CYAN}── Network Pivoting & Lateral Movement ────────{RESET}\n")
            subnet = prompt_validated(
                "Internal subnet to pivot into (e.g. 10.10.10.0/24)",
                validate_cidr, default="10.10.10.0/24", color=CYAN
            )
            results = pivot.run(session_id, subnet)
            reporter.add_section("pivot", results)
            pivot.print_summary(results)

        elif choice == "4":
            print(f"\n{CYAN}[*]  Full Gather — running all modules...{RESET}\n")

            print(f"{CYAN}[1/3]  Privilege Escalation{RESET}")
            r1 = priv_esc.run(session_id)
            reporter.add_section("privesc", r1)
            priv_esc.print_summary(r1)

            print(f"\n{CYAN}[2/3]  Credential Harvesting{RESET}")
            r2 = cred_harv.run(session_id)
            reporter.add_section("creds", r2)
            cred_harv.print_summary(r2)

            print(f"\n{CYAN}[3/3]  Pivoting{RESET}")
            subnet = prompt_validated(
                "Pivot subnet", validate_cidr,
                default="10.10.10.0/24", color=CYAN
            )
            r3 = pivot.run(session_id, subnet)
            reporter.add_section("pivot", r3)
            pivot.print_summary(r3)

            rc_path = reporter.save_rc()
            print(f"\n{GREEN}[✓]  Full Gather RC: {rc_path}{RESET}")
            print(f"{YELLOW}     msfconsole -r \"{rc_path}\"{RESET}\n")

        elif choice == "5":
            rc_path = reporter.save_rc()
            print(f"\n{GREEN}[✓]  Gather RC script: {rc_path}{RESET}")
            print(f"{YELLOW}     Load in msfconsole: resource \"{rc_path}\"{RESET}\n")

        elif choice == "6":
            reporter.print_notes()

        else:
            print(f"{RED}[-]  Invalid choice.{RESET}")

if __name__ == "__main__":
    main()
