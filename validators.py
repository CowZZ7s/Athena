"""
Athena — Input Validation & Sanitisation Utilities
Shared across Attack, Gather, and Report modules.

Linux/cross-platform compatible.
"""

import re
import os
import sys
import html

# ─── Platform & Colour Support ───────────────────────────────────────────────

def _supports_colour():
    """
    Return True if the terminal supports ANSI colour codes.
    Handles Linux (tty check), NO_COLOR env var, and dumb terminals.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    term = os.environ.get("TERM", "")
    if term == "dumb":
        return False
    return True

COLOUR = _supports_colour()

def c(code):
    """Return ANSI escape code only if colour is supported, else empty string."""
    return code if COLOUR else ""

# Named shortcuts used throughout Athena
CYAN   = c("\033[96m")
YELLOW = c("\033[93m")
GREEN  = c("\033[92m")
RED    = c("\033[91m")
GREY   = c("\033[90m")
RESET  = c("\033[0m")


# ─── IP Validation ────────────────────────────────────────────────────────────

def validate_ip(ip_str):
    """
    Validate IPv4 address, CIDR range, or hostname.
    Returns (True, cleaned) or (False, error_msg).
    """
    ip_str = ip_str.strip()
    if not ip_str:
        return False, "IP/hostname cannot be empty"

    # IPv4 pattern
    ipv4 = re.compile(
        r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    )
    m = ipv4.match(ip_str)
    if m:
        octets = [int(g) for g in m.groups()]
        if all(0 <= o <= 255 for o in octets):
            return True, ip_str
        return False, f"Invalid IPv4 octets in: {ip_str}"

    # CIDR range (e.g. 192.168.1.0/24)
    cidr = re.compile(
        r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$'
    )
    if cidr.match(ip_str):
        return True, ip_str

    # Hostname pattern (alphanumeric, hyphens, dots)
    hostname = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$')
    if hostname.match(ip_str):
        return True, ip_str

    return False, f"Invalid IP/hostname format: {ip_str}"


# ─── Port Validation ──────────────────────────────────────────────────────────

def validate_port(port_str):
    """
    Validate TCP port number (1–65535).
    Returns (True, int_port) or (False, error_msg).
    """
    try:
        port = int(str(port_str).strip())
        if 1 <= port <= 65535:
            return True, port
        return False, f"Port must be between 1 and 65535, got: {port}"
    except ValueError:
        return False, f"Port must be a number, got: '{port_str}'"


# ─── CIDR Validation ─────────────────────────────────────────────────────────

def validate_cidr(cidr_str):
    """
    Validate IPv4 CIDR notation (e.g. 10.10.10.0/24).
    Returns (True, cleaned) or (False, error_msg).
    """
    cidr_str = cidr_str.strip()
    pattern = re.compile(
        r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$'
    )
    m = pattern.match(cidr_str)
    if not m:
        return False, f"Invalid CIDR format: '{cidr_str}' (expected e.g. 10.10.10.0/24)"
    octets = [int(m.group(i)) for i in range(1, 5)]
    prefix = int(m.group(5))
    if not all(0 <= o <= 255 for o in octets):
        return False, f"Invalid octets in CIDR: '{cidr_str}'"
    if not (0 <= prefix <= 32):
        return False, f"Invalid prefix length in CIDR: /{prefix}"
    return True, cidr_str


# ─── Session ID Validation ────────────────────────────────────────────────────

def validate_session_id(sid_str):
    """
    Validate a Meterpreter session ID — must be a positive integer.
    Returns (True, str_id) or (False, error_msg).
    """
    try:
        n = int(str(sid_str).strip())
        if n < 1:
            return False, f"Session ID must be >= 1, got {n}"
        return True, str(n)
    except ValueError:
        return False, f"Session ID must be a number, got: '{sid_str}'"


# ─── Filename Sanitisation ────────────────────────────────────────────────────

def sanitise_filename(name, max_len=64):
    """
    Strip path separators and unsafe chars from a filename component.
    Only allows alphanumeric, underscore, hyphen, dot.
    Prevents path traversal on both Linux and Windows.
    """
    # Remove any directory components (handles both / and \)
    name = os.path.basename(name.replace("\\", "/"))
    # Keep only safe characters
    name = re.sub(r'[^\w\.\-]', '_', name)
    # Collapse multiple underscores
    name = re.sub(r'_+', '_', name)
    # Strip leading dots (hidden file prevention on Linux)
    name = name.lstrip('.')
    # Enforce max length
    name = name[:max_len]
    return name or "output"


# ─── MSF Module Name Validation ───────────────────────────────────────────────

MSF_MODULE_PATTERN = re.compile(
    r'^(exploit|auxiliary|post|payload|encoder|nop|evasion)'
    r'(/[a-zA-Z0-9_\-]+){1,5}$'
)

def validate_msf_module(module_str):
    """
    Validate a Metasploit module path.
    Returns (True, module) or (False, error_msg).
    """
    module_str = module_str.strip()
    if not module_str:
        return False, "Module name cannot be empty"
    if MSF_MODULE_PATTERN.match(module_str):
        return True, module_str
    return False, f"Invalid MSF module format: '{module_str}'"


# ─── Encoder Validation ───────────────────────────────────────────────────────

ENCODER_PATTERN = re.compile(r'^[a-zA-Z0-9_/\-]{3,50}$')

def validate_encoder(encoder_str):
    """Validate msfvenom encoder name."""
    if not encoder_str:
        return True, ""  # Empty = no encoder, valid
    encoder_str = encoder_str.strip()
    if ENCODER_PATTERN.match(encoder_str):
        return True, encoder_str
    return False, f"Invalid encoder format: '{encoder_str}'"


# ─── Iteration Count Validation ───────────────────────────────────────────────

def validate_iterations(iter_str, max_iter=10):
    """
    Validate encoding iteration count.
    Clamps to 1–max_iter with a warning above 5.
    """
    try:
        n = int(str(iter_str).strip())
        if n < 1:
            print(f"{YELLOW}[!]  Iterations < 1, clamping to 1.{RESET}")
            return True, 1
        if n > max_iter:
            print(f"{YELLOW}[!]  Iterations {n} exceeds maximum {max_iter}. Clamping to {max_iter}.{RESET}")
            return True, max_iter
        if n > 5:
            print(f"{YELLOW}[w]  High iteration count ({n}) will significantly slow payload generation.{RESET}")
        return True, n
    except ValueError:
        return False, f"Iterations must be a number, got: '{iter_str}'"


# ─── HTML Escaping ────────────────────────────────────────────────────────────

def esc(value):
    """HTML-escape a value for safe insertion into report templates."""
    return html.escape(str(value), quote=True)


# ─── Session JSON Field Validation ───────────────────────────────────────────

def validate_session_target(session_dict):
    """
    Validate the target field from a loaded session JSON.
    Returns (True, target) or (False, error_msg).
    """
    target = session_dict.get("target", "")
    if not target:
        return False, "Session has no target field"
    ok, result = validate_ip(target)
    if not ok:
        return False, f"Session target failed validation: {result}"
    return True, target

def validate_session_msf_modules(attempts):
    """
    Validate MSF module names in attack session attempts.
    Returns list of safe attempts (invalid modules replaced with placeholder).
    """
    safe = []
    for a in attempts:
        module = a.get("module", "")
        if module:
            ok, _ = validate_msf_module(module)
            if not ok:
                a = dict(a)  # copy
                a["module"] = "[REDACTED — failed validation]"
        safe.append(a)
    return safe


# ─── Validated Prompt Helper ─────────────────────────────────────────────────

def prompt_validated(label, validator_fn, default="", color=None):
    """
    Prompt user with validation loop.
    validator_fn: callable(str) → (bool, value_or_error)
    color: optional ANSI code; falls back to CYAN if colour is supported.
    """
    col = color if (color and COLOUR) else (CYAN if COLOUR else "")
    while True:
        raw = input(f"{col}[?]  {label}{' ['+str(default)+']' if default else ''}: {RESET}").strip()
        if not raw and default != "":
            ok, result = validator_fn(str(default))
            if ok:
                return result
            print(f"{RED}[-]  Default value also invalid: {result}{RESET}")
            continue
        ok, result = validator_fn(raw)
        if ok:
            return result
        print(f"{RED}[-]  {result} — please try again.{RESET}")
