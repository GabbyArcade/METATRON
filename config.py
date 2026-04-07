#!/usr/bin/env python3
"""
METATRON - config.py
Central configuration. All settings in one place.

API key setup:
  Option 1 (recommended): Set environment variable
      export ANTHROPIC_API_KEY="sk-ant-..."
  Option 2: Create a .env file in the METATRON directory
      ANTHROPIC_API_KEY=sk-ant-...
  Option 3: Edit ANTHROPIC_API_KEY below (not recommended — don't commit this)
"""

import os
import shutil

# ─────────────────────────────────────────────
# AI / LLM
# ─────────────────────────────────────────────

# Anthropic Claude API
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL      = "claude-sonnet-4-20250514"
MAX_TOKENS        = 4096
TEMPERATURE       = 0.4          # lower = more precise analysis

# Fallback: Ollama (local) — set USE_OLLAMA=True to use instead of Claude
USE_OLLAMA        = False
OLLAMA_URL        = "http://localhost:11434/api/generate"
OLLAMA_MODEL      = "metatron-qwen"
OLLAMA_TIMEOUT    = 600

# Tool dispatch
MAX_TOOL_LOOPS    = 9            # max times AI can call tools per session


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

# SQLite — zero config, file-based
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, "metatron.db")


# ─────────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────────

REPORT_DIR  = os.path.join(BASE_DIR, "reports")


# ─────────────────────────────────────────────
# RECON TOOLS — whitelist of allowed binaries
# ─────────────────────────────────────────────

ALLOWED_TOOLS = {
    # Core recon
    "nmap", "whois", "whatweb", "curl", "dig", "host",
    "ping", "traceroute",
    # Web vuln scanning
    "nikto", "nuclei", "wpscan", "sqlmap",
    # Fuzzing / brute
    "gobuster", "ffuf",
    # Subdomain / OSINT
    "subfinder", "amass", "theHarvester", "theharvester",
    # HTTP probing
    "httpx", "httpx-toolkit",
    # DNS at scale
    "dnsx",
    # WAF detection
    "wafw00f",
    # SSL / TLS
    "sslscan", "testssl.sh", "testssl",
    # SMB / Windows
    "enum4linux", "smbmap", "smbclient",
    # Port scanning
    "masscan", "rustscan",
    # Exploit DB
    "searchsploit",
    # Cred testing (CAUTION)
    "hydra",
}

# Tools that are dangerous / noisy / generate traffic — flag in UI
CAUTION_TOOLS = {
    "nikto", "sqlmap", "hydra", "masscan", "gobuster", "ffuf",
    "wpscan",  # active enumeration of WP
    "nuclei",  # actively probes targets
}


# ─────────────────────────────────────────────
# TOOL TIMEOUTS (seconds)
# ─────────────────────────────────────────────

TOOL_TIMEOUTS = {
    "nmap":         300,
    "nikto":        600,
    "masscan":      120,
    "gobuster":     300,
    "ffuf":         300,
    "sqlmap":       600,
    "hydra":        300,
    "nuclei":       600,
    "wpscan":       300,
    "amass":        300,
    "theHarvester": 180,
    "theharvester": 180,
    "httpx":        120,
    "httpx-toolkit":120,
    "dnsx":         120,
    "wafw00f":      60,
    "default":      120,
}


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def load_env_file():
    """Load .env file from project directory if it exists."""
    global ANTHROPIC_API_KEY
    env_path = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    os.environ[key] = val
                    if key == "ANTHROPIC_API_KEY" and not ANTHROPIC_API_KEY:
                        ANTHROPIC_API_KEY = val


def check_tool_installed(tool_name: str) -> bool:
    """Check if a CLI tool is available on the system."""
    return shutil.which(tool_name) is not None


def get_available_tools() -> dict:
    """Return dict of {tool_name: installed_bool} for all whitelisted tools."""
    return {tool: check_tool_installed(tool) for tool in sorted(ALLOWED_TOOLS)}


def validate_target(target: str) -> bool:
    """Basic validation that target looks like an IP or domain."""
    import re
    target = target.strip()
    if not target:
        return False
    # IP address (v4)
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    )
    # Domain name
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
        r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
        r'\.[a-zA-Z]{2,}$'
    )
    # URL — extract host
    url_pattern = re.compile(r'^https?://([^/:]+)')
    url_match = url_pattern.match(target)
    if url_match:
        target = url_match.group(1)

    return bool(ip_pattern.match(target) or domain_pattern.match(target))


# Auto-load .env on import
load_env_file()
