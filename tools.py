#!/usr/bin/env python3
"""
METATRON - tools.py
Recon tool runners — all output returned as strings to feed into the LLM.
Security: whitelist-only execution, no arbitrary commands.
Compatible with: Kali Linux, Parrot OS, Ubuntu
"""

import subprocess
import shutil
from config import ALLOWED_TOOLS, CAUTION_TOOLS, TOOL_TIMEOUTS


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = 120) -> str:
    """
    Execute a shell command, return combined stdout + stderr as string.
    Never crashes the program — always returns something.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout.strip()
        errors = result.stderr.strip()

        if output and errors:
            return output + "\n[STDERR]\n" + errors
        elif output:
            return output
        elif errors:
            return errors
        else:
            return "[!] Tool returned no output."

    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(command)}"
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]} — install it with: sudo apt install {command[0]}"
    except Exception as e:
        return f"[!] Unexpected error running {command[0]}: {e}"


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    """nmap -sV -sC -T4 --open — service detection + default scripts"""
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target],
                    timeout=TOOL_TIMEOUTS.get("nmap", 300))


def run_whois(target: str) -> str:
    """whois — domain registration, registrar, IP ownership"""
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_whatweb(target: str) -> str:
    """whatweb -a 3 — fingerprint web technologies"""
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def run_curl_headers(target: str) -> str:
    """curl -sI — fetch HTTP/HTTPS headers"""
    print(f"  [*] curl -sI http://{target}")
    output = run_tool([
        "curl", "-sI", "--max-time", "10", "--location",
        f"http://{target}"
    ], timeout=20)

    https_output = run_tool([
        "curl", "-sI", "--max-time", "10", "--location", "-k",
        f"https://{target}"
    ], timeout=20)

    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    """dig — DNS records: A, MX, NS, TXT"""
    print(f"  [*] dig {target} ANY")
    a_record   = run_tool(["dig", "+short", "A",   target], timeout=15)
    mx_record  = run_tool(["dig", "+short", "MX",  target], timeout=15)
    ns_record  = run_tool(["dig", "+short", "NS",  target], timeout=15)
    txt_record = run_tool(["dig", "+short", "TXT", target], timeout=15)

    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_nikto(target: str) -> str:
    """nikto -h — web server vulnerability scanner (noisy!)"""
    print(f"  [*] nikto -h {target}  (this may take a while...)")
    return run_tool(["nikto", "-h", target, "-nointeractive"],
                    timeout=TOOL_TIMEOUTS.get("nikto", 600))


def run_sslscan(target: str) -> str:
    """sslscan — SSL/TLS cipher and certificate analysis"""
    print(f"  [*] sslscan {target}")
    return run_tool(["sslscan", target], timeout=60)


def run_gobuster(target: str) -> str:
    """gobuster dir — directory brute-forcing"""
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    url = target if target.startswith("http") else f"http://{target}"
    print(f"  [*] gobuster dir -u {url} -w common.txt")
    return run_tool([
        "gobuster", "dir", "-u", url, "-w", wordlist,
        "-t", "20", "-q", "--no-error"
    ], timeout=TOOL_TIMEOUTS.get("gobuster", 300))


def run_subfinder(target: str) -> str:
    """subfinder — passive subdomain enumeration"""
    print(f"  [*] subfinder -d {target}")
    return run_tool(["subfinder", "-d", target, "-silent"],
                    timeout=120)


def run_searchsploit(query: str) -> str:
    """searchsploit — offline exploit database lookup"""
    print(f"  [*] searchsploit {query}")
    return run_tool(["searchsploit", query, "--colour"], timeout=30)


def run_enum4linux(target: str) -> str:
    """enum4linux — SMB/Windows enumeration"""
    print(f"  [*] enum4linux {target}")
    return run_tool(["enum4linux", "-a", target],
                    timeout=120)


# ─────────────────────────────────────────────
# TOOL REGISTRY
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1":  ("nmap",          run_nmap),
    "2":  ("whois",         run_whois),
    "3":  ("whatweb",       run_whatweb),
    "4":  ("curl headers",  run_curl_headers),
    "5":  ("dig DNS",       run_dig),
    "6":  ("nikto",         run_nikto),
    "7":  ("sslscan",       run_sslscan),
    "8":  ("gobuster",      run_gobuster),
    "9":  ("subfinder",     run_subfinder),
    "10": ("searchsploit",  run_searchsploit),
    "11": ("enum4linux",    run_enum4linux),
}

# Tool profiles — pre-built combos
TOOL_PROFILES = {
    "quick":    ["1", "2", "4", "5"],           # nmap, whois, curl, dig
    "web":      ["1", "3", "4", "6", "7", "8"], # + whatweb, nikto, ssl, gobuster
    "full":     ["1", "2", "3", "4", "5", "7", "9"],  # everything except noisy
    "internal": ["1", "4", "11"],                # nmap, curl, enum4linux
}


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

def run_default_recon(target: str) -> dict:
    """Run standard recon pipeline (everything except noisy tools)."""
    print(f"\n[*] Starting recon on: {target}")
    print("─" * 50)

    results = {}
    results["nmap"]         = run_nmap(target)
    results["whois"]        = run_whois(target)
    results["whatweb"]      = run_whatweb(target)
    results["curl_headers"] = run_curl_headers(target)
    results["dig"]          = run_dig(target)

    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def run_profile(profile_name: str, target: str) -> dict:
    """Run a named tool profile."""
    keys = TOOL_PROFILES.get(profile_name, [])
    results = {}
    for key in keys:
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            if shutil.which(name.split()[0]) or name in ("curl headers", "dig DNS"):
                print(f"\n[*] Running {name}...")
                results[name] = func(target)
            else:
                print(f"[!] {name} not installed — skipping.")
    return results


def format_recon_for_llm(results: dict) -> str:
    """Flatten the recon results dict into one clean string for the LLM."""
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output


# ─────────────────────────────────────────────
# SECURE TOOL DISPATCH (called by LLM)
# ─────────────────────────────────────────────

def run_tool_by_command(command_str: str) -> str:
    """
    Called by llm.py when AI writes [TOOL: nmap -sV 1.2.3.4].
    WHITELIST ONLY — only allows known tool binaries.
    """
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."

    tool_binary = parts[0]

    # Security: only allow whitelisted tools
    if tool_binary not in ALLOWED_TOOLS:
        return (
            f"[!] Blocked: '{tool_binary}' is not a whitelisted tool.\n"
            f"    Allowed tools: {', '.join(sorted(ALLOWED_TOOLS))}"
        )

    # Check if tool is installed
    if not shutil.which(tool_binary):
        return f"[!] Tool not found: {tool_binary} — install with: sudo apt install {tool_binary}"

    # Get appropriate timeout
    timeout = TOOL_TIMEOUTS.get(tool_binary, TOOL_TIMEOUTS["default"])

    return run_tool(parts, timeout=timeout)


# ─────────────────────────────────────────────
# INTERACTIVE TOOL SELECTOR (called from CLI)
# ─────────────────────────────────────────────

def interactive_tool_run(target: str) -> str:
    """
    Let user manually pick which tools to run.
    Returns combined output string.
    """
    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in sorted(TOOLS_MENU.items(), key=lambda x: int(x[0])):
        installed = "+" if shutil.which(name.split()[0]) or name in ("curl headers", "dig DNS") else "-"
        print(f"  [{key:>2}] {name:<16} [{installed}]")
    print()
    print("  [a]  Run all (except noisy tools)")
    print("  [q]  Quick scan (nmap + whois + curl + dig)")
    print("  [w]  Web scan (nmap + whatweb + curl + nikto + ssl + gobuster)")
    print("  [f]  Full scan (everything except noisy)")
    print("  [i]  Internal network (nmap + curl + enum4linux)")

    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()

    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)

    if choice in TOOL_PROFILES:
        results = run_profile(choice, target)
        return format_recon_for_llm(results)

    # Map single-letter shortcuts
    profile_map = {"q": "quick", "w": "web", "f": "full", "i": "internal"}
    if choice in profile_map:
        results = run_profile(profile_map[choice], target)
        return format_recon_for_llm(results)

    combined = {}
    for key in choice.split():
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = func(target)
        else:
            print(f"[!] Unknown option: {key}")

    return format_recon_for_llm(combined)


# ─────────────────────────────────────────────
# SYSTEM CHECK
# ─────────────────────────────────────────────

def check_tools():
    """Print status of all recon tools."""
    print("\n[ TOOL STATUS ]")
    print("─" * 40)
    for key, (name, _) in sorted(TOOLS_MENU.items(), key=lambda x: int(x[0])):
        # Get the actual binary name
        binary = name.split()[0]
        if name == "curl headers":
            binary = "curl"
        elif name == "dig DNS":
            binary = "dig"
        installed = shutil.which(binary) is not None
        status = "\033[92m INSTALLED \033[0m" if installed else "\033[91m MISSING   \033[0m"
        print(f"  {name:<16} {status}")
    print()


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    check_tools()
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
