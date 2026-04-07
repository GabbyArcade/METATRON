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
# v2.1 — OSINT / WEB ARSENAL
# ─────────────────────────────────────────────

def _strip_target(target: str) -> str:
    """Strip http(s):// scheme + path from target — leaves bare host."""
    t = target.strip()
    if t.startswith("http://"):
        t = t[7:]
    elif t.startswith("https://"):
        t = t[8:]
    return t.split("/")[0].split(":")[0]


def _resolve_binary(*candidates: str) -> str:
    """Return first installed binary from candidates (handles tool aliases)."""
    for c in candidates:
        if shutil.which(c):
            return c
    return candidates[0]  # fallback — will produce a clean "not found" error


def run_nuclei(target: str) -> str:
    """nuclei — modern vuln scanner with 7000+ templates (CAUTION: actively probes)"""
    url = target if target.startswith("http") else f"https://{_strip_target(target)}"
    print(f"  [*] nuclei -u {url} -severity low,medium,high,critical -silent")
    return run_tool([
        "nuclei", "-u", url,
        "-severity", "low,medium,high,critical",
        "-silent", "-nc", "-timeout", "10",
        "-rate-limit", "50",
    ], timeout=TOOL_TIMEOUTS.get("nuclei", 600))


def run_httpx(target: str) -> str:
    """httpx — fast HTTP probing & fingerprinting (projectdiscovery)"""
    binary = _resolve_binary("httpx-toolkit", "httpx")
    host = _strip_target(target)
    print(f"  [*] {binary} -u {host} -title -sc -tech-detect -ip -cdn")
    return run_tool([
        binary, "-u", host,
        "-title", "-status-code", "-tech-detect",
        "-ip", "-cdn", "-silent",
    ], timeout=TOOL_TIMEOUTS.get("httpx", 120))


def run_dnsx(target: str) -> str:
    """dnsx — fast DNS resolver (projectdiscovery)"""
    host = _strip_target(target)
    print(f"  [*] dnsx -d {host} -a -aaaa -cname -mx -ns -txt -resp")
    return run_tool([
        "dnsx", "-d", host,
        "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
        "-resp", "-silent",
    ], timeout=TOOL_TIMEOUTS.get("dnsx", 120))


def run_amass(target: str) -> str:
    """amass enum -passive — deep passive subdomain enumeration"""
    host = _strip_target(target)
    print(f"  [*] amass enum -passive -d {host}")
    return run_tool([
        "amass", "enum", "-passive", "-d", host, "-silent",
    ], timeout=TOOL_TIMEOUTS.get("amass", 300))


def run_theharvester(target: str) -> str:
    """theHarvester — emails, employees, subdomains from public sources"""
    binary = _resolve_binary("theHarvester", "theharvester")
    host = _strip_target(target)
    print(f"  [*] {binary} -d {host} -b duckduckgo,crtsh,bing -l 200")
    return run_tool([
        binary, "-d", host,
        "-b", "duckduckgo,crtsh,bing,hackertarget",
        "-l", "200",
    ], timeout=TOOL_TIMEOUTS.get("theHarvester", 180))


def run_wafw00f(target: str) -> str:
    """wafw00f — WAF detection"""
    url = target if target.startswith("http") else f"https://{_strip_target(target)}"
    print(f"  [*] wafw00f {url}")
    return run_tool(["wafw00f", url], timeout=TOOL_TIMEOUTS.get("wafw00f", 60))


def run_ffuf(target: str) -> str:
    """ffuf — fast modern fuzzer (directory discovery)"""
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    url = target if target.startswith("http") else f"http://{_strip_target(target)}"
    fuzz_url = f"{url.rstrip('/')}/FUZZ"
    print(f"  [*] ffuf -u {fuzz_url} -w common.txt -mc 200,204,301,302,307,401,403")
    return run_tool([
        "ffuf", "-u", fuzz_url, "-w", wordlist,
        "-mc", "200,204,301,302,307,401,403",
        "-t", "40", "-s",
    ], timeout=TOOL_TIMEOUTS.get("ffuf", 300))


def run_sqlmap(target: str) -> str:
    """sqlmap — SQLi automation (CAUTION: defaults to non-destructive crawl, level 1)"""
    url = target if target.startswith("http") else f"http://{_strip_target(target)}"
    print(f"  [*] sqlmap -u {url} --batch --crawl=1 --level=1 --risk=1 --random-agent")
    return run_tool([
        "sqlmap", "-u", url,
        "--batch", "--crawl=1", "--level=1", "--risk=1",
        "--random-agent", "--timeout=10", "--retries=1",
        "--technique=BEU",
    ], timeout=TOOL_TIMEOUTS.get("sqlmap", 600))


def run_wpscan(target: str) -> str:
    """wpscan — WordPress vulnerability scanner"""
    url = target if target.startswith("http") else f"https://{_strip_target(target)}"
    print(f"  [*] wpscan --url {url} --random-user-agent --no-banner")
    return run_tool([
        "wpscan", "--url", url,
        "--random-user-agent", "--no-banner",
        "--disable-tls-checks",
    ], timeout=TOOL_TIMEOUTS.get("wpscan", 300))


# ─────────────────────────────────────────────
# TOOL REGISTRY
# ─────────────────────────────────────────────

TOOLS_MENU = {
    # Core recon
    "1":  ("nmap",          run_nmap),
    "2":  ("whois",         run_whois),
    "3":  ("whatweb",       run_whatweb),
    "4":  ("curl headers",  run_curl_headers),
    "5":  ("dig DNS",       run_dig),
    # Web vuln
    "6":  ("nikto",         run_nikto),
    "7":  ("sslscan",       run_sslscan),
    "8":  ("gobuster",      run_gobuster),
    # Subdomain
    "9":  ("subfinder",     run_subfinder),
    # Misc
    "10": ("searchsploit",  run_searchsploit),
    "11": ("enum4linux",    run_enum4linux),
    # ─── v2.1 OSINT / WEB ARSENAL ───
    "12": ("nuclei",        run_nuclei),
    "13": ("httpx",         run_httpx),
    "14": ("dnsx",          run_dnsx),
    "15": ("amass",         run_amass),
    "16": ("theHarvester",  run_theharvester),
    "17": ("wafw00f",       run_wafw00f),
    "18": ("ffuf",          run_ffuf),
    "19": ("sqlmap",        run_sqlmap),
    "20": ("wpscan",        run_wpscan),
}

# Tool profiles — pre-built combos
TOOL_PROFILES = {
    # Core
    "quick":    ["1", "2", "4", "5"],                                    # nmap, whois, curl, dig
    "web":      ["3", "4", "7", "13", "17", "12", "6"],                  # whatweb, curl, ssl, httpx, wafw00f, nuclei, nikto
    "full":     ["1", "2", "3", "4", "5", "7", "9", "13", "15"],         # everything passive-ish
    "internal": ["1", "4", "11"],                                         # nmap, curl, enum4linux
    # v2.1 — new bundles
    "osint":    ["2", "5", "9", "15", "16", "14", "13"],                 # whois, dig, subfinder, amass, theHarvester, dnsx, httpx
    "bug":      ["9", "15", "13", "17", "12", "18"],                     # subfinder, amass, httpx, wafw00f, nuclei, ffuf
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


def _menu_binary(name: str) -> str:
    """Resolve menu name to actual binary for which() checks."""
    if name == "curl headers":   return "curl"
    if name == "dig DNS":        return "dig"
    if name == "theHarvester":   return _resolve_binary("theHarvester", "theharvester")
    if name == "httpx":          return _resolve_binary("httpx-toolkit", "httpx")
    return name.split()[0]


def run_profile(profile_name: str, target: str) -> dict:
    """Run a named tool profile."""
    keys = TOOL_PROFILES.get(profile_name, [])
    results = {}
    for key in keys:
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            if shutil.which(_menu_binary(name)):
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
        binary = name.split()[0]
        if name == "curl headers": binary = "curl"
        elif name == "dig DNS":    binary = "dig"
        elif name == "theHarvester": binary = _resolve_binary("theHarvester", "theharvester")
        elif name == "httpx":      binary = _resolve_binary("httpx-toolkit", "httpx")
        installed = "+" if shutil.which(binary) else "-"
        caution = " !" if binary in {"nikto", "sqlmap", "hydra", "masscan", "gobuster", "ffuf", "wpscan", "nuclei"} else "  "
        print(f"  [{key:>2}]{caution} {name:<14} [{installed}]")
    print()
    print("  [a]  Run all (except noisy tools)")
    print("  [q]  Quick     — nmap + whois + curl + dig                       (~30s)")
    print("  [w]  Web       — whatweb + curl + ssl + httpx + wafw00f + nuclei + nikto")
    print("  [o]  OSINT     — whois + dig + subfinder + amass + theHarvester + dnsx + httpx")
    print("  [b]  Bug bnty  — subfinder + amass + httpx + wafw00f + nuclei + ffuf")
    print("  [f]  Full      — kitchen sink (passive-ish)")
    print("  [i]  Internal  — nmap + curl + enum4linux")
    print("  ! = active/noisy — generates traffic to target")

    choice = input("\nChoice(s) e.g. 1 2 4 or a/q/w/o/b/f/i: ").strip().lower()

    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)

    if choice in TOOL_PROFILES:
        results = run_profile(choice, target)
        return format_recon_for_llm(results)

    # Map single-letter shortcuts
    profile_map = {
        "q": "quick", "w": "web", "f": "full", "i": "internal",
        "o": "osint", "b": "bug",
    }
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
    print("─" * 50)
    install_hints = {
        "nuclei":       "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  (or apt install nuclei)",
        "httpx":        "apt install httpx-toolkit",
        "dnsx":         "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "theHarvester": "apt install theharvester",
        "wafw00f":      "apt install wafw00f",
        "amass":        "apt install amass",
        "wpscan":       "apt install wpscan",
        "ffuf":         "apt install ffuf",
        "sqlmap":       "apt install sqlmap",
    }
    for key, (name, _) in sorted(TOOLS_MENU.items(), key=lambda x: int(x[0])):
        binary = _menu_binary(name)
        installed = shutil.which(binary) is not None
        if installed:
            status = "\033[92m INSTALLED \033[0m"
            hint = ""
        else:
            status = "\033[91m MISSING   \033[0m"
            hint = "  → " + install_hints.get(name, f"apt install {binary}")
        print(f"  [{key:>2}] {name:<14} {status}{hint}")
    print()


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    check_tools()
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
