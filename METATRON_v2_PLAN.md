# METATRON v2 — Upgrade Plan
### From CLI Prototype → Full Pentest Automation Platform

---

## Current State

METATRON today is a solid proof-of-concept: it runs 6 recon tools, feeds results to a local LLM, parses the AI output, and saves everything to MariaDB. But it's manual-heavy — you're still doing a lot of the thinking and clicking. The goal of v2 is to make METATRON do the heavy lifting so you can focus on the creative, high-judgment parts of an engagement.

---

## Phase 1: Reduce Setup Friction

**Problem:** MariaDB requires a separate install, root access, SQL table creation, and a running service. That's a lot of friction just to get started.

**Changes:**

- **Switch to SQLite** — zero config, no server needed, single file database. The schema stays the same but it "just works" out of the box. One `metatron.db` file in the project directory.
- **Auto-create tables on first run** — no manual SQL. The app checks if tables exist and creates them if not.
- **Config file (`config.py` or `config.yaml`)** — move all hardcoded values out: LLM model name, Ollama URL, timeout settings, default tools, report output directory. One place to change everything.
- **Auto-detect installed tools on startup** — instead of crashing when a tool is missing, check what's available and tell the user what they're missing.

**Effort:** Small. 1-2 hours. High impact on usability.

---

## Phase 2: Expanded Recon Arsenal

**Problem:** Only 6 tools. A real engagement needs way more coverage.

**New tools to add:**

| Tool | Purpose | Why It Matters |
|------|---------|---------------|
| `gobuster` / `ffuf` | Directory and file brute-forcing | Finds hidden endpoints, admin panels, backup files |
| `subfinder` / `amass` | Subdomain enumeration | Maps the full attack surface |
| `sslscan` / `testssl.sh` | SSL/TLS analysis | Finds weak ciphers, expired certs, protocol issues |
| `enum4linux` | SMB/Windows enumeration | Critical for internal network pentests |
| `masscan` | Fast port scanning | Scans entire subnets in seconds |
| `wpscan` | WordPress vulnerability scanning | Tons of targets run WordPress |
| `sqlmap` | SQL injection testing | Automates one of the most common web vulns |
| `hydra` | Credential brute-forcing | Tests default/weak passwords on services |
| `searchsploit` | Local exploit database lookup | Offline CVE → exploit matching |

**Architecture changes:**

- **Tool categories** — organize tools into Recon, Web, Network, Credentials, Exploitation
- **Smart target detection** — auto-detect if target is IP, domain, URL, or subnet and suggest appropriate tools
- **Tool profiles** — pre-built combos like "Quick Web Scan", "Full External", "Internal Network", "WordPress Site"
- **Parallel execution** — run independent tools simultaneously using Python threading (nmap + whois + dig can all run at the same time)

**Effort:** Medium. 3-5 hours. Massive impact on capability.

---

## Phase 3: Smarter AI Integration

**Problem:** The current LLM integration is basic — it sends one big prompt and hopes the AI formats output correctly. Regex parsing is brittle. Only supports one model.

**Changes:**

- **Structured JSON output** — instead of parsing `VULN: name | SEVERITY: level` with regex, tell the LLM to output JSON. Use a JSON schema validator. Way more reliable.
- **Multi-model support** — add a model selector in config: Ollama (local), OpenAI API, Anthropic API. Keep local as default but let users leverage better models if they want.
- **Better prompts with few-shot examples** — include 2-3 example analyses in the system prompt so the model knows exactly what good output looks like.
- **Conversational follow-up** — after the initial analysis, let the user ask the AI questions: "Tell me more about that RCE", "How would I exploit the SQLi on port 8080?", "Write me a Python script for that"
- **Tool dispatch improvements** — whitelist approach instead of blocklist for the command execution. Only allow known-safe tool binaries.
- **Chain-of-thought reasoning** — have the AI explain its reasoning before giving findings, which produces better analysis

**Effort:** Medium. 3-4 hours. Major quality improvement.

---

## Phase 4: Automated Pentesting Workflows

**Problem:** Right now METATRON only does recon + analysis. The actual exploitation is manual.

**Changes:**

- **Auto-exploit suggestions with runnable commands** — for each vuln found, generate the exact command to exploit it (not just a description)
- **Metasploit integration** — connect to msfrpc to auto-configure and run Metasploit modules based on findings
- **Smart chaining** — subdomain discovery → port scan each subdomain → web scan each web service → vuln scan → exploit suggestions. All automated.
- **Credential testing** — auto-run hydra against discovered services with common credential lists
- **Post-exploitation module** — once access is gained, auto-enumerate the compromised system
- **Safety controls** — require explicit confirmation before running any exploit, log everything, never auto-exploit without user approval

**Effort:** Large. 6-10 hours. This is the game-changer.

---

## Phase 5: Reporting & Output

**Problem:** The current PDF/HTML reports are functional but basic. Real pentest reports need executive summaries, CVSS scores, compliance mapping, and professional formatting.

**Changes:**

- **CVSS scoring** — auto-calculate CVSS v3.1 scores for each vulnerability
- **Executive summary** — AI-generated non-technical summary for management
- **Compliance mapping** — map findings to OWASP Top 10, NIST, CIS Controls, PCI-DSS
- **Risk matrix visualization** — severity × likelihood chart
- **Evidence screenshots** — auto-capture and embed tool output as evidence
- **Multiple report formats** — PDF, HTML, DOCX, Markdown, JSON (for importing into other tools)
- **Report templates** — professional templates with your branding/logo

**Effort:** Medium. 3-5 hours. Makes the output client-ready.

---

## Phase 6: UI/UX Overhaul

**Problem:** Raw terminal output is hard to scan. No progress indicators. No color-coded risk.

**Changes:**

- **Rich terminal UI** — use the `rich` library (already in requirements!) for colored tables, progress bars, panels, and tree views
- **Live scan dashboard** — show tool progress, findings count, and risk level updating in real-time as tools complete
- **Interactive results browser** — navigate findings with arrow keys, expand/collapse details
- **Session resume** — if a scan crashes or you close the terminal, pick up where you left off

**Effort:** Medium. 3-4 hours. Much better user experience.

---

## Phase 7: Security Hardening

**Problem:** The tool itself has some security gaps (weak DB creds, thin command blocklist, no input validation on targets).

**Changes:**

- **Whitelist tool execution** — only allow specific known tool binaries, not arbitrary commands
- **Target validation** — validate IP/domain format before running any tools
- **Rate limiting** — prevent accidental DoS of targets
- **Audit logging** — log every command executed, every AI interaction, every database change
- **No hardcoded credentials** — use environment variables or a local config file outside the repo

**Effort:** Small. 1-2 hours. Important for responsible use.

---

## Suggested Build Order

| Priority | Phase | Impact | Effort |
|----------|-------|--------|--------|
| 1 | Phase 1: Setup Friction | High | Small |
| 2 | Phase 7: Security Hardening | High | Small |
| 3 | Phase 3: Smarter AI | High | Medium |
| 4 | Phase 2: More Tools | Very High | Medium |
| 5 | Phase 6: UI/UX | Medium | Medium |
| 6 | Phase 5: Reporting | High | Medium |
| 7 | Phase 4: Auto Pentest | Very High | Large |

Start with Phases 1 + 7 (quick wins, make it solid), then 3 + 2 (make it smart and capable), then 5 + 6 (make it pretty and client-ready), and finally Phase 4 (the big automation play).

---

## What Stays the Same

- MIT License
- Python 3
- Ollama as primary LLM runner
- CLI-first approach
- 100% local by default (cloud AI is opt-in)
- The core flow: target → recon → AI analysis → save → report
