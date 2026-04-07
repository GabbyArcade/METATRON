#!/usr/bin/env python3
"""
METATRON - llm.py
Anthropic Claude API interface (with Ollama fallback).
Builds prompts, handles AI responses, runs tool dispatch loop.
"""

import re
import json
from config import (
    ANTHROPIC_API_KEY, CLAUDE_MODEL, MAX_TOKENS, TEMPERATURE,
    USE_OLLAMA, OLLAMA_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT,
    MAX_TOOL_LOOPS
)
from tools import run_tool_by_command
from search import handle_search_dispatch


# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are METATRON, an elite AI penetration testing assistant.
You are precise, technical, and direct. No fluff.

You have access to real tools. To use them, write tags in your response:

  [TOOL: nmap -sV 192.168.1.1]       → runs nmap or any whitelisted CLI tool
  [SEARCH: CVE-2021-44228 exploit]   → searches the web via DuckDuckGo

Rules:
- Always analyze scan data thoroughly before suggesting exploits
- List vulnerabilities with: name, severity (critical/high/medium/low), port, service
- For each vulnerability, suggest a concrete fix
- If you need more information, use [SEARCH:] or [TOOL:]
- Format vulnerabilities clearly so they can be saved to a database
- Be specific about CVE IDs when you know them
- Always give a final risk rating: CRITICAL / HIGH / MEDIUM / LOW

Output format for vulnerabilities (use this exactly):
VULN: <name> | SEVERITY: <level> | PORT: <port> | SERVICE: <service>
DESC: <description>
FIX: <fix recommendation>

Output format for exploits:
EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or description>
RESULT: <expected result>
NOTES: <any notes>

End your analysis with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence overall summary>
"""


# ─────────────────────────────────────────────
# CLAUDE API CALL
# ─────────────────────────────────────────────

def ask_claude(prompt: str) -> str:
    """
    Send a prompt to Claude via the Anthropic API.
    Returns the AI response string.
    """
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

        print(f"\n[*] Sending to Claude ({CLAUDE_MODEL})...")
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        response = message.content[0].text.strip()

        if not response:
            return "[!] Claude returned empty response."

        return response

    except Exception as e:
        error_str = str(e)
        if "api_key" in error_str.lower() or "authentication" in error_str.lower():
            return (
                "[!] Anthropic API key is missing or invalid.\n"
                "    Set it with: export ANTHROPIC_API_KEY='sk-ant-...'\n"
                "    Or add it to .env file in the METATRON directory."
            )
        if "rate_limit" in error_str.lower():
            return "[!] Rate limited by Anthropic API. Wait a moment and try again."
        return f"[!] Claude API error: {e}"


# ─────────────────────────────────────────────
# OLLAMA FALLBACK
# ─────────────────────────────────────────────

def ask_ollama(prompt: str) -> str:
    """
    Send a prompt to a local Ollama model.
    Used as fallback when USE_OLLAMA=True in config.
    """
    try:
        import requests
        payload = {
            "model":  OLLAMA_MODEL,
            "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
            "stream": False,
            "options": {
                "num_predict": MAX_TOKENS,
                "temperature": TEMPERATURE,
                "top_p": 0.9,
            }
        }

        print(f"\n[*] Sending to {OLLAMA_MODEL} (Ollama)...")
        resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()

        data = resp.json()
        response = data.get("response", "").strip()

        if not response:
            return "[!] Model returned empty response."
        return response

    except Exception as e:
        return f"[!] Ollama error: {e}"


# ─────────────────────────────────────────────
# UNIFIED ASK FUNCTION
# ─────────────────────────────────────────────

def ask_ai(prompt: str) -> str:
    """Route to Claude or Ollama based on config."""
    if USE_OLLAMA:
        return ask_ollama(prompt)
    return ask_claude(prompt)


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    """
    Extract all [TOOL: ...] and [SEARCH: ...] tags from AI response.
    Returns list of tuples: [("TOOL", "nmap -sV x.x.x.x"), ("SEARCH", "CVE...")]
    """
    calls = []

    tool_matches   = re.findall(r'\[TOOL:\s*(.+?)\]',   response)
    search_matches = re.findall(r'\[SEARCH:\s*(.+?)\]', response)

    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))

    return calls


def run_tool_calls(calls: list) -> str:
    """Execute all tool/search calls and return combined results string."""
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += output.strip() + "\n"

    return results


# ─────────────────────────────────────────────
# PARSER — extract structured data from AI output
# ─────────────────────────────────────────────

def parse_vulnerabilities(response: str) -> list:
    """Parse VULN: lines from AI response into dicts."""
    vulns = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("VULN:"):
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = lines[j].strip()
                if next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1

            if vuln["vuln_name"]:
                vulns.append(vuln)

        i += 1

    return vulns


def parse_exploits(response: str) -> list:
    """Parse EXPLOIT: lines from AI response into dicts."""
    exploits = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used":    "",
                "payload":      "",
                "result":       "unknown",
                "notes":        ""
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = lines[j].strip()
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return exploits


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    """Extract SUMMARY line from AI response."""
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return match.group(1).strip() if match else response[:500]


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    """
    Full analysis pipeline:
    1. Build initial prompt with scan data
    2. Send to Claude (or Ollama)
    3. Run tool dispatch loop if AI requests tools
    4. Parse structured output
    5. Return everything ready for db.py to save

    Returns dict with:
      - full_response   : complete AI text
      - vulnerabilities : list of parsed vuln dicts
      - exploits        : list of parsed exploit dicts
      - risk_level      : CRITICAL/HIGH/MEDIUM/LOW
      - summary         : short summary text
      - raw_scan        : original scan dump
    """

    # ── Step 1: initial prompt ──────────────────
    initial_prompt = f"""TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities, fixes, and suggest exploits where applicable."""

    conversation_context = initial_prompt
    final_response       = ""

    # ── Step 2: tool dispatch loop ──────────────
    for loop in range(MAX_TOOL_LOOPS):
        response = ask_ai(conversation_context)

        print(f"\n{'─'*60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─'*60}")
        print(response)

        final_response = response

        # check for tool calls
        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        # run all tool calls
        tool_results = run_tool_calls(tool_calls)

        # feed results back into conversation
        conversation_context = (
            f"{conversation_context}\n\n"
            f"[YOUR PREVIOUS RESPONSE]\n{response}\n\n"
            f"[TOOL RESULTS]\n{tool_results}\n\n"
            f"Continue your analysis with this new information. "
            f"If analysis is complete, give the final RISK_LEVEL and SUMMARY."
        )

    # ── Step 3: parse structured output ─────────
    vulnerabilities = parse_vulnerabilities(final_response)
    exploits        = parse_exploits(final_response)
    risk_level      = parse_risk_level(final_response)
    summary         = parse_summary(final_response)

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    return {
        "full_response":   final_response,
        "vulnerabilities": vulnerabilities,
        "exploits":        exploits,
        "risk_level":      risk_level,
        "summary":         summary,
        "raw_scan":        raw_scan
    }


# ─────────────────────────────────────────────
# INTERACTIVE CHAT (post-scan follow-up)
# ─────────────────────────────────────────────

def chat_about_scan(target: str, scan_data: str, ai_analysis: str):
    """
    Let the user ask follow-up questions about a completed scan.
    Maintains conversation context.
    """
    context = f"""You previously analyzed target {target}.

Here is the scan data:
{scan_data[:3000]}

Here is your analysis:
{ai_analysis[:3000]}

The user wants to ask follow-up questions. Answer precisely and technically."""

    print("\n\033[94m[*] Chat mode — ask questions about this scan. Type 'exit' to quit.\033[0m")

    while True:
        question = input("\n\033[36mmetatron-chat> \033[0m").strip()
        if not question or question.lower() in ("exit", "quit", "back"):
            break

        full_prompt = f"{context}\n\nUser question: {question}"
        response = ask_ai(full_prompt)
        print(f"\n{response}")

        # Update context with this exchange
        context += f"\n\nUser: {question}\nAssistant: {response}"


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — direct AI query ]\n")

    if USE_OLLAMA:
        print("[*] Using Ollama (local)")
        try:
            import requests
            r = requests.get("http://localhost:11434", timeout=5)
            print("[+] Ollama is running.")
        except Exception:
            print("[!] Ollama not reachable. Run: ollama serve")
            exit(1)
    else:
        print("[*] Using Claude API")
        if not ANTHROPIC_API_KEY:
            print("[!] No API key set. Run: export ANTHROPIC_API_KEY='sk-ant-...'")
            exit(1)
        print("[+] API key found.")

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
