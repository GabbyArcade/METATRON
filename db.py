#!/usr/bin/env python3
"""
METATRON - db.py
SQLite database — zero config, no server needed.
Auto-creates tables on first run.
"""

import sqlite3
from datetime import datetime
from config import DB_PATH


# ─────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────

def get_connection():
    """Returns a SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ─────────────────────────────────────────────
# AUTO-CREATE TABLES
# ─────────────────────────────────────────────

def init_db():
    """Create all tables if they don't exist. Safe to call every startup."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            sl_no     INTEGER PRIMARY KEY AUTOINCREMENT,
            target    TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            status    TEXT DEFAULT 'active'
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no       INTEGER,
            vuln_name   TEXT,
            severity    TEXT,
            port        TEXT,
            service     TEXT,
            description TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS fixes (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no    INTEGER,
            vuln_id  INTEGER,
            fix_text TEXT,
            source   TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no),
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS exploits_attempted (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no        INTEGER,
            exploit_name TEXT,
            tool_used    TEXT,
            payload      TEXT,
            result       TEXT,
            notes        TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS summary (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no        INTEGER,
            raw_scan     TEXT,
            ai_analysis  TEXT,
            risk_level   TEXT,
            generated_at TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no)
        )
    """)

    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# WRITE FUNCTIONS
# ─────────────────────────────────────────────

def create_session(target: str) -> int:
    """Insert new row into history. Returns sl_no."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO history (target, scan_date, status) VALUES (?, ?, ?)",
        (target, now, "active")
    )
    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                       port: str, service: str, description: str) -> int:
    """Insert a vulnerability. Returns its id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO vulnerabilities (sl_no, vuln_name, severity, port, service, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (sl_no, vuln_name, severity, port, service, description))
    conn.commit()
    vuln_id = c.lastrowid
    conn.close()
    return vuln_id


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (?, ?, ?, ?)
    """, (sl_no, vuln_id, fix_text, source))
    conn.commit()
    conn.close()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO exploits_attempted (sl_no, exploit_name, tool_used, payload, result, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (sl_no,
          str(exploit_name or "")[:500],
          str(tool_used or "")[:200],
          str(payload or ""),
          str(result or "")[:500],
          str(notes or "")))
    conn.commit()
    conn.close()


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    """Insert the full session summary."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
        VALUES (?, ?, ?, ?, ?)
    """, (sl_no, raw_scan, ai_analysis, risk_level, now))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# READ FUNCTIONS
# ─────────────────────────────────────────────

def get_all_history():
    """Return all rows from history ordered by newest first."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_session(sl_no: int) -> dict:
    """Return everything linked to a sl_no across all tables."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM history WHERE sl_no = ?", (sl_no,))
    history = c.fetchone()

    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    vulns = c.fetchall()

    c.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,))
    fixes = c.fetchall()

    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    exploits = c.fetchall()

    c.execute("SELECT * FROM summary WHERE sl_no = ?", (sl_no,))
    summary = c.fetchone()

    conn.close()

    return {
        "history":   history,
        "vulns":     vulns,
        "fixes":     fixes,
        "exploits":  exploits,
        "summary":   summary
    }


def get_vulnerabilities(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_fixes(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_exploits(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────
# EDIT FUNCTIONS
# ─────────────────────────────────────────────

def edit_vulnerability(vuln_id: int, field: str, value: str):
    """Edit a single field in vulnerabilities by id."""
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"UPDATE vulnerabilities SET {field} = ? WHERE id = ?", (value, vuln_id))
    conn.commit()
    conn.close()
    print(f"[+] vulnerabilities.{field} updated for id={vuln_id}")


def edit_fix(fix_id: int, fix_text: str):
    """Edit the fix_text of a fix by id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE fixes SET fix_text = ? WHERE id = ?", (fix_text, fix_id))
    conn.commit()
    conn.close()
    print(f"[+] fix id={fix_id} updated.")


def edit_exploit(exploit_id: int, field: str, value: str):
    """Edit a single field in exploits_attempted by id."""
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"UPDATE exploits_attempted SET {field} = ? WHERE id = ?", (value, exploit_id))
    conn.commit()
    conn.close()
    print(f"[+] exploits_attempted.{field} updated for id={exploit_id}")


def edit_summary_risk(sl_no: int, risk_level: str):
    """Update the risk level on a summary."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE summary SET risk_level = ? WHERE sl_no = ?", (risk_level, sl_no))
    conn.commit()
    conn.close()
    print(f"[+] Summary risk_level updated for SL#{sl_no}")


# ─────────────────────────────────────────────
# DELETE FUNCTIONS
# ─────────────────────────────────────────────

def delete_vulnerability(vuln_id: int):
    """Delete a single vulnerability and its linked fixes."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE vuln_id = ?", (vuln_id,))
    c.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    conn.commit()
    conn.close()
    print(f"[+] Vulnerability id={vuln_id} and its fixes deleted.")


def delete_exploit(exploit_id: int):
    """Delete a single exploit attempt."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM exploits_attempted WHERE id = ?", (exploit_id,))
    conn.commit()
    conn.close()
    print(f"[+] Exploit id={exploit_id} deleted.")


def delete_fix(fix_id: int):
    """Delete a single fix."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE id = ?", (fix_id,))
    conn.commit()
    conn.close()
    print(f"[+] Fix id={fix_id} deleted.")


def delete_full_session(sl_no: int):
    """Wipe everything linked to a sl_no across all 5 tables."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes             WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM vulnerabilities    WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM summary            WHERE sl_no = ?", (sl_no,))
    c.execute("DELETE FROM history            WHERE sl_no = ?", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Full session SL#{sl_no} deleted from all tables.")


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'═'*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═'*60}")

    print("\n[ VULNERABILITIES ]")
    if data["vulns"]:
        for v in data["vulns"]:
            print(f"  id={v[0]} | {v[2]} | Severity: {v[3]} | Port: {v[4]} | Service: {v[5]}")
            print(f"           {v[6]}")
    else:
        print("  None recorded.")

    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")

    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")

    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Generated  : {s[5]}")
        print(f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()


# ─────────────────────────────────────────────
# INIT ON IMPORT
# ─────────────────────────────────────────────

init_db()


if __name__ == "__main__":
    init_db()
    print(f"[+] SQLite database ready: {DB_PATH}")
    print("[+] All tables created/verified.")
