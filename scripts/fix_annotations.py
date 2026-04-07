#!/usr/bin/env python3
"""
Fix annotation and hint line numbers that are misaligned after code upgrades.
Reads each snippet's code and asks Claude to correct line_numbers in hints and annotations.

Much cheaper than full upgrade — only fixes the line references, doesn't rewrite code.

Usage:
    ANTHROPIC_API_KEY=sk-... DATABASE_URL=postgresql://... python3 scripts/fix_annotations.py
"""

import json
import logging
import os
import sys
import time

import anthropic
import psycopg

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("fix")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "570"))

if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
conn = psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None)


def fetch_snippets():
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, title, solidity_code, hints, annotations, what_breaks
            FROM training_snippets
            ORDER BY created_at
            LIMIT %s
        """, (BATCH_SIZE,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def fix_line_numbers(snippet):
    code = snippet.get("solidity_code", "")
    code_lines = code.splitlines()

    # Mark each line with its type for Claude's context
    labeled_lines = []
    for i, line in enumerate(code_lines):
        stripped = line.strip()
        if not stripped:
            label = "EMPTY"
        elif stripped.startswith("///") or stripped.startswith("/**") or stripped.startswith("*"):
            label = "COMMENT"
        elif stripped in ('{', '}', '});'):
            label = "BRACE"
        elif stripped.startswith("event ") or stripped.startswith("error ") or stripped.startswith("emit "):
            label = "EVENT/ERROR"
        elif "function " in stripped:
            label = "FUNCTION"
        elif stripped.startswith("mapping") or stripped.startswith("uint") or stripped.startswith("address") or stripped.startswith("bool") or stripped.startswith("int"):
            label = "STATE_VAR"
        elif ".call" in stripped or ".transfer" in stripped or ".send(" in stripped:
            label = "EXTERNAL_CALL"
        elif "require(" in stripped or "revert " in stripped or "if (" in stripped:
            label = "CHECK"
        elif "+=" in stripped or "-=" in stripped or "=" in stripped:
            label = "STATE_CHANGE"
        else:
            label = "CODE"
        labeled_lines.append(f"L{i+1} [{label}]: {line}")

    numbered_code = "\n".join(labeled_lines)

    hints = snippet.get("hints", [])
    if isinstance(hints, str):
        try: hints = json.loads(hints)
        except: hints = []

    annotations = snippet.get("annotations", [])
    if isinstance(annotations, str):
        try: annotations = json.loads(annotations)
        except: annotations = []

    what_breaks = snippet.get("what_breaks", "") or ""
    attack_pattern = snippet.get("attack_pattern", "") or ""
    exploit_path = snippet.get("exploit_path", "") or ""

    prompt = f"""You are a smart contract security expert. Fix the line number references in this training snippet.

VULNERABILITY TYPE: {attack_pattern}
WHAT BREAKS: {what_breaks}
EXPLOIT PATH: {exploit_path[:300]}

HERE IS THE CODE (each line labeled with its type):
{numbered_code}

CURRENT ANNOTATIONS (line numbers are WRONG — need fixing):
{json.dumps(annotations, indent=2)}

CURRENT HINTS (line numbers may be wrong):
{json.dumps(hints, indent=2)}

YOUR TASK:

FOR ANNOTATIONS — find the exact lines:
1. BUG annotation: Find the line that IS the vulnerability. This should be a [FUNCTION], [STATE_CHANGE], [EXTERNAL_CALL], or [CHECK] line — NEVER a [COMMENT], [EMPTY], [BRACE], or [EVENT/ERROR] line.
   - For missing access control bugs: point to the function declaration line
   - For reentrancy bugs: point to the external call line
   - For oracle bugs: point to the line reading the oracle
   - For arithmetic bugs: point to the calculation line
   - For initialization bugs: point to the initialize function line

2. IMPACT annotation: Find the line where the damage happens — usually a transfer, a state read used for decisions, or a return value. Also must be [FUNCTION], [STATE_CHANGE], [EXTERNAL_CALL], or [CHECK] — NEVER a comment or brace.

FOR HINTS — progressive narrowing:
- Hint 1: Point to a broad area (2-3 function-level lines). Question about the area.
- Hint 2: Point to 2 specific lines that interact. Name the concern category.
- Hint 3: Point to the exact vulnerable line(s). Almost reveal the bug.
- All hint lines must be [FUNCTION], [STATE_CHANGE], [EXTERNAL_CALL], [CHECK], or [STATE_VAR] — never comments or braces.

HARD RULES:
- Line numbers must be between 1 and {len(code_lines)}
- NEVER point to a [COMMENT], [EMPTY], or [BRACE] line
- Keep the exact same explanation text — only change line_numbers and labels
- Output exactly 2 annotations: BUG and IMPACT
- Output exactly 3 hints (or same number as input if fewer)

Return ONLY valid JSON (no markdown fences):
{{
  "hints": [
    {{"line_numbers": [N1, N2], "text": "same hint 1 text", "cost": 0}},
    {{"line_numbers": [N3, N4], "text": "same hint 2 text", "cost": 1}},
    {{"line_numbers": [N5], "text": "same hint 3 text", "cost": 1}}
  ],
  "annotations": [
    {{"line_numbers": [BUG_LINE], "type": "vulnerable", "label": "BUG", "explanation": "same BUG explanation"}},
    {{"line_numbers": [IMPACT_LINE], "type": "vulnerable", "label": "IMPACT", "explanation": "same IMPACT explanation"}}
  ]
}}"""

    try:
        r = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        text = r.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            if text.endswith("```"): text = text[:-3]
            if text.startswith("json\n"): text = text[5:]
            text = text.strip()
        return json.loads(text)
    except Exception as e:
        log.error("Fix failed: %s", e)
        return None


def update_snippet(snippet_id, data):
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE training_snippets SET
                hints = %s,
                annotations = %s
            WHERE id = %s
        """, (
            json.dumps(data["hints"]),
            json.dumps(data["annotations"]),
            snippet_id,
        ))


def run():
    log.info("=" * 60)
    log.info("Annotation Line Number Fix")
    log.info("  Batch size: %d", BATCH_SIZE)
    log.info("=" * 60)

    snippets = fetch_snippets()
    log.info("Found %d snippets to fix", len(snippets))

    fixed = 0
    failed = 0

    for i, s in enumerate(snippets):
        log.info("[%d/%d] Fixing: %s", i + 1, len(snippets), (s['title'] or '?')[:50])

        data = fix_line_numbers(s)
        if data is None or "hints" not in data or "annotations" not in data:
            failed += 1
            continue

        # Validate: line numbers in range AND not pointing at comments/braces
        code_text_lines = (s.get("solidity_code", "") or "").splitlines()
        code_line_count = len(code_text_lines)
        valid = True
        annotation_issues = []

        for a in data["annotations"]:
            for ln in a.get("line_numbers", []):
                if ln < 1 or ln > code_line_count:
                    valid = False
                    annotation_issues.append(f"L{ln} out of range")
                else:
                    stripped = code_text_lines[ln - 1].strip()
                    if not stripped or stripped.startswith("///") or stripped.startswith("/**") or stripped.startswith("*") or stripped in ('{', '}', '});'):
                        annotation_issues.append(f"L{ln} is comment/brace: '{stripped[:30]}'")
                        # Don't fail — try to find a better line nearby
                        better = None
                        for offset in [1, -1, 2, -2, 3, -3]:
                            candidate = ln + offset
                            if 1 <= candidate <= code_line_count:
                                cand_text = code_text_lines[candidate - 1].strip()
                                if cand_text and not cand_text.startswith("///") and cand_text not in ('{', '}', '});'):
                                    better = candidate
                                    break
                        if better:
                            a["line_numbers"] = [better]
                            log.info("    Auto-corrected L%d -> L%d", ln, better)

        for h in data["hints"]:
            for ln in h.get("line_numbers", []):
                if ln < 1 or ln > code_line_count:
                    valid = False

        if not valid:
            log.warning("  Invalid line numbers out of range, skipping")
            if annotation_issues:
                log.warning("  Issues: %s", "; ".join(annotation_issues[:3]))
            failed += 1
            continue

        update_snippet(s["id"], data)
        fixed += 1

        if (i + 1) % 20 == 0:
            log.info("  Progress: %d fixed, %d failed", fixed, failed)

        time.sleep(0.5)

    conn.close()
    log.info("")
    log.info("=" * 60)
    log.info("Done. Fixed: %d, Failed: %d", fixed, failed)
    log.info("=" * 60)


if __name__ == "__main__":
    run()
