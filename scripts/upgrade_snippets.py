#!/usr/bin/env python3
"""
Upgrade existing snippets with better code quality and deeper explanations.
Replaces each snippet with an improved version.

Usage:
    ANTHROPIC_API_KEY=sk-... DATABASE_URL=postgresql://... python3 scripts/upgrade_snippets.py
    CLUSTER_SLUG=reentrancy  (optional: single cluster)
"""

import json
import logging
import os
import sys
import time

import anthropic
import psycopg

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("upgrade")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
CLUSTER_SLUG = os.environ.get("CLUSTER_SLUG", "")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))

if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
conn = psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None)


UPGRADE_PROMPT = """You are upgrading a Solidity training snippet to production quality.

CURRENT SNIPPET:
Title: {title}
Difficulty: {difficulty}
Sub-pattern: {attack_pattern}
Code:
```solidity
{code}
```

Current hints: {hints}
Current annotations: {annotations}
Current invariant: {invariant}
Current exploit_path: {exploit_path}
Current what_breaks: {what_breaks}
Current why_missed: {why_missed}

UPGRADE REQUIREMENTS:

1. CODE QUALITY — make it look like real production Solidity:
   - Add NatSpec comments (/// @notice, /// @param, /// @dev) on the contract and key functions
   - Add at least 2 events and emit them in state-changing functions
   - Use custom errors (error InsufficientBalance();) instead of string reverts where appropriate
   - Use realistic contract/function/variable names from real DeFi protocols
   - Add a few constants for magic numbers (MAX_SLIPPAGE, MIN_COLLATERAL_RATIO, etc.)
   - Include proper import comments (// import "@openzeppelin/...")
   - Keep the same vulnerability — do NOT change what the bug is
   - Target 40-60 lines. Not shorter, not much longer.

2. EXPLANATION DEPTH — make reveals more educational:
   - INVARIANT: 1-2 sentences. A precise formal statement of what must hold. Include the mathematical relationship if applicable.
   - WHAT BREAKS: 2-3 sentences. Name the specific mechanism. Include what state becomes inconsistent.
   - EXPLOIT PATH: 5-6 numbered steps with CONCRETE numbers. E.g., "1. Attacker deposits 1 ETH as collateral (worth $2000 at current oracle price). 2. Oracle price becomes stale — real price drops to $1500 but oracle still reports $2000..."
   - WHY MISSED: 2-3 sentences. Explain the specific cognitive trap. What does the auditor see that makes them think the code is safe? What assumption do they make that is wrong?

3. HINTS — keep the same 3-hint progressive structure but make them slightly better:
   - Hint 1 (free): Draw attention to the vulnerable area WITHOUT naming what's wrong. Ask a question.
   - Hint 2 (-1pt): Point at the interaction between two code elements. Name the category of concern.
   - Hint 3 (-1pt): Almost give it away. Describe what could go wrong in one sentence.

4. ANNOTATIONS — after reveal, these appear inline in the code:
   - 2-3 annotations on the specific vulnerable lines
   - Each annotation: label (VULNERABLE/IMPACT/ROOT CAUSE), explanation (1-2 sentences, specific)

Return ONLY valid JSON (no markdown fences):
{{
  "title": "{title}",
  "solidity_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.19;\\n\\n...",
  "hints": [
    {{"line_numbers": [N], "text": "question about this area", "cost": 0}},
    {{"line_numbers": [N, M], "text": "more specific hint", "cost": 1}},
    {{"line_numbers": [N, M, P], "text": "almost gives it away", "cost": 1}}
  ],
  "annotations": [
    {{"line_numbers": [N], "type": "vulnerable", "label": "VULNERABLE", "explanation": "specific explanation"}},
    {{"line_numbers": [M], "type": "vulnerable", "label": "IMPACT", "explanation": "what attacker achieves"}},
    {{"line_numbers": [P], "type": "vulnerable", "label": "ROOT CAUSE", "explanation": "why this is wrong"}}
  ],
  "invariant": "Precise formal invariant statement (1-2 sentences, include math if applicable)",
  "what_breaks": "Specific mechanism of the break (2-3 sentences, name the inconsistent state)",
  "exploit_path": "1. First step with concrete numbers. 2. Second step. 3. Third step. 4. Fourth step. 5. Impact with dollar amounts or percentages.",
  "why_missed": "The cognitive trap (2-3 sentences). What the auditor assumes. Why that assumption is wrong."
}}"""


def fetch_snippets():
    with conn.cursor() as cur:
        if CLUSTER_SLUG:
            cur.execute("""
                SELECT ts.id, ts.title, ts.difficulty, ts.solidity_code, ts.hints, ts.annotations,
                       ts.invariant, ts.exploit_path, ts.what_breaks, ts.why_missed, ts.attack_pattern,
                       pc.name as cluster_name
                FROM training_snippets ts
                JOIN pattern_clusters pc ON ts.cluster_id = pc.id
                WHERE pc.slug = %s
                ORDER BY ts.created_at
                LIMIT %s
            """, (CLUSTER_SLUG, BATCH_SIZE))
        else:
            cur.execute("""
                SELECT ts.id, ts.title, ts.difficulty, ts.solidity_code, ts.hints, ts.annotations,
                       ts.invariant, ts.exploit_path, ts.what_breaks, ts.why_missed, ts.attack_pattern,
                       pc.name as cluster_name
                FROM training_snippets ts
                JOIN pattern_clusters pc ON ts.cluster_id = pc.id
                ORDER BY pc.finding_count DESC, ts.created_at
                LIMIT %s
            """, (BATCH_SIZE,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def upgrade_snippet(s):
    hints_str = json.dumps(s['hints']) if isinstance(s['hints'], list) else str(s['hints'])
    annot_str = json.dumps(s['annotations']) if isinstance(s['annotations'], list) else str(s['annotations'])

    prompt = UPGRADE_PROMPT.format(
        title=s['title'] or 'Untitled',
        difficulty=s['difficulty'] or 'intermediate',
        attack_pattern=s['attack_pattern'] or 'unknown',
        code=s['solidity_code'] or '',
        hints=hints_str[:500],
        annotations=annot_str[:500],
        invariant=s['invariant'] or '',
        exploit_path=s['exploit_path'] or '',
        what_breaks=s['what_breaks'] or '',
        why_missed=s['why_missed'] or '',
    )

    try:
        r = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=3000,
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
        log.error("Upgrade failed: %s", e)
        return None


def update_snippet(snippet_id, data):
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE training_snippets SET
                solidity_code = %s,
                hints = %s,
                annotations = %s,
                invariant = %s,
                exploit_path = %s,
                what_breaks = %s,
                why_missed = %s
            WHERE id = %s
        """, (
            data.get("solidity_code", ""),
            json.dumps(data.get("hints", [])),
            json.dumps(data.get("annotations", [])),
            data.get("invariant", ""),
            data.get("exploit_path", ""),
            data.get("what_breaks", ""),
            data.get("why_missed", ""),
            snippet_id,
        ))


def run():
    log.info("=" * 60)
    log.info("Snippet Quality Upgrade")
    log.info("  Target: %s", CLUSTER_SLUG or "top clusters")
    log.info("  Batch size: %d", BATCH_SIZE)
    log.info("=" * 60)

    snippets = fetch_snippets()
    log.info("Found %d snippets to upgrade", len(snippets))

    upgraded = 0
    failed = 0

    for i, s in enumerate(snippets):
        log.info("[%d/%d] Upgrading: %s [%s] (%s)",
                 i + 1, len(snippets), s['title'][:50], s['difficulty'], s['cluster_name'])

        data = upgrade_snippet(s)
        if data is None:
            failed += 1
            log.warning("  FAILED")
            continue

        code = data.get("solidity_code", "")
        if len(code) < 100:
            failed += 1
            log.warning("  Code too short (%d chars)", len(code))
            continue

        update_snippet(s['id'], data)
        upgraded += 1

        # Quick quality check
        lines = code.splitlines()
        has_natspec = any('///' in l or '/**' in l for l in lines)
        has_events = any('event ' in l for l in lines)
        ep_len = len(data.get('exploit_path', ''))
        log.info("  ✓ %d lines | NatSpec:%s | Events:%s | ExploitPath:%dch",
                 len(lines), has_natspec, has_events, ep_len)

        time.sleep(0.8)

    conn.close()
    log.info("")
    log.info("=" * 60)
    log.info("Done. Upgraded: %d, Failed: %d", upgraded, failed)
    log.info("=" * 60)


if __name__ == "__main__":
    run()
