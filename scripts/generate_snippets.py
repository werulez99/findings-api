#!/usr/bin/env python3
"""
Training snippet generator for Valves Security.
Uses Claude API to generate purpose-built Solidity training snippets
from real audit finding clusters.

Usage:
    ANTHROPIC_API_KEY=sk-... python scripts/generate_snippets.py

Requires: DATABASE_URL, ANTHROPIC_API_KEY
Optional: DRY_RUN=true, CLUSTER_SLUG=vault-share-accounting (single cluster),
          SNIPPETS_PER_CLUSTER=3, DIFFICULTIES=beginner,intermediate,advanced
"""

import json
import logging
import os
import sys
import time
import uuid

import anthropic

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("gen_snippets")

# ── Config ──
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() in ("1", "true", "yes")
CLUSTER_SLUG = os.environ.get("CLUSTER_SLUG", "")  # empty = all clusters
SNIPPETS_PER_DIFFICULTY = int(os.environ.get("SNIPPETS_PER_DIFFICULTY", "1"))
DIFFICULTIES = os.environ.get("DIFFICULTIES", "beginner,intermediate,advanced").split(",")

if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """You are a smart contract security educator building training material for an auditor training platform.

Your job: generate a minimal, realistic Solidity code snippet that demonstrates a specific vulnerability pattern. The snippet will be shown to auditors-in-training who must identify the bug.

RULES:
1. 20-50 lines of clean, compilable Solidity (pragma solidity ^0.8.0;)
2. Contains EXACTLY ONE vulnerability — no more, no less
3. Realistic variable names, struct names, function signatures — it should look like real production code
4. NO comments naming the bug. NO "// vulnerable" markers. The code must look normal.
5. Include necessary imports as comments (e.g., // import "@openzeppelin/...")
6. The vulnerability must be non-trivial but findable by a trained eye

DIFFICULTY LEVELS:
- beginner: Bug is in a single function, straightforward pattern (missing check, wrong modifier)
- intermediate: Bug requires understanding interaction between 2-3 functions or state variables
- advanced: Bug requires understanding complex state, cross-function interaction, or subtle math

OUTPUT FORMAT: Return ONLY valid JSON (no markdown, no code fences):
{
  "title": "Short descriptive title for this challenge (do NOT reveal the bug)",
  "solidity_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.0;\\n\\n...",
  "hints": [
    {"line_numbers": [7], "text": "What does this function read? Can the return value be influenced externally?", "cost": 0},
    {"line_numbers": [7, 22], "text": "Trace what happens when these two values diverge.", "cost": 1},
    {"line_numbers": [7, 20, 22], "text": "What if someone sends tokens directly without calling deposit()? Follow the math.", "cost": 1}
  ],
  "annotations": [
    {"line_numbers": [7], "type": "vulnerable", "label": "VULNERABLE", "explanation": "totalAssets reads balanceOf directly — anyone can inflate this via direct transfer"},
    {"line_numbers": [22], "type": "vulnerable", "label": "IMPACT", "explanation": "When totalAssets is inflated, this division rounds down to 0 for small depositors"}
  ],
  "invariant": "Share price must remain proportional to deposited assets.",
  "what_breaks": "Direct token transfers inflate totalAssets without minting shares, breaking the share price calculation.",
  "exploit_path": "1. Deposit 1 wei to mint 1 share. 2. Transfer 1M tokens directly to vault. 3. Victim deposits — gets 0 shares due to rounding. 4. Attacker redeems for all assets.",
  "why_missed": "The math works correctly for normal deposits. The edge case is external token transfers that bypass the deposit function."
}"""


def fetch_clusters(conn):
    """Fetch clusters to generate snippets for."""
    with conn.cursor() as cur:
        if CLUSTER_SLUG:
            cur.execute(
                "SELECT id, name, slug, description, invariant_template, difficulty, finding_count "
                "FROM pattern_clusters WHERE slug = %s", (CLUSTER_SLUG,)
            )
        else:
            cur.execute(
                "SELECT id, name, slug, description, invariant_template, difficulty, finding_count "
                "FROM pattern_clusters WHERE finding_count >= 10 ORDER BY finding_count DESC"
            )
        return cur.fetchall()


def fetch_sample_findings(conn, cluster_id, limit=8):
    """Fetch sample findings from a cluster for context."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT f.title, f.short_summary, f.severity::text
            FROM findings f
            JOIN finding_cluster_map fcm ON f.id = fcm.finding_id
            WHERE fcm.cluster_id = %s
            ORDER BY f.risk_score DESC NULLS LAST
            LIMIT %s
        """, (cluster_id, limit))
        return cur.fetchall()


def generate_snippet(cluster_name, cluster_desc, invariant, difficulty, sample_findings):
    """Call Claude API to generate a training snippet."""
    findings_context = "\n".join(
        f"- [{sev}] {title}: {(summary or '')[:150]}"
        for title, summary, sev in sample_findings
    )

    user_prompt = f"""Generate a {difficulty}-level Solidity training snippet for this vulnerability pattern:

PATTERN: {cluster_name}
DESCRIPTION: {cluster_desc}
CORE INVARIANT: {invariant}
DIFFICULTY: {difficulty}

These are real findings in this category (use them as inspiration, do NOT copy directly):
{findings_context}

Generate a clean, realistic snippet that demonstrates this pattern. Return ONLY the JSON object."""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = response.content[0].text.strip()
        # Strip markdown fences if present
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            # Also handle ```json prefix
            if text.startswith("json\n"):
                text = text[5:]
            text = text.strip()

        data = json.loads(text)
        return data
    except json.JSONDecodeError as e:
        log.error("Failed to parse JSON from Claude: %s\nRaw: %s", e, text[:500])
        return None
    except Exception as e:
        log.error("Claude API error: %s", e)
        return None


def insert_snippet(conn, cluster_id, difficulty, data):
    """Insert a generated snippet into the database."""
    snippet_id = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO training_snippets
                (id, cluster_id, difficulty, title, solidity_code, hints, annotations,
                 invariant, exploit_path, what_breaks, why_missed, attack_pattern)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            snippet_id,
            cluster_id,
            difficulty,
            data.get("title", "Untitled Challenge"),
            data.get("solidity_code", ""),
            json.dumps(data.get("hints", [])),
            json.dumps(data.get("annotations", [])),
            data.get("invariant", ""),
            data.get("exploit_path", ""),
            data.get("what_breaks", ""),
            data.get("why_missed", ""),
            data.get("attack_pattern", ""),
        ))
    return snippet_id


def run():
    import psycopg

    log.info("=" * 60)
    log.info("Snippet Generation — Valves Security")
    log.info("  DRY_RUN = %s", DRY_RUN)
    log.info("  CLUSTER_SLUG = %s", CLUSTER_SLUG or "(all)")
    log.info("  DIFFICULTIES = %s", DIFFICULTIES)
    log.info("  SNIPPETS_PER_DIFFICULTY = %d", SNIPPETS_PER_DIFFICULTY)
    log.info("=" * 60)

    conn = psycopg.connect(DATABASE_URL)
    conn.autocommit = False

    clusters = fetch_clusters(conn)
    log.info("Found %d clusters to process", len(clusters))

    total_generated = 0
    total_failed = 0

    for cid, cname, cslug, cdesc, cinvariant, cdifficulty, cfcount in clusters:
        log.info("")
        log.info("━" * 50)
        log.info("Cluster: %s (%d findings)", cname, cfcount)

        samples = fetch_sample_findings(conn, cid)
        log.info("  Sample findings: %d", len(samples))

        for difficulty in DIFFICULTIES:
            for i in range(SNIPPETS_PER_DIFFICULTY):
                log.info("  Generating %s snippet %d/%d...", difficulty, i + 1, SNIPPETS_PER_DIFFICULTY)

                if DRY_RUN:
                    log.info("  [DRY RUN] Would generate %s snippet for %s", difficulty, cname)
                    total_generated += 1
                    continue

                data = generate_snippet(cname, cdesc, cinvariant, difficulty, samples)
                if data is None:
                    total_failed += 1
                    log.warning("  FAILED to generate snippet")
                    continue

                # Validate
                code = data.get("solidity_code", "")
                if len(code) < 50:
                    log.warning("  Snippet too short (%d chars), skipping", len(code))
                    total_failed += 1
                    continue

                with conn.transaction():
                    sid = insert_snippet(conn, cid, difficulty, data)

                log.info("  ✓ Generated: %s (id=%s)", data.get("title", "?")[:60], sid)
                total_generated += 1

                # Rate limit: ~1 request per second
                time.sleep(1.5)

    # Update snippet counts
    if not DRY_RUN:
        with conn.transaction():
            conn.execute("""
                UPDATE pattern_clusters SET snippet_count = COALESCE(sub.cnt, 0)
                FROM (
                    SELECT cluster_id, COUNT(*) as cnt
                    FROM training_snippets
                    GROUP BY cluster_id
                ) sub
                WHERE pattern_clusters.id = sub.cluster_id
            """)

    conn.close()

    log.info("")
    log.info("=" * 60)
    log.info("Done. Generated: %d, Failed: %d", total_generated, total_failed)
    log.info("=" * 60)


if __name__ == "__main__":
    run()
