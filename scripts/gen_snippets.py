#!/usr/bin/env python3
"""
Training snippet generator using Claude API + Supabase CLI for DB access.
Avoids direct DB password — uses `supabase db query --linked` for all DB ops.

Usage:
    ANTHROPIC_API_KEY=sk-... python3 scripts/gen_snippets.py

Optional: CLUSTER_SLUG=vault-share-accounting (process single cluster)
"""

import json
import logging
import os
import subprocess
import sys
import time
import uuid

import anthropic

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("gen")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

CLUSTER_SLUG = os.environ.get("CLUSTER_SLUG", "")

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

import psycopg

_conn = None
def get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg.connect(DATABASE_URL)
        _conn.autocommit = True
    return _conn


def db_query(sql: str) -> list[dict]:
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(sql)
        cols = [desc[0] for desc in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def db_exec(sql: str) -> bool:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql)
        return True
    except Exception as e:
        log.error("DB exec error: %s", e)
        return False


def sql_escape(s: str) -> str:
    """Escape a string for SQL."""
    if s is None:
        return "NULL"
    return "'" + str(s).replace("'", "''") + "'"


SYSTEM_PROMPT = """You are a smart contract security educator building training material.

Generate a minimal, realistic Solidity code snippet that demonstrates a specific vulnerability pattern.

RULES:
1. Write 25-50 lines of clean Solidity (pragma solidity ^0.8.0;)
2. EXACTLY ONE vulnerability — no more, no less
3. Realistic names and structure — looks like real production code
4. NO comments naming the bug. NO "vulnerable" markers. Code looks normal.
5. Include imports as comments if needed
6. Vulnerability must be non-trivial but findable

DIFFICULTY:
- beginner: Single function bug, straightforward pattern
- intermediate: Requires understanding 2-3 function interactions
- advanced: Complex state, cross-function, subtle math

Return ONLY valid JSON (no markdown fences, no ```):
{
  "title": "Short challenge title (NOT revealing the bug)",
  "solidity_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.0;\\n...",
  "hints": [
    {"line_numbers": [N], "text": "Draw attention to area without naming bug", "cost": 0},
    {"line_numbers": [N, M], "text": "Point at mechanism", "cost": 1},
    {"line_numbers": [N, M, P], "text": "Almost give it away", "cost": 1}
  ],
  "annotations": [
    {"line_numbers": [N], "type": "vulnerable", "label": "VULNERABLE", "explanation": "What is wrong"},
    {"line_numbers": [M], "type": "vulnerable", "label": "IMPACT", "explanation": "What the impact is"}
  ],
  "invariant": "The core invariant violated",
  "what_breaks": "Specific break mechanism",
  "exploit_path": "1. First step. 2. Second step. 3. Third step. 4. Impact.",
  "why_missed": "Why auditors miss this"
}"""


def generate_snippet(cluster_name: str, desc: str, invariant: str, difficulty: str, samples: str) -> dict | None:
    """Call Claude API to generate one snippet."""
    user_prompt = f"""Generate a {difficulty}-level Solidity training snippet.

PATTERN: {cluster_name}
DESCRIPTION: {desc}
CORE INVARIANT: {invariant}
DIFFICULTY: {difficulty}

Real findings from this category (inspiration only):
{samples}

Return ONLY the JSON object."""

    try:
        r = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        text = r.content[0].text.strip()
        # Strip markdown fences
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[:-3]
            if text.startswith("json\n"):
                text = text[5:]
            text = text.strip()

        return json.loads(text)
    except json.JSONDecodeError as e:
        log.error("JSON parse error: %s — raw: %s", e, text[:200])
        return None
    except Exception as e:
        log.error("Claude API error: %s", e)
        return None


def insert_snippet(cluster_id: str, difficulty: str, data: dict) -> bool:
    """Insert snippet via Supabase CLI."""
    sql = f"""INSERT INTO training_snippets
        (id, cluster_id, difficulty, title, solidity_code, hints, annotations,
         invariant, exploit_path, what_breaks, why_missed, attack_pattern)
    VALUES (
        gen_random_uuid(),
        '{cluster_id}',
        {sql_escape(difficulty)},
        {sql_escape(data.get('title', 'Untitled'))},
        {sql_escape(data.get('solidity_code', ''))},
        {sql_escape(json.dumps(data.get('hints', [])))},
        {sql_escape(json.dumps(data.get('annotations', [])))},
        {sql_escape(data.get('invariant', ''))},
        {sql_escape(data.get('exploit_path', ''))},
        {sql_escape(data.get('what_breaks', ''))},
        {sql_escape(data.get('why_missed', ''))},
        {sql_escape(data.get('attack_pattern', ''))}
    );"""
    return db_exec(sql)


def run():
    log.info("=" * 60)
    log.info("Snippet Generation (CLI mode)")
    log.info("  Target: %s", CLUSTER_SLUG or "all clusters with 20+ findings")
    log.info("=" * 60)

    # Fetch clusters
    if CLUSTER_SLUG:
        where = f"WHERE slug = '{CLUSTER_SLUG}'"
    else:
        where = "WHERE finding_count >= 20"

    clusters = db_query(f"""
        SELECT id, name, slug, description, invariant_template, finding_count
        FROM pattern_clusters {where}
        ORDER BY finding_count DESC
    """)

    log.info("Found %d clusters", len(clusters))

    total_ok = 0
    total_fail = 0

    for c in clusters:
        cid = c["id"]
        cname = c["name"]
        cslug = c["slug"]

        log.info("")
        log.info("━━━ %s (%d findings) ━━━", cname, c["finding_count"])

        # Check existing snippets per difficulty
        existing = db_query(f"SELECT difficulty, COUNT(*) as cnt FROM training_snippets WHERE cluster_id = '{cid}' GROUP BY difficulty")
        existing_by_diff = {r["difficulty"]: r["cnt"] for r in existing}
        total_existing = sum(existing_by_diff.values())
        TARGET_PER_DIFF = 5
        if total_existing >= TARGET_PER_DIFF * 3:
            log.info("  Already has %d snippets (%d target), skipping", total_existing, TARGET_PER_DIFF * 3)
            continue

        # Fetch sample findings
        samples_rows = db_query(f"""
            SELECT f.title, f.short_summary, f.severity::text
            FROM findings f
            JOIN finding_cluster_map fcm ON f.id = fcm.finding_id
            WHERE fcm.cluster_id = '{cid}'
            ORDER BY f.risk_score DESC NULLS LAST
            LIMIT 6
        """)
        samples_text = "\n".join(
            f"- [{r['severity']}] {r['title'][:80]}: {(r.get('short_summary') or '')[:100]}"
            for r in samples_rows
        )

        for difficulty in ["beginner", "intermediate", "advanced"]:
            existing_for_diff = existing_by_diff.get(difficulty, 0)
            needed = TARGET_PER_DIFF - existing_for_diff
            if needed <= 0:
                log.info("  [%s] Already has %d, skipping", difficulty, existing_for_diff)
                continue
            for gen_idx in range(needed):
                log.info("  [%s] Generating %d/%d...", difficulty, gen_idx + 1, needed)

                data = generate_snippet(
                    cname, c["description"], c["invariant_template"], difficulty, samples_text
                )

                if data is None:
                    total_fail += 1
                    log.warning("  [%s] FAILED", difficulty)
                    continue

                code = data.get("solidity_code", "")
                if len(code) < 50:
                    total_fail += 1
                    log.warning("  [%s] Code too short (%d chars)", difficulty, len(code))
                    continue

                ok = insert_snippet(cid, difficulty, data)
                if ok:
                    total_ok += 1
                    log.info("  [%s] ✓ %s", difficulty, data.get("title", "?")[:60])
                else:
                    total_fail += 1
                    log.warning("  [%s] DB insert failed", difficulty)

                time.sleep(1.2)

    # Update counts
    log.info("")
    log.info("Updating snippet counts...")
    db_exec("""
        UPDATE pattern_clusters SET snippet_count = COALESCE(sub.cnt, 0)
        FROM (SELECT cluster_id, COUNT(*) as cnt FROM training_snippets GROUP BY cluster_id) sub
        WHERE pattern_clusters.id = sub.cluster_id;
    """)

    # Show results
    results = db_query("SELECT slug, name, snippet_count FROM pattern_clusters WHERE snippet_count > 0 ORDER BY snippet_count DESC")
    log.info("")
    log.info("=" * 60)
    log.info("Results: %d generated, %d failed", total_ok, total_fail)
    for r in results:
        log.info("  %-30s %d snippets", r["name"], r["snippet_count"])
    log.info("=" * 60)


if __name__ == "__main__":
    run()
