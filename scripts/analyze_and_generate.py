#!/usr/bin/env python3
"""
Data-first snippet generation for Valves Security.

Pipeline:
1. Fetch ALL findings for a cluster from DB
2. Send to Claude to analyze and group by actual root cause
3. Identify distinct sub-patterns (deduplicated)
4. Generate one snippet per real sub-pattern

Usage:
    ANTHROPIC_API_KEY=sk-... DATABASE_URL=postgresql://... python3 scripts/analyze_and_generate.py

Optional:
    CLUSTER_SLUG=oracle-dependency  (single cluster, default: all)
    MAX_SNIPPETS_PER_CLUSTER=10     (default: 10)
"""

import json
import logging
import os
import sys
import time

import anthropic
import psycopg

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("analyze")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
CLUSTER_SLUG = os.environ.get("CLUSTER_SLUG", "")
MAX_SNIPPETS = int(os.environ.get("MAX_SNIPPETS_PER_CLUSTER", "15"))

if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
conn = psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None)


def sql_escape(s):
    if s is None: return "NULL"
    return "'" + str(s).replace("'", "''") + "'"


def fetch_clusters():
    with conn.cursor() as cur:
        if CLUSTER_SLUG:
            cur.execute("SELECT id, name, slug, description, invariant_template, finding_count FROM pattern_clusters WHERE slug = %s", (CLUSTER_SLUG,))
        else:
            cur.execute("SELECT id, name, slug, description, invariant_template, finding_count FROM pattern_clusters WHERE finding_count >= 20 ORDER BY finding_count DESC")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def fetch_findings_for_cluster(cluster_id, limit=200):
    """Fetch findings, prioritizing HIGH severity and diverse protocols."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT f.title, f.short_summary, f.severity::text, f.protocol_name, f.description
            FROM findings f
            JOIN finding_cluster_map fcm ON f.id = fcm.finding_id
            WHERE fcm.cluster_id = %s
            ORDER BY
                CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
                f.risk_score DESC NULLS LAST
            LIMIT %s
        """, (cluster_id, limit))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def count_existing_snippets(cluster_id):
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM training_snippets WHERE cluster_id = %s", (cluster_id,))
        return cur.fetchone()[0]


def clear_cluster_snippets(cluster_id):
    """Remove old auto-generated snippets for this cluster."""
    with conn.cursor() as cur:
        cur.execute("DELETE FROM training_snippets WHERE cluster_id = %s", (cluster_id,))
        deleted = cur.rowcount
    log.info("  Cleared %d old snippets", deleted)


def analyze_subpatterns(cluster_name, findings, existing_patterns=None):
    """Send findings to Claude to identify distinct root cause sub-patterns."""
    # Build a compact summary of all findings
    finding_summaries = []
    for i, f in enumerate(findings[:150]):  # Cap at 150 for context window
        title = (f['title'] or '')[:100]
        summary = (f['short_summary'] or f['description'] or '')[:200]
        summary = summary.replace('\n', ' ').strip()
        finding_summaries.append(f"[{f['severity']}] {title}: {summary}")

    findings_text = "\n".join(finding_summaries)

    existing_note = ""
    if existing_patterns:
        existing_note = f"""

CRITICAL DEDUP RULE: The following sub-patterns ALREADY EXIST. You must NOT generate anything that overlaps with these — not even the same bug mechanism with a different name.

EXISTING PATTERNS (name + what the bug does):
{chr(10).join(str(p) for p in existing_patterns)}

Your new sub-patterns must each have a FUNDAMENTALLY DIFFERENT root cause from ALL of the above. "Different context, same bug" is NOT acceptable — the mechanism itself must be different."""

    prompt = f"""You are analyzing {len(findings)} real smart contract audit findings in the "{cluster_name}" category.

Your job: identify the DISTINCT vulnerability sub-patterns in these findings. Many findings describe the same bug in different protocols — group them by ROOT CAUSE.
{existing_note}

HERE ARE THE FINDINGS:
{findings_text}

TASK: Analyze these findings and identify 8-15 distinct sub-patterns. For each sub-pattern:
1. Give it a short technical name (snake_case)
2. Classify difficulty: beginner (single function), intermediate (2-3 function interaction), advanced (complex state/cross-contract)
3. Count how many of the findings match this sub-pattern
4. Write a 1-sentence description of the specific root cause

Return ONLY valid JSON (no markdown fences):
{{
  "cluster": "{cluster_name}",
  "total_findings": {len(findings)},
  "sub_patterns": [
    {{
      "name": "stale_price_no_freshness_check",
      "difficulty": "beginner",
      "finding_count": 45,
      "root_cause": "Oracle price is used without checking updatedAt timestamp, allowing stale data to drive financial decisions.",
      "example_title": "Stale Oracle Price Allows Undercollateralized Borrowing"
    }},
    ...more patterns...
  ]
}}

Rules:
- Each sub-pattern must represent a GENUINELY DIFFERENT bug, not the same bug with different words
- Sort by finding_count descending (most common first)
- finding_counts should roughly sum to {len(findings)} (some findings may fit multiple patterns)
- Minimum 8 sub-patterns, maximum 15
- Be specific — "logic error" is too vague, "division before multiplication loses precision in fee calculation" is good
- Include a mix of difficulties: at least 2 beginner, 3 intermediate, 2 advanced"""

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
        log.error("Analysis failed: %s", e)
        return None


def generate_snippet_for_subpattern(cluster_name, cluster_desc, subpattern, sample_findings):
    """Generate one training snippet for a specific sub-pattern, grounded in real findings."""
    # Find findings that match this sub-pattern
    relevant = []
    for f in sample_findings[:100]:
        text = f"{f['title']} {f['short_summary'] or ''} {f['description'] or ''}"[:500].lower()
        # Simple keyword match from the sub-pattern name and root cause
        keywords = subpattern['name'].replace('_', ' ').split() + subpattern['root_cause'].lower().split()[:10]
        if any(kw in text for kw in keywords if len(kw) > 3):
            relevant.append(f)

    # Use the most relevant findings, fall back to all
    examples = relevant[:5] if relevant else sample_findings[:5]
    examples_text = "\n".join(
        f"- [{f['severity']}] {f['title'][:80]}: {(f['short_summary'] or '')[:150]}"
        for f in examples
    )

    prompt = f"""Generate a Solidity training snippet for this SPECIFIC vulnerability sub-pattern:

CLUSTER: {cluster_name}
SUB-PATTERN: {subpattern['name'].replace('_', ' ')}
ROOT CAUSE: {subpattern['root_cause']}
DIFFICULTY: {subpattern['difficulty']}

Real audit findings with this exact bug (use as inspiration, don't copy):
{examples_text}

RULES:
1. Write 25-50 lines of clean Solidity (pragma solidity ^0.8.0;)
2. The code must demonstrate THIS SPECIFIC sub-pattern — not a generic {cluster_name} bug
3. Realistic variable names and structure — looks like real production code
4. NO comments naming the bug. Code looks normal and correct at first glance.
5. The vulnerability should require understanding the specific root cause described above

Return ONLY valid JSON:
{{
  "title": "Short challenge title (do NOT reveal the specific bug)",
  "solidity_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.0;\\n...",
  "hints": [
    {{"line_numbers": [N], "text": "Draw attention to the area without naming the bug", "cost": 0}},
    {{"line_numbers": [N, M], "text": "More specific — point at the mechanism", "cost": 1}},
    {{"line_numbers": [N, M, P], "text": "Almost gives it away — name what could go wrong", "cost": 1}}
  ],
  "annotations": [
    {{"line_numbers": [N], "type": "vulnerable", "label": "VULNERABLE", "explanation": "Specific explanation of what is wrong on this line"}},
    {{"line_numbers": [M], "type": "vulnerable", "label": "IMPACT", "explanation": "What the attacker achieves"}}
  ],
  "invariant": "The specific invariant this sub-pattern violates",
  "what_breaks": "One sentence: what exactly breaks and how",
  "exploit_path": "1. Step one. 2. Step two. 3. Step three. 4. Impact with numbers if possible.",
  "why_missed": "Why auditors specifically miss THIS sub-pattern (not generic advice)"
}}"""

    try:
        r = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2500,
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
        log.error("Snippet generation failed: %s", e)
        return None


def insert_snippet(cluster_id, difficulty, subpattern_name, data):
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO training_snippets
                (id, cluster_id, difficulty, title, solidity_code, hints, annotations,
                 invariant, exploit_path, what_breaks, why_missed, attack_pattern)
            VALUES (gen_random_uuid(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            cluster_id,
            difficulty,
            data.get("title", "Untitled"),
            data.get("solidity_code", ""),
            json.dumps(data.get("hints", [])),
            json.dumps(data.get("annotations", [])),
            data.get("invariant", ""),
            data.get("exploit_path", ""),
            data.get("what_breaks", ""),
            data.get("why_missed", ""),
            subpattern_name,
        ))


def run():
    log.info("=" * 60)
    log.info("Data-First Snippet Generation")
    log.info("  Target: %s", CLUSTER_SLUG or "all clusters")
    log.info("  Max snippets per cluster: %d", MAX_SNIPPETS)
    log.info("=" * 60)

    clusters = fetch_clusters()
    log.info("Found %d clusters", len(clusters))

    total_generated = 0
    total_failed = 0

    for c in clusters:
        cid = c["id"]
        cname = c["name"]
        cslug = c["slug"]

        log.info("")
        log.info("━" * 60)
        log.info("CLUSTER: %s (%d findings)", cname, c["finding_count"])
        log.info("━" * 60)

        # Step 1: Fetch all findings
        findings = fetch_findings_for_cluster(cid, limit=200)
        log.info("  Fetched %d findings for analysis", len(findings))

        if len(findings) < 5:
            log.warning("  Too few findings, skipping")
            continue

        # Step 2: Check existing snippets — get names AND descriptions for dedup
        existing_patterns = []
        existing_descriptions = []
        with conn.cursor() as cur:
            cur.execute("SELECT attack_pattern, what_breaks FROM training_snippets WHERE cluster_id = %s AND attack_pattern IS NOT NULL", (cid,))
            for row in cur.fetchall():
                existing_patterns.append(row[0])
                if row[1]:
                    existing_descriptions.append(f"- {row[0]}: {row[1][:120]}")

        existing_count = len(existing_patterns)
        remaining_budget = MAX_SNIPPETS - existing_count

        if remaining_budget <= 0:
            log.info("  Already has %d snippets (target: %d), skipping", existing_count, MAX_SNIPPETS)
            continue

        log.info("  Has %d snippets, need %d more (target: %d)", existing_count, remaining_budget, MAX_SNIPPETS)

        # Step 3: Analyze sub-patterns (excluding existing ones)
        log.info("  Analyzing NEW sub-patterns via Claude...")
        existing_context = existing_patterns if existing_patterns else None
        # If we have descriptions, use those instead (more context for dedup)
        if existing_descriptions:
            existing_context = existing_descriptions
        analysis = analyze_subpatterns(cname, findings, existing_context)

        if not analysis or "sub_patterns" not in analysis:
            log.error("  Analysis failed, skipping cluster")
            total_failed += 1
            continue

        sub_patterns = analysis["sub_patterns"]

        # Filter out any that match existing pattern names
        new_patterns = [sp for sp in sub_patterns if sp["name"] not in existing_patterns]
        log.info("  Found %d new sub-patterns (%d total, %d already exist):", len(new_patterns), len(sub_patterns), existing_count)
        for sp in new_patterns:
            log.info("    %-40s [%s] (%d findings) %s",
                     sp["name"], sp["difficulty"], sp["finding_count"],
                     sp["root_cause"][:80])

        # Generate one snippet per NEW sub-pattern, up to remaining budget
        snippets_to_generate = new_patterns[:remaining_budget]

        for i, sp in enumerate(snippets_to_generate):
            log.info("  [%d/%d] Generating: %s [%s]...",
                     i + 1, len(snippets_to_generate), sp["name"], sp["difficulty"])

            data = generate_snippet_for_subpattern(cname, c["description"], sp, findings)

            if data is None:
                total_failed += 1
                log.warning("    FAILED")
                continue

            code = data.get("solidity_code", "")
            if len(code) < 50:
                total_failed += 1
                log.warning("    Code too short (%d chars)", len(code))
                continue

            insert_snippet(cid, sp["difficulty"], sp["name"], data)
            total_generated += 1
            log.info("    ✓ %s", data.get("title", "?")[:60])

            time.sleep(1.0)

    # Update snippet counts
    log.info("")
    log.info("Updating snippet counts...")
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE pattern_clusters SET snippet_count = COALESCE(sub.cnt, 0)
            FROM (SELECT cluster_id, COUNT(*) as cnt FROM training_snippets GROUP BY cluster_id) sub
            WHERE pattern_clusters.id = sub.cluster_id
        """)
        # Reset clusters with no snippets
        cur.execute("""
            UPDATE pattern_clusters SET snippet_count = 0
            WHERE id NOT IN (SELECT DISTINCT cluster_id FROM training_snippets)
        """)

    conn.close()

    log.info("")
    log.info("=" * 60)
    log.info("Done. Generated: %d, Failed: %d", total_generated, total_failed)
    log.info("=" * 60)


if __name__ == "__main__":
    run()
