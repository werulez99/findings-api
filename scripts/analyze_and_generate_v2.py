#!/usr/bin/env python3
"""
Valves Security — Snippet Generation Pipeline v2

Improvements over v1:
1. Cluster-fit screening: LLM filters out-of-cluster findings before analysis
2. Finding-ref traceability: sub-patterns reference specific findings, no keyword rematching
3. Single-bug enforcement: generation prompt requires exactly one vulnerability
4. Anchor-text annotations: model returns code strings, Python resolves line numbers
5. Validator pass: second LLM check before insert rejects multi-bug or mismatched snippets
6. Operational robustness: retries, rejection logging, stage-level counters

Usage:
    ANTHROPIC_API_KEY=sk-... DATABASE_URL=postgresql://... python3 scripts/analyze_and_generate_v2.py

Optional:
    CLUSTER_SLUG=oracle-dependency  (single cluster)
    MAX_SNIPPETS_PER_CLUSTER=15     (default: 15)
    REPLACE_MISMATCHED=true         (delete and regenerate mismatched snippets)
"""

import json
import logging
import os
import re
import sys
import time
from typing import Any

import anthropic
import psycopg

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("gen_v2")

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
CLUSTER_SLUG = os.environ.get("CLUSTER_SLUG", "")
MAX_SNIPPETS = int(os.environ.get("MAX_SNIPPETS_PER_CLUSTER", "15"))
REPLACE_MISMATCHED = os.environ.get("REPLACE_MISMATCHED", "false").lower() in ("1", "true", "yes")
MODEL = "claude-sonnet-4-20250514"

if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
conn = psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None)

# ── Counters ──
stats = {
    "clusters_processed": 0,
    "findings_screened": 0,
    "findings_accepted": 0,
    "findings_rejected": 0,
    "subpatterns_discovered": 0,
    "snippets_generated": 0,
    "snippets_validated": 0,
    "snippets_rejected": 0,
    "snippets_inserted": 0,
    "failures": 0,
}


# ══════════════════════════════════════════════════════════════════════════════
# LLM HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def call_llm(prompt: str, max_tokens: int = 3000, retries: int = 2) -> dict | None:
    """Call Claude and parse JSON response. Retries on malformed JSON."""
    for attempt in range(retries + 1):
        try:
            r = client.messages.create(
                model=MODEL,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            text = r.content[0].text.strip()
            # Strip markdown fences robustly
            if text.startswith("```"):
                first_newline = text.find("\n")
                if first_newline > 0:
                    text = text[first_newline + 1:]
                if text.endswith("```"):
                    text = text[:-3]
                text = text.strip()
            return json.loads(text)
        except json.JSONDecodeError as e:
            if attempt < retries:
                log.warning("  JSON parse error (attempt %d/%d): %s", attempt + 1, retries + 1, str(e)[:80])
                time.sleep(1)
            else:
                log.error("  JSON parse failed after %d attempts: %s", retries + 1, str(e)[:80])
                stats["failures"] += 1
                return None
        except Exception as e:
            log.error("  LLM call failed: %s", str(e)[:120])
            stats["failures"] += 1
            return None


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1: CLUSTER-FIT SCREENING
# ══════════════════════════════════════════════════════════════════════════════

def screen_findings_for_cluster(cluster_name: str, findings: list[dict]) -> list[dict]:
    """First-pass LLM screening: classify each finding as in_cluster or out_of_cluster."""

    # Build compact finding list
    finding_lines = []
    for i, f in enumerate(findings[:120]):
        title = (f.get("title") or "")[:90]
        summary = (f.get("short_summary") or f.get("description") or "")[:150]
        summary = summary.replace("\n", " ").strip()
        finding_lines.append(f"[{i}] {title}: {summary}")

    findings_text = "\n".join(finding_lines)

    prompt = f"""You are a smart contract security expert. Classify each finding below as belonging to the "{cluster_name}" vulnerability category or not.

A finding belongs to "{cluster_name}" if its PRIMARY vulnerability mechanism is a {cluster_name} issue. Secondary mentions or tangential references do NOT count.

FINDINGS:
{findings_text}

For each finding, classify as:
- "in": primary bug is clearly a {cluster_name} issue
- "out": primary bug belongs to a different category
- "uncertain": could go either way

Return ONLY valid JSON:
{{
  "classifications": [
    {{"index": 0, "label": "in", "reason": "Missing initializer guard on proxy"}},
    {{"index": 1, "label": "out", "reason": "Primary issue is fee accounting, not {cluster_name.lower()}"}},
    ...
  ]
}}

Rules:
- Classify every finding from index 0 to {len(findings[:120]) - 1}
- Be strict: if the primary bug fits another category better, classify as "out"
- "in" means you are confident this is genuinely a {cluster_name} bug"""

    result = call_llm(prompt, max_tokens=4000)
    if not result or "classifications" not in result:
        log.warning("  Screening failed — skipping cluster (no fallback to unscreened findings)")
        return []

    # Filter to in-cluster findings
    in_indices = set()
    uncertain_indices = set()
    for c in result["classifications"]:
        idx = c.get("index")
        if idx is None or idx >= len(findings):
            continue
        label = c.get("label", "").lower()
        if label == "in":
            in_indices.add(idx)
        elif label == "uncertain":
            uncertain_indices.add(idx)

    stats["findings_screened"] += len(findings[:120])
    stats["findings_accepted"] += len(in_indices)
    stats["findings_rejected"] += len(findings[:120]) - len(in_indices) - len(uncertain_indices)

    accepted = [findings[i] for i in sorted(in_indices)]

    # If too few, include uncertain
    if len(accepted) < 10 and uncertain_indices:
        log.info("  Only %d in-cluster findings, adding %d uncertain", len(accepted), len(uncertain_indices))
        accepted.extend(findings[i] for i in sorted(uncertain_indices))

    if len(accepted) < 5:
        log.warning("  Only %d screened findings for %s — skipping cluster", len(accepted), cluster_name)
        return []

    log.info("  Screened: %d in-cluster, %d uncertain, %d out-of-cluster (from %d total)",
             len(in_indices), len(uncertain_indices),
             len(findings[:120]) - len(in_indices) - len(uncertain_indices),
             len(findings[:120]))

    return accepted


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2: SUB-PATTERN ANALYSIS WITH FINDING REFS
# ══════════════════════════════════════════════════════════════════════════════

def analyze_subpatterns(cluster_name: str, findings: list[dict], existing_descriptions: list[str] | None = None) -> dict | None:
    """Analyze screened findings to discover sub-patterns with explicit finding references."""

    finding_lines = []
    for i, f in enumerate(findings[:100]):
        title = (f.get("title") or "")[:90]
        summary = (f.get("short_summary") or f.get("description") or "")[:180]
        summary = summary.replace("\n", " ").strip()
        finding_lines.append(f"[{i}] [{f.get('severity', '?')}] {title}: {summary}")

    findings_text = "\n".join(finding_lines)

    existing_note = ""
    if existing_descriptions:
        existing_note = f"""
DEDUP RULE: These sub-patterns ALREADY EXIST. Do NOT overlap with them:
{chr(10).join(str(p) for p in existing_descriptions)}

Your new patterns must have FUNDAMENTALLY DIFFERENT root causes."""

    prompt = f"""Analyze these {len(findings[:100])} screened "{cluster_name}" findings and identify distinct sub-patterns.
{existing_note}

FINDINGS:
{findings_text}

For each sub-pattern:
1. Give a technical snake_case name
2. Set difficulty: beginner / intermediate / advanced
3. Write 1 sentence describing the specific root cause
4. List the finding indexes that match this sub-pattern

Return ONLY valid JSON:
{{
  "sub_patterns": [
    {{
      "name": "stale_price_no_freshness_check",
      "difficulty": "beginner",
      "root_cause": "Oracle price used without checking updatedAt, allowing stale data.",
      "finding_refs": [0, 4, 7, 11]
    }}
  ]
}}

Rules:
- Each sub-pattern must be a GENUINELY DIFFERENT mechanism
- Every finding index should appear in at least one sub-pattern
- A finding can appear in at most 2 sub-patterns
- 5-12 sub-patterns total
- Include mix of difficulties: at least 1 beginner, 2 intermediate, 1 advanced
- All sub-patterns must be genuine {cluster_name} bugs, not tangential issues"""

    result = call_llm(prompt, max_tokens=3000)
    if not result or "sub_patterns" not in result:
        return None

    stats["subpatterns_discovered"] += len(result["sub_patterns"])
    return result


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3: SNIPPET GENERATION (SINGLE-BUG, ANCHOR-TEXT)
# ══════════════════════════════════════════════════════════════════════════════

def generate_snippet(cluster_name: str, subpattern: dict, referenced_findings: list[dict]) -> dict | None:
    """Generate a snippet grounded in specific findings, with anchor-text annotations."""

    examples_text = "\n".join(
        f"- [{f.get('severity', '?')}] {(f.get('title') or '')[:80]}: {(f.get('short_summary') or '')[:120]}"
        for f in referenced_findings[:5]
    )

    sp_name = subpattern["name"].replace("_", " ")
    sp_root = subpattern["root_cause"]
    sp_diff = subpattern.get("difficulty", "intermediate")

    prompt = f"""Generate a production-quality Solidity training snippet.

CLUSTER: {cluster_name}
SUB-PATTERN: {sp_name}
ROOT CAUSE: {sp_root}
DIFFICULTY: {sp_diff}

Real findings with this exact bug (inspiration only):
{examples_text}

CODE REQUIREMENTS:
- pragma solidity ^0.8.19, 50-90 lines
- NatSpec: /// @title, /// @notice, /// @param on contract and key functions
- At least 2 events, emit them in state-changing functions
- Custom errors instead of string reverts
- 2-3 constants for magic numbers
- Import comments: // import "@openzeppelin/..."
- Realistic DeFi naming, looks like production code

HARD RULES:
- EXACTLY ONE primary vulnerability matching the sub-pattern above
- NO secondary material bugs, misleading flaws, or compile contradictions
- The bug must cleanly match "{cluster_name}" more than any other category
- Do not use immutable variables with initializer-only assignment unless that IS the single bug
- All annotations must refer to the SAME root cause
- IMPACT must be the consequence of the SAME bug, not a second issue
- Code should look correct at first glance
- NO comments naming or hinting at the bug

ANNOTATION FORMAT — use anchor_text, NOT line numbers:
Return the exact code string that identifies the vulnerable line.

Return ONLY valid JSON:
{{
  "title": "Short title (do NOT reveal the bug)",
  "solidity_code": "// SPDX-License-Identifier: MIT\\npragma solidity ^0.8.19;\\n...",
  "hints": [
    {{"anchor_text": "exact code line text", "text": "Question about the area", "cost": 0}},
    {{"anchor_text": "exact code line text", "text": "More specific hint", "cost": 1}},
    {{"anchor_text": "exact code line text", "text": "Almost reveals the bug", "cost": 1}}
  ],
  "annotations": [
    {{"anchor_text": "exact vulnerable code line", "type": "vulnerable", "label": "BUG", "explanation": "What is wrong (1-2 sentences)"}},
    {{"anchor_text": "exact impact code line", "type": "vulnerable", "label": "IMPACT", "explanation": "What the attacker achieves (1-2 sentences)"}}
  ],
  "invariant": "Precise invariant (1-2 sentences, include math if applicable)",
  "what_breaks": "Specific mechanism and inconsistent state (2-3 sentences). Must relate to {cluster_name}.",
  "exploit_path": "1. Step with value. 2. Causes Y. 3. State becomes Z. 4. Attacker calls W. 5. Impact: loss of $N.",
  "why_missed": "Cognitive trap (2-3 sentences). What the auditor assumes, why it is wrong."
}}"""

    result = call_llm(prompt, max_tokens=3500)
    if not result:
        return None

    stats["snippets_generated"] += 1
    return result


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4: ANCHOR RESOLUTION
# ══════════════════════════════════════════════════════════════════════════════

def resolve_anchor(code: str, anchor_text: str) -> int | None:
    """Find the line number of an anchor text in the code.
    Returns 1-indexed line number or None.
    Requires a unique exact match — no fuzzy fallback."""
    if not anchor_text or not code:
        return None

    lines = code.splitlines()
    anchor_clean = anchor_text.strip()

    # Normalize whitespace for comparison
    def normalize(s):
        return " ".join(s.split())

    anchor_norm = normalize(anchor_clean)
    matches = []

    for i, line in enumerate(lines):
        line_norm = normalize(line)
        if anchor_norm in line_norm:
            matches.append(i + 1)

    # Require exactly one match for determinism
    if len(matches) == 1:
        return matches[0]

    # If multiple matches, try exact stripped equality
    if len(matches) > 1:
        exact = [m for m in matches if normalize(lines[m - 1]) == anchor_norm]
        if len(exact) == 1:
            return exact[0]

    return None  # No match or ambiguous — fail


def resolve_all_anchors(data: dict) -> dict | None:
    """Resolve anchor_text to line_numbers for all annotations and hints.
    Returns the data with line_numbers added, or None if critical anchors fail."""

    code = data.get("solidity_code", "")
    if not code:
        return None

    code_lines = code.splitlines()

    # Resolve annotations (critical — must succeed)
    annotations = data.get("annotations", [])
    resolved_annotations = []
    for ann in annotations:
        anchor = ann.get("anchor_text", "")
        line_num = resolve_anchor(code, anchor)

        if line_num is None:
            log.warning("    Could not resolve annotation anchor uniquely: '%s'", anchor[:60])
            return None  # Critical failure — no silent fallback

        # Verify it's not a comment, empty line, or brace
        line_text = code_lines[line_num - 1].strip() if line_num <= len(code_lines) else ""
        if not line_text or line_text.startswith("///") or line_text.startswith("/**") or line_text in ("{", "}", "});"):
            log.warning("    Annotation anchor resolved to non-code line: L%d '%s'", line_num, line_text[:40])
            return None  # Reject — do not shift silently

        resolved_annotations.append({
            "line_numbers": [line_num],
            "type": ann.get("type", "vulnerable"),
            "label": ann.get("label", "BUG"),
            "explanation": ann.get("explanation", ""),
            "anchor_text": anchor,
        })

    # Resolve hints (non-critical — skip if fails)
    hints = data.get("hints", [])
    resolved_hints = []
    for hint in hints:
        anchor = hint.get("anchor_text", "")
        line_num = resolve_anchor(code, anchor)
        line_nums = [line_num] if line_num else []
        resolved_hints.append({
            "line_numbers": line_nums,
            "text": hint.get("text", ""),
            "cost": hint.get("cost", 0),
        })

    data["annotations"] = resolved_annotations
    data["hints"] = resolved_hints
    return data


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5: VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

def validate_snippet(cluster_name: str, subpattern_name: str, data: dict) -> dict:
    """Second LLM pass: validate snippet before insertion."""

    code = data.get("solidity_code", "")
    what_breaks = data.get("what_breaks", "")[:300]
    annotations = json.dumps(data.get("annotations", []), indent=2)[:500]

    prompt = f"""You are validating a Solidity training snippet before it enters a production training platform.

ASSIGNED CLUSTER: {cluster_name}
ASSIGNED SUB-PATTERN: {subpattern_name}

CODE (truncated):
{code}

WHAT BREAKS: {what_breaks}

ANNOTATIONS: {annotations}

Validate this snippet against these criteria:

1. CLUSTER FIT: Is the primary bug genuinely a "{cluster_name}" issue? Or does it fit another category better?
2. SUB-PATTERN FIT: Does the bug match "{subpattern_name}"?
3. SINGLE BUG: Is there exactly one primary material vulnerability? Are there any secondary bugs?
4. ANNOTATION CONSISTENCY: Do BUG and IMPACT annotations describe the same root cause?
5. WHAT_BREAKS MATCH: Does the what_breaks text match what the code actually shows?

Return ONLY valid JSON:
{{
  "pass": true,
  "matches_cluster": true,
  "best_cluster": "{cluster_name}",
  "matches_subpattern": true,
  "primary_bug": "description of the single primary bug",
  "secondary_bugs": [],
  "annotation_consistent": true,
  "reason": "Snippet is clean and matches the assigned cluster."
}}

Rules:
- pass=false if ANY criterion fails
- If the bug fits another cluster better, set matches_cluster=false and best_cluster to the better fit
- secondary_bugs should list any additional material vulnerabilities found
- Be strict: quality is more important than volume"""

    result = call_llm(prompt, max_tokens=800)
    if not result:
        return {"pass": False, "reason": "Validator call failed"}

    return result


def should_insert(validation: dict) -> bool:
    """Check if validation result allows insertion."""
    return (
        validation.get("pass", False) is True
        and validation.get("matches_cluster", False) is True
        and validation.get("matches_subpattern", False) is True
        and validation.get("annotation_consistent", False) is True
        and len(validation.get("secondary_bugs", [])) == 0
    )


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def fetch_clusters() -> list[dict]:
    with conn.cursor() as cur:
        if CLUSTER_SLUG:
            cur.execute("SELECT id, name, slug, description, invariant_template, finding_count FROM pattern_clusters WHERE slug = %s", (CLUSTER_SLUG,))
        else:
            cur.execute("SELECT id, name, slug, description, invariant_template, finding_count FROM pattern_clusters WHERE finding_count >= 20 ORDER BY finding_count DESC")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def fetch_findings(cluster_id, limit=200) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT f.title, f.short_summary, f.severity::text, f.protocol_name, f.description
            FROM findings f
            JOIN finding_cluster_map fcm ON f.id = fcm.finding_id
            WHERE fcm.cluster_id = %s
            ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END,
                     f.risk_score DESC NULLS LAST
            LIMIT %s
        """, (cluster_id, limit))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def get_existing_snippets(cluster_id) -> tuple[list[str], list[str]]:
    """Returns (pattern_names, descriptions) of existing snippets."""
    with conn.cursor() as cur:
        cur.execute("SELECT attack_pattern, what_breaks FROM training_snippets WHERE cluster_id = %s AND attack_pattern IS NOT NULL", (cluster_id,))
        patterns = []
        descriptions = []
        for row in cur.fetchall():
            patterns.append(row[0])
            if row[1]:
                descriptions.append(f"- {row[0]}: {row[1][:120]}")
        return patterns, descriptions


def count_mismatched_snippets(cluster_id, cluster_name) -> int:
    """Count snippets that don't match their cluster theme. DRY-RUN ONLY — does not delete."""
    # This is the keyword-based detection from earlier
    CLUSTER_KEYWORDS = {
        "reentrancy": ["reentran", "callback", "re-enter", "external call before", "cei"],
        "access-control": ["access control", "unauthorized", "modifier", "permission", "onlyowner", "privilege"],
        "oracle-dependency": ["oracle", "price feed", "stale price", "chainlink", "twap"],
        "vault-share-accounting": ["share", "vault", "erc4626", "inflation", "deposit", "totalassets"],
        "initialization": ["initial", "uninitial", "constructor", "setup", "configure"],
        "proxy-upgrade": ["proxy", "delegatecall", "storage", "upgrade", "implementation"],
        "signature-auth": ["signature", "replay", "nonce", "ecrecover", "eip712", "permit"],
        "arithmetic-precision": ["precision", "rounding", "division", "overflow", "truncat"],
        "integer-overflow": ["overflow", "underflow", "unchecked", "downcast", "truncat"],
        "denial-of-service": ["dos", "denial", "grief", "revert", "stuck", "unbounded", "block"],
        "flash-loan-attacks": ["flash loan", "flash", "atomic", "same transaction"],
        "frontrunning-mev": ["frontrun", "front-run", "sandwich", "mev", "slippage", "mempool"],
        "bridge-cross-chain": ["bridge", "cross-chain", "relay", "message", "chain id"],
        "governance-attacks": ["governance", "voting", "proposal", "quorum", "delegate"],
        "token-accounting": ["fee-on-transfer", "rebasing", "erc777", "decimal", "balance"],
        "price-manipulation": ["price manipul", "spot price", "amm", "pool"],
        "lending-liquidation": ["liquidat", "health factor", "collateral", "borrow", "ltv"],
        "dex-amm-logic": ["swap", "liquidity", "amm", "pool", "slippage", "dex"],
        "logic-errors": ["logic", "condition", "edge case", "off-by-one"],
    }

    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, attack_pattern, what_breaks, title
            FROM training_snippets WHERE cluster_id = %s
        """, (cluster_id,))
        rows = cur.fetchall()

    slug = None
    for s, name in CLUSTER_KEYWORDS.items():
        if cluster_name.lower().replace("&", "and").replace(" ", "-") in s or s in cluster_name.lower().replace(" ", "-"):
            slug = s
            break

    if not slug:
        # Try to find by partial match
        for s in CLUSTER_KEYWORDS:
            if any(w in cluster_name.lower() for w in s.split("-")):
                slug = s
                break

    if not slug:
        return 0

    keywords = CLUSTER_KEYWORDS.get(slug, [])
    if not keywords:
        return 0

    to_delete = []
    for row in rows:
        sid, pattern, wb, title = row
        combined = ((wb or "") + " " + (pattern or "") + " " + (title or "")).lower()
        if not any(kw in combined for kw in keywords):
            to_delete.append(sid)

    if to_delete:
        log.info("  Mismatched snippet IDs (not deleting): %s", [str(s)[:8] for s in to_delete[:10]])

    return len(to_delete)


def insert_snippet(cluster_id: str, difficulty: str, subpattern_name: str, data: dict):
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
    stats["snippets_inserted"] += 1


def update_snippet_counts():
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE pattern_clusters SET snippet_count = COALESCE(sub.cnt, 0)
            FROM (SELECT cluster_id, COUNT(*) as cnt FROM training_snippets GROUP BY cluster_id) sub
            WHERE pattern_clusters.id = sub.cluster_id
        """)
        cur.execute("""
            UPDATE pattern_clusters SET snippet_count = 0
            WHERE id NOT IN (SELECT DISTINCT cluster_id FROM training_snippets)
        """)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def process_cluster(cluster: dict):
    """Full pipeline for one cluster."""
    cid = cluster["id"]
    cname = cluster["name"]

    log.info("")
    log.info("━" * 70)
    log.info("CLUSTER: %s (%d findings)", cname, cluster["finding_count"])
    log.info("━" * 70)
    stats["clusters_processed"] += 1

    # ── Optional: identify mismatched snippets (dry-run only, no auto-delete) ──
    if REPLACE_MISMATCHED:
        mismatched = count_mismatched_snippets(cid, cname)
        if mismatched > 0:
            log.info("  Found %d potentially mismatched snippets (dry-run: not deleting)", mismatched)
            log.info("  To delete these, run: DELETE FROM training_snippets WHERE id IN (select manually)")

    # ── Check existing snippets ──
    existing_patterns, existing_descriptions = get_existing_snippets(cid)
    existing_count = len(existing_patterns)
    remaining_budget = MAX_SNIPPETS - existing_count

    if remaining_budget <= 0:
        log.info("  Already has %d snippets (target: %d), skipping", existing_count, MAX_SNIPPETS)
        return

    log.info("  Has %d snippets, need %d more (target: %d)", existing_count, remaining_budget, MAX_SNIPPETS)

    # ── Step 1: Fetch and screen findings ──
    log.info("  Step 1: Fetching and screening findings...")
    raw_findings = fetch_findings(cid, limit=200)
    if len(raw_findings) < 5:
        log.warning("  Too few findings (%d), skipping", len(raw_findings))
        return

    screened = screen_findings_for_cluster(cname, raw_findings)
    if not screened:
        log.warning("  No findings passed screening, skipping")
        return

    # ── Step 2: Analyze sub-patterns with finding refs ──
    log.info("  Step 2: Analyzing sub-patterns...")
    analysis = analyze_subpatterns(cname, screened, existing_descriptions or None)

    if not analysis or "sub_patterns" not in analysis:
        log.error("  Analysis failed, skipping")
        stats["failures"] += 1
        return

    sub_patterns = analysis["sub_patterns"]

    # Filter out existing patterns
    new_patterns = [sp for sp in sub_patterns if sp["name"] not in existing_patterns]
    log.info("  Found %d new sub-patterns (%d already exist)", len(new_patterns), existing_count)

    if not new_patterns:
        log.info("  No new sub-patterns found, skipping")
        return

    # ── Steps 3-5: Generate, resolve, validate, insert ──
    to_generate = new_patterns[:remaining_budget]

    for i, sp in enumerate(to_generate):
        log.info("  [%d/%d] %s [%s]", i + 1, len(to_generate), sp["name"], sp.get("difficulty", "?"))

        # Get referenced findings — strict traceability, no fallback
        refs = sp.get("finding_refs", [])
        referenced = [screened[r] for r in refs if isinstance(r, int) and 0 <= r < len(screened)]
        if len(referenced) < 2:
            log.warning("    Sub-pattern has %d valid finding refs (need >= 2), skipping", len(referenced))
            stats["failures"] += 1
            continue

        # ── Step 3: Generate snippet ──
        data = generate_snippet(cname, sp, referenced)
        if not data:
            log.warning("    Generation failed")
            stats["failures"] += 1
            continue

        code = data.get("solidity_code", "")
        if len(code) < 100:
            log.warning("    Code too short (%d chars)", len(code))
            stats["failures"] += 1
            continue

        # ── Step 4: Resolve anchors ──
        resolved = resolve_all_anchors(data)
        if not resolved:
            log.warning("    Anchor resolution failed")
            stats["failures"] += 1
            continue

        # ── Step 5: Validate ──
        log.info("    Validating...")
        validation = validate_snippet(cname, sp["name"], resolved)
        stats["snippets_validated"] += 1

        if not should_insert(validation):
            reason = validation.get("reason", "Unknown")
            best = validation.get("best_cluster", "?")
            secondary = validation.get("secondary_bugs", [])
            log.warning("    REJECTED: %s (best_cluster=%s, secondary_bugs=%d)", reason[:80], best, len(secondary))
            stats["snippets_rejected"] += 1
            continue

        # ── Insert ──
        insert_snippet(cid, sp.get("difficulty", "intermediate"), sp["name"], resolved)
        log.info("    ✓ Inserted: %s", resolved.get("title", "?")[:60])

        time.sleep(0.8)


def run():
    log.info("=" * 70)
    log.info("Snippet Generation Pipeline v2")
    log.info("  Target: %s", CLUSTER_SLUG or "all clusters")
    log.info("  Max per cluster: %d", MAX_SNIPPETS)
    log.info("  Replace mismatched: %s", REPLACE_MISMATCHED)
    log.info("=" * 70)

    clusters = fetch_clusters()
    log.info("Found %d clusters", len(clusters))

    for cluster in clusters:
        process_cluster(cluster)

    update_snippet_counts()
    conn.close()

    log.info("")
    log.info("=" * 70)
    log.info("PIPELINE REPORT")
    log.info("=" * 70)
    for key, val in stats.items():
        log.info("  %-25s %d", key, val)

    if stats["snippets_generated"] > 0:
        accept_rate = stats["snippets_inserted"] / stats["snippets_generated"] * 100
        log.info("  %-25s %.1f%%", "acceptance_rate", accept_rate)

    log.info("=" * 70)


if __name__ == "__main__":
    run()
