#!/usr/bin/env python3
"""
Snippet Deduplication Pipeline for Valves Security.

This is the final quality gate. It ensures every snippet in a cluster
teaches a genuinely different vulnerability mechanism.

Pipeline:
1. For each cluster, fetch ALL snippets
2. Send to Claude for semantic grouping by ROOT CAUSE mechanism
3. Within each group of duplicates, score each snippet on quality
4. Keep the best one per group, mark others for deletion
5. Optionally delete (or just report)

Quality scoring per snippet:
  - Code quality: NatSpec (+2), events (+2), custom errors (+1), constants (+1), realistic naming (+1)
  - Explanation depth: invariant length (+1 per 50 chars, max 3), exploit_path length (+1 per 100 chars, max 5),
    why_missed length (+1 per 80 chars, max 3)
  - Hint quality: 3 hints (+2), line_numbers present (+1 per hint)
  - Annotation quality: 2+ annotations (+2), explanations present (+1 per annotation)
  - Difficulty spread bonus: if the group has mixed difficulties, prefer keeping rarer difficulty

Usage:
    ANTHROPIC_API_KEY=sk-... DATABASE_URL=postgresql://... python3 scripts/dedup_snippets.py

    DRY_RUN=true   — report only, don't delete (default)
    DRY_RUN=false  — actually delete duplicates
    CLUSTER_SLUG=reentrancy  — single cluster (default: all)
    MIN_GROUP_SIZE=2  — only flag groups with N+ snippets (default: 2)
"""

import json
import logging
import os
import sys
import time

import anthropic
import psycopg

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("dedup")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() in ("1", "true", "yes")
CLUSTER_SLUG = os.environ.get("CLUSTER_SLUG", "")
MIN_GROUP_SIZE = int(os.environ.get("MIN_GROUP_SIZE", "2"))

if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
conn = psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None)


# ══════════════════════════════════════════════════════════════════════════════
# QUALITY SCORING
# ══════════════════════════════════════════════════════════════════════════════

def score_snippet(s):
    """Score a snippet's quality on a 0-30 scale. Higher = better."""
    score = 0
    code = s.get("solidity_code", "")
    lines = code.splitlines()

    # ── Code quality (max 10) ──
    has_natspec = any("///" in l or "/**" in l or "@notice" in l or "@param" in l or "@dev" in l for l in lines)
    has_events = any(l.strip().startswith("event ") for l in lines)
    has_emit = any("emit " in l for l in lines)
    has_custom_errors = any(l.strip().startswith("error ") for l in lines)
    has_constants = any("constant " in l for l in lines)
    has_modifier = any(l.strip().startswith("modifier ") for l in lines)
    line_count = len(lines)

    if has_natspec: score += 2
    if has_events and has_emit: score += 2
    elif has_events or has_emit: score += 1
    if has_custom_errors: score += 1
    if has_constants: score += 1
    if has_modifier: score += 1
    if 35 <= line_count <= 80: score += 2  # good length
    elif 25 <= line_count <= 100: score += 1
    # Penalty for very short code
    if line_count < 15: score -= 3

    # ── Explanation depth (max 11) ──
    invariant = s.get("invariant", "") or ""
    exploit_path = s.get("exploit_path", "") or ""
    what_breaks = s.get("what_breaks", "") or ""
    why_missed = s.get("why_missed", "") or ""

    score += min(3, len(invariant) // 50)
    score += min(5, len(exploit_path) // 100)
    score += min(3, len(why_missed) // 80)

    # Bonus for exploit path with numbered steps
    if exploit_path:
        step_count = exploit_path.count(". ")
        if step_count >= 4: score += 2
        elif step_count >= 2: score += 1

    # ── Hint quality (max 5) ──
    hints = s.get("hints", [])
    if isinstance(hints, str):
        try: hints = json.loads(hints)
        except: hints = []

    if len(hints) >= 3: score += 2
    elif len(hints) >= 2: score += 1

    for h in hints:
        if isinstance(h, dict) and h.get("line_numbers") and len(h["line_numbers"]) > 0:
            score += 1
            break  # just check that at least one hint has line numbers

    # Check hint text quality
    hint_texts = [h.get("text", "") for h in hints if isinstance(h, dict)]
    avg_hint_len = sum(len(t) for t in hint_texts) / max(len(hint_texts), 1)
    if avg_hint_len > 60: score += 1
    if avg_hint_len > 100: score += 1

    # ── Annotation quality (max 4) ──
    annotations = s.get("annotations", [])
    if isinstance(annotations, str):
        try: annotations = json.loads(annotations)
        except: annotations = []

    if len(annotations) >= 2: score += 2
    elif len(annotations) >= 1: score += 1

    for a in annotations:
        if isinstance(a, dict) and a.get("explanation") and len(a["explanation"]) > 30:
            score += 1
            break

    # Check annotation labels are meaningful
    labels = [a.get("label", "") for a in annotations if isinstance(a, dict)]
    if any(l in ("VULNERABLE", "IMPACT", "ROOT CAUSE") for l in labels): score += 1

    return score


# ══════════════════════════════════════════════════════════════════════════════
# SEMANTIC GROUPING VIA CLAUDE
# ══════════════════════════════════════════════════════════════════════════════

def semantic_group_snippets(cluster_name, snippets):
    """Ask Claude to group snippets by their underlying mechanism.

    Uses the actual vulnerability code and fix pattern as the dedup signal,
    not just metadata descriptions.
    """

    snippet_details = []
    for i, s in enumerate(snippets):
        code = (s.get("solidity_code", "") or "")
        # Extract the vulnerable lines — look for lines referenced in annotations
        annotations = s.get("annotations", [])
        if isinstance(annotations, str):
            try: annotations = json.loads(annotations)
            except: annotations = []

        vuln_lines = []
        code_lines = code.splitlines()
        for ann in annotations:
            if isinstance(ann, dict):
                for ln in ann.get("line_numbers", []):
                    if 1 <= ln <= len(code_lines):
                        vuln_lines.append(f"  L{ln}: {code_lines[ln-1].strip()}")

        vuln_code = "\n".join(vuln_lines[:6]) if vuln_lines else code[:300]

        snippet_details.append(
            f"--- SNIPPET {i} ---\n"
            f"Pattern name: {s.get('attack_pattern','?')}\n"
            f"Difficulty: {s.get('difficulty','?')}\n"
            f"What breaks: {(s.get('what_breaks','') or '')[:200]}\n"
            f"Vulnerable code:\n{vuln_code}\n"
            f"Exploit path: {(s.get('exploit_path','') or '')[:200]}"
        )

    details_text = "\n\n".join(snippet_details)

    prompt = f"""You are a smart contract security expert performing quality control on a training platform.

CONTEXT: The "{cluster_name}" cluster has {len(snippets)} training snippets. Each snippet is a Solidity code challenge that teaches auditors to find a specific vulnerability. Your job is to identify snippets that teach the SAME lesson — even if they use different variable names or DeFi contexts.

THE DEDUP TEST — two snippets are duplicates if ALL THREE of these are true:
1. FIX TEST: The same 1-line code fix pattern would prevent both vulnerabilities (e.g., both need "add a reentrancy guard", both need "check updatedAt timestamp", both need "update state before external call")
2. KNOWLEDGE TEST: An auditor who learned to spot snippet A would IMMEDIATELY recognize snippet B without needing any new knowledge
3. DETECTION TEST: A single static analysis rule could catch both bugs

Two snippets are NOT duplicates if ANY of these differ:
- The fix requires a fundamentally different code change
- Understanding one does NOT help you find the other
- They target different function types (e.g., one targets deposit(), other targets governance voting)
- The attack sequence is meaningfully different (not just different token amounts)

IMPORTANT: Different DeFi CONTEXTS doing the SAME mechanism ARE duplicates (e.g., "missing reentrancy guard in a vault" and "missing reentrancy guard in a staking pool" are the same lesson). But "classic reentrancy via ETH transfer" and "reentrancy via ERC721 callback" are DIFFERENT lessons because they require different detection knowledge.

HERE ARE THE SNIPPETS:
{details_text}

TASK: Group snippets by what they TEACH. Return ONLY valid JSON (no markdown fences):
{{
  "groups": [
    {{
      "mechanism": "short_technical_name",
      "what_the_auditor_learns": "One sentence: what skill does solving this snippet build?",
      "fix_pattern": "The 1-line fix that prevents this class of bug",
      "snippet_ids": [3, 7, 14],
      "is_duplicate_group": true
    }},
    {{
      "mechanism": "different_mechanism",
      "what_the_auditor_learns": "Different skill than the above",
      "fix_pattern": "Different fix pattern",
      "snippet_ids": [5],
      "is_duplicate_group": false
    }}
  ]
}}

Rules:
- Every snippet ID (0 to {len(snippets)-1}) must appear in EXACTLY one group
- A group with 1 snippet: is_duplicate_group = false
- A group with 2+ snippets: is_duplicate_group = true
- STRICT MODE: when in doubt whether two snippets teach different things, keep them SEPARATE
- Do NOT group snippets just because they are in the same vulnerability category — that is the CLUSTER's job. Within a cluster, we want maximum diversity."""

    try:
        r = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
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
        log.error("Semantic grouping failed: %s", e)
        return None


# ══════════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def fetch_clusters():
    with conn.cursor() as cur:
        if CLUSTER_SLUG:
            cur.execute("SELECT id, name, slug, snippet_count FROM pattern_clusters WHERE slug = %s", (CLUSTER_SLUG,))
        else:
            cur.execute("SELECT id, name, slug, snippet_count FROM pattern_clusters WHERE snippet_count > 0 ORDER BY finding_count DESC")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def fetch_snippets_for_cluster(cluster_id):
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, title, difficulty, solidity_code, hints, annotations,
                   invariant, exploit_path, what_breaks, why_missed, attack_pattern
            FROM training_snippets
            WHERE cluster_id = %s
            ORDER BY created_at
        """, (cluster_id,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def delete_snippets(ids):
    if not ids:
        return
    with conn.cursor() as cur:
        cur.execute("DELETE FROM training_snippets WHERE id = ANY(%s)", (ids,))
        log.info("    Deleted %d snippets", cur.rowcount)


def update_cluster_counts():
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


def run():
    log.info("=" * 70)
    log.info("Snippet Deduplication Pipeline")
    log.info("  Mode: %s", "DRY RUN (report only)" if DRY_RUN else "LIVE (will delete duplicates)")
    log.info("  Target: %s", CLUSTER_SLUG or "all clusters")
    log.info("  Min group size for flagging: %d", MIN_GROUP_SIZE)
    log.info("=" * 70)

    clusters = fetch_clusters()
    log.info("Found %d clusters to analyze", len(clusters))

    total_snippets = 0
    total_duplicates = 0
    total_kept = 0
    total_deleted = 0
    cluster_reports = []

    for cluster in clusters:
        cid = cluster["id"]
        cname = cluster["name"]
        cslug = cluster["slug"]

        snippets = fetch_snippets_for_cluster(cid)
        total_snippets += len(snippets)

        log.info("")
        log.info("━" * 70)
        log.info("CLUSTER: %s (%d snippets)", cname, len(snippets))
        log.info("━" * 70)

        if len(snippets) <= 2:
            log.info("  Too few snippets to dedup, skipping")
            total_kept += len(snippets)
            continue

        # Step 1: Score all snippets
        scored = []
        for s in snippets:
            quality = score_snippet(s)
            scored.append({**s, "_quality_score": quality})

        avg_quality = sum(s["_quality_score"] for s in scored) / len(scored)
        log.info("  Quality scores: min=%d, max=%d, avg=%.1f",
                 min(s["_quality_score"] for s in scored),
                 max(s["_quality_score"] for s in scored),
                 avg_quality)

        # Step 2: Semantic grouping via Claude
        log.info("  Analyzing semantic similarity via Claude...")
        grouping = semantic_group_snippets(cname, snippets)

        if not grouping or "groups" not in grouping:
            log.error("  Grouping failed, skipping cluster")
            total_kept += len(snippets)
            continue

        groups = grouping["groups"]
        dup_groups = [g for g in groups if g.get("is_duplicate_group") and len(g.get("snippet_ids", [])) >= MIN_GROUP_SIZE]
        unique_groups = [g for g in groups if not g.get("is_duplicate_group")]

        log.info("  Found %d unique mechanisms, %d duplicate groups", len(unique_groups), len(dup_groups))

        # Step 3: For each duplicate group, keep the best snippet
        to_delete = []
        to_keep = []

        for g in groups:
            ids_in_group = g.get("snippet_ids", [])
            if not ids_in_group:
                continue

            group_snippets = [scored[i] for i in ids_in_group if i < len(scored)]

            if not g.get("is_duplicate_group") or len(group_snippets) <= 1:
                # Unique mechanism — keep all
                to_keep.extend(group_snippets)
                continue

            # Duplicate group — pick the best one
            # Sort by quality score descending, then by difficulty diversity
            group_snippets.sort(key=lambda s: s["_quality_score"], reverse=True)

            best = group_snippets[0]
            rest = group_snippets[1:]

            # Check if there are different difficulties in the group
            # If so, keep one per difficulty level (not just the best overall)
            difficulties_seen = set()
            keep_from_group = []

            for s in group_snippets:
                diff = s.get("difficulty", "intermediate")
                if diff not in difficulties_seen:
                    difficulties_seen.add(diff)
                    keep_from_group.append(s)
                else:
                    to_delete.append(s)

            to_keep.extend(keep_from_group)

            log.info("  DUP GROUP: %s", g["mechanism"])
            log.info("    %d snippets, keeping %d (best per difficulty), removing %d",
                     len(group_snippets), len(keep_from_group), len(group_snippets) - len(keep_from_group))
            for s in group_snippets:
                kept = s in keep_from_group
                log.info("      %s [%s] quality=%d %s — %s",
                         "KEEP" if kept else "DEL ",
                         s.get("difficulty", "?")[:4],
                         s["_quality_score"],
                         s.get("attack_pattern", "?")[:35],
                         (s.get("what_breaks", "") or "")[:60])

        total_duplicates += len(to_delete)
        total_kept += len(to_keep)

        # Step 4: Delete duplicates
        if to_delete:
            delete_ids = [s["id"] for s in to_delete]
            if DRY_RUN:
                log.info("  [DRY RUN] Would delete %d snippets", len(delete_ids))
                total_deleted += len(delete_ids)
            else:
                delete_snippets(delete_ids)
                total_deleted += len(delete_ids)
                log.info("  Deleted %d duplicates", len(delete_ids))
        else:
            log.info("  No duplicates found — all snippets are unique")

        cluster_reports.append({
            "cluster": cname,
            "total": len(snippets),
            "unique_mechanisms": len(unique_groups) + len(dup_groups),
            "duplicates_found": len(to_delete),
            "kept": len(to_keep),
        })

        time.sleep(1.0)

    # Step 5: Update counts
    if not DRY_RUN and total_deleted > 0:
        log.info("")
        log.info("Updating cluster snippet counts...")
        update_cluster_counts()

    # Final report
    log.info("")
    log.info("=" * 70)
    log.info("DEDUPLICATION REPORT")
    log.info("=" * 70)
    log.info("")
    log.info("%-35s %6s %6s %6s %6s", "CLUSTER", "TOTAL", "UNIQ", "DUPES", "KEPT")
    log.info("-" * 70)
    for r in cluster_reports:
        log.info("%-35s %6d %6d %6d %6d",
                 r["cluster"][:35], r["total"], r["unique_mechanisms"],
                 r["duplicates_found"], r["kept"])
    log.info("-" * 70)
    log.info("%-35s %6d %6s %6d %6d", "TOTAL", total_snippets, "", total_duplicates, total_kept)
    log.info("")
    log.info("Mode: %s", "DRY RUN — nothing was deleted" if DRY_RUN else "LIVE — duplicates were deleted")
    log.info("Snippets analyzed: %d", total_snippets)
    log.info("Duplicates identified: %d (%.1f%%)", total_duplicates,
             (total_duplicates / max(total_snippets, 1)) * 100)
    log.info("Snippets to keep: %d", total_kept)
    if DRY_RUN:
        log.info("")
        log.info("To actually delete duplicates, run with DRY_RUN=false")
    log.info("=" * 70)

    conn.close()


if __name__ == "__main__":
    run()
