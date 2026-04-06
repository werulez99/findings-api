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

def extract_vulnerability_signature(snippet):
    """Extract the core vulnerability pattern from a snippet's code.
    Returns the vulnerable lines, the annotations, and a code context window."""
    code = (snippet.get("solidity_code", "") or "")
    code_lines = code.splitlines()

    annotations = snippet.get("annotations", [])
    if isinstance(annotations, str):
        try: annotations = json.loads(annotations)
        except: annotations = []

    # Get annotated vulnerable lines with surrounding context
    vuln_sections = []
    seen_ranges = set()
    for ann in annotations:
        if not isinstance(ann, dict): continue
        for ln in ann.get("line_numbers", []):
            if ln in seen_ranges: continue
            seen_ranges.add(ln)
            # Get 2 lines before and after for context
            start = max(0, ln - 3)
            end = min(len(code_lines), ln + 2)
            section_lines = []
            for i in range(start, end):
                marker = " >>> " if (i + 1) == ln else "     "
                section_lines.append(f"{marker}L{i+1}: {code_lines[i].rstrip()}")
            vuln_sections.append("\n".join(section_lines))
            if ann.get("explanation"):
                vuln_sections.append(f"     BUG: {ann['explanation'][:150]}")

    return "\n".join(vuln_sections) if vuln_sections else code[:400]


def semantic_group_snippets(cluster_name, snippets):
    """Two-phase dedup: first extract signatures, then group by mechanism.

    Phase 1: For each snippet, extract a "vulnerability signature" —
             the exact code pattern + what makes it vulnerable.
    Phase 2: Ask Claude to compare signatures and group by mechanism.
    """

    # Phase 1: Build detailed vulnerability cards
    cards = []
    for i, s in enumerate(snippets):
        vuln_sig = extract_vulnerability_signature(s)
        exploit = (s.get("exploit_path", "") or "")[:250]
        what_breaks = (s.get("what_breaks", "") or "")[:200]

        # Extract the fix — what would you change to prevent this?
        # This is the strongest dedup signal: same fix = same bug
        why_missed = (s.get("why_missed", "") or "")[:150]

        cards.append(
            f"╔══ SNIPPET {i} ══╗\n"
            f"Name: {s.get('attack_pattern','?')}\n"
            f"Difficulty: {s.get('difficulty','?')}\n"
            f"\n"
            f"VULNERABLE CODE (annotated lines marked with >>>):\n"
            f"{vuln_sig}\n"
            f"\n"
            f"WHAT BREAKS: {what_breaks}\n"
            f"ATTACK STEPS: {exploit}\n"
            f"WHY AUDITORS MISS IT: {why_missed}\n"
            f"╚{'═' * 30}╝"
        )

    cards_text = "\n\n".join(cards)

    prompt = f"""You are the lead security researcher at a top audit firm. You're reviewing {len(snippets)} training challenges in the "{cluster_name}" cluster to ensure each one teaches a DISTINCT skill.

YOUR TASK: Read each snippet's vulnerable code, attack path, and explanation. Then group them by what SKILL an auditor needs to solve them.

THE KEY QUESTION for each pair of snippets:
"If I teach a junior auditor to solve snippet A, can they IMMEDIATELY solve snippet B without learning anything new?"
- YES → they are duplicates (same lesson)
- NO → they are different (different lesson)

CONCRETE TESTS (a pair is duplicate only if ALL pass):

TEST 1 — SAME FIX:
  Write the fix for each snippet in one line.
  If both fixes are the same pattern → duplicate signal.
  Example: "add nonReentrant modifier" = same fix, even in different contracts.
  Counter-example: "add nonReentrant" vs "check msg.sender == owner" = different fixes.

TEST 2 — SAME DETECTION SKILL:
  What does the auditor need to LOOK FOR to find this bug?
  If both require looking for the same code pattern → duplicate signal.
  Example: "look for external call before state update" = same detection skill.
  Counter-example: "look for external call before state update" vs "look for missing callback handler" = different.

TEST 3 — SAME MENTAL MODEL:
  What concept does the auditor need to UNDERSTAND?
  If both require the same conceptual understanding → duplicate signal.
  Example: "understand that balanceOf can be manipulated by direct transfer" = same mental model.
  Counter-example: "understand balanceOf manipulation" vs "understand oracle staleness" = different.

STRICT RULE: When in doubt, keep snippets SEPARATE. False negatives (missing a duplicate) are much less harmful than false positives (deleting a unique lesson).

NOT DUPLICATES even if they look similar:
- Same bug type but triggered through different ENTRY POINTS (ETH transfer vs ERC721 callback vs ERC777 hook — these are 3 different lessons)
- Same bug type but requiring different PREREQUISITE KNOWLEDGE
- Same fix pattern but different DETECTION difficulty

HERE ARE THE SNIPPETS:
{cards_text}

Return ONLY valid JSON (no markdown fences):
{{
  "analysis_notes": "Brief notes on your reasoning for controversial groupings",
  "groups": [
    {{
      "mechanism": "short_technical_name",
      "the_one_lesson": "Complete this sentence: 'After this challenge, the auditor knows to...'",
      "fix_in_one_line": "The exact code change that prevents this bug",
      "detection_skill": "What the auditor looks for in code to find this bug",
      "snippet_ids": [3, 7, 14],
      "is_duplicate_group": true
    }}
  ]
}}

Rules:
- Every snippet ID (0 to {len(snippets)-1}) must appear in EXACTLY one group
- A group with 1 snippet: is_duplicate_group = false
- A group with 2+ snippets: is_duplicate_group = true — these teach the same lesson
- STRICT: when uncertain, keep them separate
- Output the analysis_notes field explaining any close calls"""

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
