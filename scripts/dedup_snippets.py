#!/usr/bin/env python3
"""
Valves Security — Snippet Deduplication (Report-First)

Identifies duplicate snippets using semantic grouping via Claude.
Always produces a reviewable report. Never deletes without an approved ID file.

Modes:
  AUDIT (default):
    python3 scripts/dedup_snippets.py
    → writes dedup_report.json

  REVIEWED DELETE:
    python3 scripts/dedup_snippets.py --delete-from approved_dedup_deletes.json
    → deletes only IDs listed in the file

Env vars:
    ANTHROPIC_API_KEY   required
    DATABASE_URL        required
    CLUSTER_SLUG        optional (single cluster)
    REPORT_PATH         optional (default: dedup_report.json)
"""

import argparse
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
CLUSTER_SLUG = os.environ.get("CLUSTER_SLUG", "")
REPORT_PATH = os.environ.get("REPORT_PATH", "dedup_report.json")
MODEL = "claude-sonnet-4-20250514"

if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
conn = psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None)


# ══════════════════════════════════════════════════════════════════════════════
# QUALITY SCORING
# ══════════════════════════════════════════════════════════════════════════════

def score_snippet(s: dict) -> int:
    """Score snippet quality 0-30. Higher = better."""
    score = 0
    code = s.get("solidity_code", "") or ""
    lines = code.splitlines()

    # Code quality
    has_natspec = any("///" in l or "/**" in l or "@notice" in l for l in lines)
    has_events = any(l.strip().startswith("event ") for l in lines)
    has_emit = any("emit " in l for l in lines)
    has_custom_errors = any(l.strip().startswith("error ") for l in lines)
    has_constants = any("constant " in l for l in lines)

    if has_natspec: score += 2
    if has_events and has_emit: score += 2
    if has_custom_errors: score += 1
    if has_constants: score += 1
    if 35 <= len(lines) <= 100: score += 2

    # Explanation depth
    invariant = s.get("invariant", "") or ""
    exploit_path = s.get("exploit_path", "") or ""
    why_missed = s.get("why_missed", "") or ""

    score += min(3, len(invariant) // 50)
    score += min(5, len(exploit_path) // 100)
    score += min(3, len(why_missed) // 80)
    if exploit_path.count(". ") >= 4: score += 2

    # Hints
    hints = s.get("hints", [])
    if isinstance(hints, str):
        try: hints = json.loads(hints)
        except: hints = []
    if len(hints) >= 3: score += 2

    # Annotations
    annotations = s.get("annotations", [])
    if isinstance(annotations, str):
        try: annotations = json.loads(annotations)
        except: annotations = []
    if len(annotations) >= 2: score += 2

    return score


# ══════════════════════════════════════════════════════════════════════════════
# LLM
# ══════════════════════════════════════════════════════════════════════════════

def call_llm(prompt: str, max_tokens: int = 4000, retries: int = 2) -> dict | None:
    for attempt in range(retries + 1):
        try:
            r = client.messages.create(
                model=MODEL, max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )
            text = r.content[0].text.strip()
            if text.startswith("```"):
                first_nl = text.find("\n")
                if first_nl > 0: text = text[first_nl + 1:]
                if text.endswith("```"): text = text[:-3]
                text = text.strip()
            return json.loads(text)
        except json.JSONDecodeError:
            if attempt < retries:
                time.sleep(1)
            else:
                return None
        except Exception as e:
            log.error("  LLM error: %s", str(e)[:100])
            return None


# ══════════════════════════════════════════════════════════════════════════════
# SEMANTIC GROUPING
# ══════════════════════════════════════════════════════════════════════════════

def extract_vuln_signature(snippet: dict) -> str:
    """Extract vulnerability context for dedup comparison."""
    code = (snippet.get("solidity_code", "") or "")
    annotations = snippet.get("annotations", [])
    if isinstance(annotations, str):
        try: annotations = json.loads(annotations)
        except: annotations = []

    code_lines = code.splitlines()
    vuln_sections = []
    seen_lines = set()

    for ann in annotations:
        if not isinstance(ann, dict): continue
        for ln in ann.get("line_numbers", []):
            if ln in seen_lines: continue
            seen_lines.add(ln)
            start = max(0, ln - 3)
            end = min(len(code_lines), ln + 2)
            for i in range(start, end):
                marker = " >>> " if (i + 1) == ln else "     "
                vuln_sections.append(f"{marker}L{i+1}: {code_lines[i].rstrip()}")
            if ann.get("explanation"):
                vuln_sections.append(f"     BUG: {ann['explanation'][:150]}")

    return "\n".join(vuln_sections) if vuln_sections else code[:400]


def group_snippets(cluster_name: str, snippets: list[dict]) -> dict | None:
    """Semantic grouping via Claude with strict schema validation."""

    cards = []
    for i, s in enumerate(snippets):
        vuln_sig = extract_vuln_signature(s)
        wb = (s.get("what_breaks", "") or "")[:200]
        ep = (s.get("exploit_path", "") or "")[:200]

        cards.append(
            f"╔══ SNIPPET {i} ══╗\n"
            f"Name: {s.get('attack_pattern', '?')}\n"
            f"Difficulty: {s.get('difficulty', '?')}\n"
            f"VULNERABLE CODE:\n{vuln_sig}\n"
            f"WHAT BREAKS: {wb}\n"
            f"ATTACK STEPS: {ep}\n"
            f"╚{'═' * 30}╝"
        )

    cards_text = "\n\n".join(cards)

    prompt = f"""Analyze {len(snippets)} training snippets in "{cluster_name}" for duplicates.

Two snippets are duplicates if ALL THREE pass:
1. FIX TEST: Same 1-line fix prevents both
2. DETECTION TEST: Same detection skill finds both
3. KNOWLEDGE TEST: Learning one means immediately solving the other

When uncertain, keep them SEPARATE.

SNIPPETS:
{cards_text}

Return ONLY valid JSON:
{{
  "analysis_notes": "brief reasoning for close calls",
  "groups": [
    {{
      "mechanism": "short_name",
      "the_one_lesson": "After this, the auditor knows to...",
      "fix_in_one_line": "The fix",
      "snippet_ids": [3, 7],
      "is_duplicate_group": true
    }}
  ]
}}

Rules:
- Every ID (0 to {len(snippets) - 1}) must appear in EXACTLY one group
- Group with 1 snippet: is_duplicate_group = false
- Group with 2+: is_duplicate_group = true
- STRICT: when uncertain, keep separate"""

    result = call_llm(prompt, max_tokens=4000)
    if not result or "groups" not in result:
        return None

    # Schema validation: every index must appear exactly once
    all_ids = set()
    for g in result["groups"]:
        ids = g.get("snippet_ids", [])
        if not isinstance(ids, list):
            log.warning("  Invalid snippet_ids in group")
            return None
        for sid in ids:
            if not isinstance(sid, int) or sid < 0 or sid >= len(snippets):
                log.warning("  Invalid snippet ID: %s", sid)
                return None
            if sid in all_ids:
                log.warning("  Duplicate snippet ID in grouping: %d", sid)
                return None
            all_ids.add(sid)

    if len(all_ids) != len(snippets):
        log.warning("  Grouping covers %d of %d snippets — incomplete", len(all_ids), len(snippets))
        return None

    return result


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════

def fetch_clusters() -> list[dict]:
    with conn.cursor() as cur:
        if CLUSTER_SLUG:
            cur.execute("SELECT id, name, slug, snippet_count FROM pattern_clusters WHERE slug = %s", (CLUSTER_SLUG,))
        else:
            cur.execute("SELECT id, name, slug, snippet_count FROM pattern_clusters WHERE snippet_count > 0 ORDER BY finding_count DESC")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def fetch_snippets_for_cluster(cluster_id) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, title, difficulty, solidity_code, hints, annotations,
                   invariant, exploit_path, what_breaks, why_missed, attack_pattern
            FROM training_snippets WHERE cluster_id = %s ORDER BY created_at
        """, (cluster_id,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def delete_by_ids(ids: list[str]) -> int:
    if not ids:
        return 0
    import uuid
    uuids = [uuid.UUID(i) for i in ids]
    with conn.cursor() as cur:
        cur.execute("DELETE FROM training_snippets WHERE id = ANY(%s)", (uuids,))
        return cur.rowcount


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT MODE
# ══════════════════════════════════════════════════════════════════════════════

def run_audit():
    log.info("=" * 70)
    log.info("Snippet Deduplication — AUDIT MODE")
    log.info("  Target: %s", CLUSTER_SLUG or "all clusters")
    log.info("  Report: %s", REPORT_PATH)
    log.info("=" * 70)

    clusters = fetch_clusters()
    log.info("Found %d clusters", len(clusters))

    report = {
        "mode": "audit",
        "total_snippets": 0,
        "total_duplicates": 0,
        "total_unique": 0,
        "clusters": [],
        "all_delete_candidates": [],
    }

    for cluster in clusters:
        cid = cluster["id"]
        cname = cluster["name"]

        snippets = fetch_snippets_for_cluster(cid)
        report["total_snippets"] += len(snippets)

        log.info("")
        log.info("━" * 70)
        log.info("CLUSTER: %s (%d snippets)", cname, len(snippets))

        if len(snippets) <= 2:
            log.info("  Too few to dedup")
            report["total_unique"] += len(snippets)
            continue

        # Score all
        scored = []
        for s in snippets:
            scored.append({**s, "_quality": score_snippet(s)})

        # Group
        log.info("  Grouping via Claude...")
        grouping = group_snippets(cname, snippets)

        if not grouping:
            log.warning("  Grouping failed, skipping cluster")
            report["total_unique"] += len(snippets)
            continue

        dup_groups = [g for g in grouping["groups"] if g.get("is_duplicate_group")]
        unique_groups = [g for g in grouping["groups"] if not g.get("is_duplicate_group")]

        cluster_report = {
            "cluster": cname,
            "cluster_slug": cluster["slug"],
            "total_snippets": len(snippets),
            "unique_mechanisms": len(unique_groups) + len(dup_groups),
            "duplicate_groups": [],
        }

        cluster_dupes = 0

        for g in dup_groups:
            ids_in_group = g.get("snippet_ids", [])
            group_scored = [scored[i] for i in ids_in_group if i < len(scored)]

            # Keep the single best snippet (highest quality score)
            group_scored.sort(key=lambda s: s["_quality"], reverse=True)
            keep = group_scored[0]
            delete = group_scored[1:]

            keep_id = str(keep["id"])
            delete_ids = [str(d["id"]) for d in delete]

            dup_entry = {
                "mechanism": g.get("mechanism", "?"),
                "lesson": g.get("the_one_lesson", ""),
                "fix": g.get("fix_in_one_line", ""),
                "snippet_count": len(group_scored),
                "keep_id": keep_id,
                "keep_title": keep.get("title", "?"),
                "keep_quality": keep["_quality"],
                "delete_ids": delete_ids,
                "delete_titles": [(d.get("title", "?"), d["_quality"]) for d in delete],
            }
            cluster_report["duplicate_groups"].append(dup_entry)
            report["all_delete_candidates"].extend(delete_ids)
            cluster_dupes += len(delete)

        report["total_duplicates"] += cluster_dupes
        report["total_unique"] += len(snippets) - cluster_dupes
        report["clusters"].append(cluster_report)

        log.info("  Found %d duplicate groups, %d snippets to remove",
                 len(dup_groups), cluster_dupes)

        time.sleep(1.0)

    # Write report
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, default=str)

    log.info("")
    log.info("=" * 70)
    log.info("DEDUP REPORT")
    log.info("=" * 70)
    log.info("  Total snippets:    %d", report["total_snippets"])
    log.info("  Unique:            %d", report["total_unique"])
    log.info("  Duplicates:        %d", report["total_duplicates"])
    log.info("  Delete candidates: %d", len(report["all_delete_candidates"]))
    log.info("  Report: %s", REPORT_PATH)
    log.info("")
    log.info("  To delete, create an approved file and run:")
    log.info("  python3 scripts/dedup_snippets.py --delete-from approved_dedup_deletes.json")
    log.info("=" * 70)


# ══════════════════════════════════════════════════════════════════════════════
# REVIEWED DELETE MODE
# ══════════════════════════════════════════════════════════════════════════════

def run_reviewed_delete(approved_file: str):
    log.info("=" * 70)
    log.info("Snippet Deduplication — REVIEWED DELETE MODE")
    log.info("  Approved file: %s", approved_file)
    log.info("=" * 70)

    with open(approved_file) as f:
        approved = json.load(f)

    if isinstance(approved, dict):
        ids = approved.get("approved_ids", [])
    elif isinstance(approved, list):
        ids = approved
    else:
        log.error("Invalid format"); sys.exit(1)

    log.info("  Approved IDs: %d", len(ids))

    if not ids:
        log.info("  Nothing to delete")
        return

    deleted = delete_by_ids(ids)
    log.info("  Deleted: %d", deleted)

    with conn.cursor() as cur:
        cur.execute("""
            UPDATE pattern_clusters SET snippet_count = COALESCE(sub.cnt, 0)
            FROM (SELECT cluster_id, COUNT(*) as cnt FROM training_snippets GROUP BY cluster_id) sub
            WHERE pattern_clusters.id = sub.cluster_id
        """)

    log.info("  Counts updated")
    log.info("=" * 70)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deduplicate training snippets")
    parser.add_argument("--delete-from", help="Path to approved deletion IDs JSON file")
    args = parser.parse_args()

    if args.delete_from:
        run_reviewed_delete(args.delete_from)
    else:
        run_audit()

    conn.close()
