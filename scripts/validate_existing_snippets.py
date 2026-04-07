#!/usr/bin/env python3
"""
Valves Security — Legacy Snippet Validator

Scans existing snippets and validates each one semantically.
Produces a reviewable JSON report. Does NOT delete by default.

Modes:
  AUDIT (default):
    python3 scripts/validate_existing_snippets.py
    → writes report to validation_report.json

  REVIEWED DELETE:
    python3 scripts/validate_existing_snippets.py --delete-from approved_deletes.json
    → deletes only snippet IDs listed in the approved file

Env vars:
    ANTHROPIC_API_KEY   required
    DATABASE_URL        required
    CLUSTER_SLUG        optional (single cluster)
    REPORT_PATH         optional (default: validation_report.json)
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
log = logging.getLogger("validate")

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
CLUSTER_SLUG = os.environ.get("CLUSTER_SLUG", "")
REPORT_PATH = os.environ.get("REPORT_PATH", "validation_report.json")
MODEL = "claude-sonnet-4-20250514"

if not ANTHROPIC_API_KEY:
    log.error("Missing ANTHROPIC_API_KEY"); sys.exit(1)
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
conn = psycopg.connect(DATABASE_URL, autocommit=True, prepare_threshold=None)

stats = {
    "total_scanned": 0,
    "passed": 0,
    "flagged": 0,
    "errors": 0,
}


# ══════════════════════════════════════════════════════════════════════════════
# LLM
# ══════════════════════════════════════════════════════════════════════════════

def call_llm(prompt: str, max_tokens: int = 1000, retries: int = 2) -> dict | None:
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
# VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

def validate_snippet(cluster_name: str, snippet: dict) -> dict:
    """Validate a single snippet against quality criteria."""

    code = snippet.get("solidity_code", "")
    what_breaks = snippet.get("what_breaks", "")
    annotations = snippet.get("annotations", [])
    if isinstance(annotations, str):
        try: annotations = json.loads(annotations)
        except: annotations = []
    attack_pattern = snippet.get("attack_pattern", "")

    prompt = f"""You are validating a Solidity training snippet for a security training platform.

ASSIGNED CLUSTER: {cluster_name}
ATTACK PATTERN: {attack_pattern}

CODE:
{code}

WHAT BREAKS: {what_breaks}

ANNOTATIONS: {json.dumps(annotations, indent=2)}

Validate against these criteria:

1. CLUSTER FIT: Is the primary bug genuinely a "{cluster_name}" issue? If another category fits better, name it.
2. SINGLE BUG: Is there exactly one primary material vulnerability? List any secondary bugs.
3. ANNOTATION CONSISTENCY: Do all annotations describe the same root cause?
4. CODE-DESCRIPTION MATCH: Does what_breaks accurately describe the bug visible in the code?
5. CODE QUALITY: Is the code realistic enough for training? Any compile contradictions (e.g., immutable + initializer)?

Return ONLY valid JSON:
{{
  "pass": true,
  "matches_cluster": true,
  "best_cluster": "{cluster_name}",
  "single_bug": true,
  "primary_bug": "description",
  "secondary_bugs": [],
  "annotation_consistent": true,
  "code_description_match": true,
  "code_quality_issues": [],
  "reason": "Summary of validation result"
}}

Be strict. Quality is more important than volume."""

    result = call_llm(prompt, max_tokens=800)
    if not result:
        return {"pass": False, "reason": "Validator call failed", "error": True}
    return result


def is_flagged(v: dict) -> bool:
    """Determine if a validation result should be flagged for review."""
    if v.get("error"):
        return True
    if not v.get("pass", False):
        return True
    if not v.get("matches_cluster", False):
        return True
    if not v.get("single_bug", True):
        return True
    if not v.get("annotation_consistent", True):
        return True
    if not v.get("code_description_match", True):
        return True
    if len(v.get("secondary_bugs", [])) > 0:
        return True
    if len(v.get("code_quality_issues", [])) > 0:
        return True
    return False


def recommended_action(v: dict) -> str:
    """Determine recommended action based on validation result."""
    if v.get("error"):
        return "retry_validation"
    if not v.get("matches_cluster", True):
        return "delete_and_regenerate"
    if len(v.get("secondary_bugs", [])) > 0:
        return "delete_and_regenerate"
    if not v.get("annotation_consistent", True):
        return "fix_annotations"
    if not v.get("code_description_match", True):
        return "fix_description"
    if len(v.get("code_quality_issues", [])) > 0:
        return "review_quality"
    return "keep"


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════

def fetch_snippets() -> list[dict]:
    with conn.cursor() as cur:
        if CLUSTER_SLUG:
            cur.execute("""
                SELECT ts.id, ts.title, ts.difficulty, ts.solidity_code, ts.annotations,
                       ts.what_breaks, ts.attack_pattern, ts.invariant, ts.exploit_path,
                       ts.why_missed, pc.name as cluster_name, pc.slug as cluster_slug
                FROM training_snippets ts
                JOIN pattern_clusters pc ON ts.cluster_id = pc.id
                WHERE pc.slug = %s
                ORDER BY pc.name, ts.created_at
            """, (CLUSTER_SLUG,))
        else:
            cur.execute("""
                SELECT ts.id, ts.title, ts.difficulty, ts.solidity_code, ts.annotations,
                       ts.what_breaks, ts.attack_pattern, ts.invariant, ts.exploit_path,
                       ts.why_missed, pc.name as cluster_name, pc.slug as cluster_slug
                FROM training_snippets ts
                JOIN pattern_clusters pc ON ts.cluster_id = pc.id
                ORDER BY pc.name, ts.created_at
            """)
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
    log.info("Legacy Snippet Validator — AUDIT MODE")
    log.info("  Target: %s", CLUSTER_SLUG or "all clusters")
    log.info("  Report: %s", REPORT_PATH)
    log.info("=" * 70)

    snippets = fetch_snippets()
    log.info("Found %d snippets to validate", len(snippets))

    report = {
        "mode": "audit",
        "total_scanned": 0,
        "passed": 0,
        "flagged": 0,
        "errors": 0,
        "flagged_snippets": [],
        "summary_by_cluster": {},
        "summary_by_action": {},
    }

    for i, s in enumerate(snippets):
        stats["total_scanned"] += 1
        report["total_scanned"] += 1
        sid = str(s["id"])
        cluster = s["cluster_name"]

        if (i + 1) % 10 == 0 or i == 0:
            log.info("[%d/%d] Validating: %s (%s)", i + 1, len(snippets), (s["title"] or "?")[:40], cluster)

        v = validate_snippet(cluster, s)

        # Track per-cluster
        if cluster not in report["summary_by_cluster"]:
            report["summary_by_cluster"][cluster] = {"total": 0, "passed": 0, "flagged": 0}
        report["summary_by_cluster"][cluster]["total"] += 1

        if is_flagged(v):
            stats["flagged"] += 1
            report["flagged"] += 1
            report["summary_by_cluster"][cluster]["flagged"] += 1

            action = recommended_action(v)
            report["summary_by_action"][action] = report["summary_by_action"].get(action, 0) + 1

            entry = {
                "snippet_id": sid,
                "cluster": cluster,
                "cluster_slug": s["cluster_slug"],
                "title": s["title"],
                "attack_pattern": s["attack_pattern"],
                "difficulty": s["difficulty"],
                "validation": v,
                "recommended_action": action,
                "delete_candidate": action == "delete_and_regenerate",
            }
            report["flagged_snippets"].append(entry)

            if v.get("error"):
                stats["errors"] += 1
                report["errors"] += 1
        else:
            stats["passed"] += 1
            report["passed"] += 1
            report["summary_by_cluster"][cluster]["passed"] += 1

        time.sleep(0.5)

    # Write report
    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2, default=str)

    log.info("")
    log.info("=" * 70)
    log.info("VALIDATION REPORT")
    log.info("=" * 70)
    log.info("  Total scanned:  %d", report["total_scanned"])
    log.info("  Passed:         %d", report["passed"])
    log.info("  Flagged:        %d", report["flagged"])
    log.info("  Errors:         %d", report["errors"])
    log.info("")
    log.info("  Actions breakdown:")
    for action, count in sorted(report["summary_by_action"].items(), key=lambda x: -x[1]):
        log.info("    %-30s %d", action, count)
    log.info("")
    log.info("  Delete candidates: %d", sum(1 for f in report["flagged_snippets"] if f["delete_candidate"]))
    log.info("  Report written to: %s", REPORT_PATH)
    log.info("=" * 70)


# ══════════════════════════════════════════════════════════════════════════════
# REVIEWED DELETE MODE
# ══════════════════════════════════════════════════════════════════════════════

def run_reviewed_delete(approved_file: str):
    log.info("=" * 70)
    log.info("Legacy Snippet Validator — REVIEWED DELETE MODE")
    log.info("  Approved file: %s", approved_file)
    log.info("=" * 70)

    with open(approved_file) as f:
        approved = json.load(f)

    if isinstance(approved, dict):
        ids = approved.get("approved_ids", [])
    elif isinstance(approved, list):
        ids = approved
    else:
        log.error("Invalid approved file format"); sys.exit(1)

    log.info("  Approved IDs: %d", len(ids))

    if not ids:
        log.info("  Nothing to delete")
        return

    deleted = delete_by_ids(ids)
    log.info("  Deleted: %d snippets", deleted)

    # Update counts
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE pattern_clusters SET snippet_count = COALESCE(sub.cnt, 0)
            FROM (SELECT cluster_id, COUNT(*) as cnt FROM training_snippets GROUP BY cluster_id) sub
            WHERE pattern_clusters.id = sub.cluster_id
        """)

    log.info("  Snippet counts updated")
    log.info("=" * 70)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate existing training snippets")
    parser.add_argument("--delete-from", help="Path to approved deletion IDs JSON file")
    args = parser.parse_args()

    if args.delete_from:
        run_reviewed_delete(args.delete_from)
    else:
        run_audit()

    conn.close()
