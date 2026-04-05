#!/usr/bin/env python3
"""
Solodit → Findings ingestion script.
Run manually to populate the database with real audit findings.

FIRST RUN PROCEDURE:
    1. Set DRY_RUN=true and INGEST_LIMIT=5 to inspect API response shape
    2. Verify field mapping looks correct in logs
    3. Set DRY_RUN=false and INGEST_LIMIT=5 to insert first 5 real findings
    4. Verify in Supabase that 5 rows appear in the findings table
    5. Scale up: INGEST_LIMIT=500, then 2000

Required env vars:
    DATABASE_URL        Supabase PostgreSQL connection string (pooler URL)
    SOLODIT_API_KEY     Solodit API key — never commit, never log

Optional env vars:
    DRY_RUN             true/false — if true, fetch and map but do NOT write to DB (default: true)
    INGEST_LIMIT        max findings to fetch total (default: 5 for safety)
    INGEST_BATCH_SIZE   findings per API request (default: 5, max 100)
    TENANT_ID           UUID for tenant row (default: 00000000-0000-0000-0000-000000000001)
    LOG_RAW_KEYS        true/false — log raw API field names for first N records (default: true)
    LOG_RAW_KEYS_COUNT  how many records to log raw keys for (default: 3)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import time
import uuid
from typing import Any

import requests

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ingest_solodit")

# ── Config (all from env, no defaults for secrets) ────────────────────────────

def _require_env(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        log.error("Missing required env var: %s", key)
        sys.exit(1)
    return val

def _bool_env(key: str, default: bool) -> bool:
    val = os.environ.get(key, "").strip().lower()
    if not val:
        return default
    return val in ("1", "true", "yes")

DATABASE_URL    = _require_env("DATABASE_URL").replace("postgresql+asyncpg://", "postgresql://")
SOLODIT_API_KEY = _require_env("SOLODIT_API_KEY")

DRY_RUN           = _bool_env("DRY_RUN", default=True)   # safe default: no writes
INGEST_LIMIT      = int(os.getenv("INGEST_LIMIT", "5"))   # safe default: tiny batch
BATCH_SIZE        = min(int(os.getenv("INGEST_BATCH_SIZE", "5")), 100)
TENANT_ID         = os.getenv("TENANT_ID", "00000000-0000-0000-0000-000000000001")
LOG_RAW_KEYS      = _bool_env("LOG_RAW_KEYS", default=True)
LOG_RAW_KEYS_COUNT = int(os.getenv("LOG_RAW_KEYS_COUNT", "3"))

SOLODIT_ENDPOINT = "https://solodit.cyfrin.io/api/v1/solodit/findings"

# API key is added at request time only — never logged, never stored in a variable
# that gets printed

# ── Severity mapping ──────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, str] = {
    "critical":      "CRITICAL",
    "high":          "HIGH",
    "medium":        "MEDIUM",
    "med":           "MEDIUM",
    "low":           "LOW",
    "info":          "LOW",
    "informational": "LOW",
    "gas":           "LOW",
    "note":          "LOW",
    "optimization":  "LOW",
}

def map_severity(raw: Any) -> str:
    if not raw:
        return "MEDIUM"
    return _SEVERITY_MAP.get(str(raw).strip().lower(), "MEDIUM")

# ── Classification ────────────────────────────────────────────────────────────

_CATEGORY_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"reentran",                                re.I), "Reentrancy"),
    (re.compile(r"overflow|underflow",                      re.I), "Integer Overflow"),
    (re.compile(r"oracle",                                  re.I), "Oracle Manipulation"),
    (re.compile(r"access.?control|unauthorized|onlyowner",  re.I), "Access Control"),
    (re.compile(r"flash.?loan",                             re.I), "Flash Loan"),
    (re.compile(r"front.?run|mev|sandwich",                 re.I), "Front-Running / MEV"),
    (re.compile(r"price.?manipulat",                        re.I), "Price Manipulation"),
    (re.compile(r"denial.?of.?service|dos\b|grief",         re.I), "Denial of Service"),
    (re.compile(r"rounding|precision|truncat|integer.?divis", re.I), "Arithmetic / Precision"),
    (re.compile(r"signature|ecrecover|replay|nonce",        re.I), "Signature / Auth"),
    (re.compile(r"proxy|delegatecall|storage.?collision|upgrade", re.I), "Proxy / Upgrade"),
    (re.compile(r"initializ",                               re.I), "Initialization"),
    (re.compile(r"inflation|share.?price|erc.?4626|first.?deposit", re.I), "Vault Inflation"),
    (re.compile(r"cross.?chain|bridge",                     re.I), "Bridge / Cross-Chain"),
    (re.compile(r"logic.?error|incorrect.?logic|wrong.?condition", re.I), "Logic Error"),
]

_VECTOR_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"flash.?loan|arbitrage|economic|manipulat|liquidat", re.I), "economic"),
    (re.compile(r"cross.?contract|callback|delegate|external.?call|reentran", re.I), "cross-contract"),
    (re.compile(r"off.?chain|oracle|price.?feed|chainlink|signer|signature", re.I), "off-chain"),
    (re.compile(r"on.?chain|mempool|front.?run|mev|sandwich|block", re.I), "on-chain"),
]

_TAG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"reentran",             re.I), "reentrancy"),
    (re.compile(r"\boverflow\b",         re.I), "overflow"),
    (re.compile(r"\bunderflow\b",        re.I), "underflow"),
    (re.compile(r"\boracle\b",           re.I), "oracle"),
    (re.compile(r"flash.?loan",          re.I), "flash-loan"),
    (re.compile(r"front.?run",           re.I), "front-running"),
    (re.compile(r"\bmev\b",              re.I), "mev"),
    (re.compile(r"access.?control",      re.I), "access-control"),
    (re.compile(r"\bsignature\b",        re.I), "signature"),
    (re.compile(r"\breplay\b",           re.I), "replay"),
    (re.compile(r"\bproxy\b",            re.I), "proxy"),
    (re.compile(r"delegatecall",         re.I), "delegatecall"),
    (re.compile(r"\bupgrade\b",          re.I), "upgrade"),
    (re.compile(r"initializ",            re.I), "initialization"),
    (re.compile(r"rounding|precision",   re.I), "precision"),
    (re.compile(r"denial.?of.?service|grief", re.I), "dos"),
    (re.compile(r"erc.?4626|share.?price|inflation", re.I), "erc4626"),
    (re.compile(r"cross.?chain|bridge",  re.I), "bridge"),
    (re.compile(r"price.?manipulat",     re.I), "price-manipulation"),
    (re.compile(r"\bwithdraw\b",         re.I), "withdraw"),
    (re.compile(r"\beth\b|ether",        re.I), "eth"),
    (re.compile(r"erc.?20",              re.I), "erc20"),
    (re.compile(r"erc.?721|\bnft\b",     re.I), "nft"),
    (re.compile(r"\bloop\b|iteration",   re.I), "loop"),
    (re.compile(r"\btimestamp\b",        re.I), "timestamp"),
    (re.compile(r"governance|voting",    re.I), "governance"),
]

_RISK_BASE = {"CRITICAL": 95, "HIGH": 79, "MEDIUM": 54, "LOW": 24}

_MULTI_SPACE = re.compile(r" {2,}")

def _clean(s: Any) -> str:
    if s is None:
        return ""
    return _MULTI_SPACE.sub(" ", str(s).strip())

def classify(corpus: str) -> tuple[str, str, list[str]]:
    category = "Unknown"
    for pattern, label in _CATEGORY_RULES:
        if pattern.search(corpus):
            category = label
            break

    attack_vector = "unknown"
    for pattern, label in _VECTOR_RULES:
        if pattern.search(corpus):
            attack_vector = label
            break

    seen: set[str] = set()
    tags: list[str] = []
    for pattern, tag in _TAG_PATTERNS:
        if len(tags) >= 5:
            break
        if tag not in seen and pattern.search(corpus):
            seen.add(tag)
            tags.append(tag)

    return category, attack_vector, tags

def build_short_summary(title: str, description: str) -> str:
    boundary = re.search(r"[.!?]", description[:400])
    first = description[:boundary.start()+1].strip() if boundary else description.strip()
    raw = f"{title.strip()}. {first}"
    if len(raw) <= 200:
        return raw
    truncated = raw[:199]
    last_space = truncated.rfind(" ")
    if last_space > 100:
        truncated = truncated[:last_space]
    return truncated.rstrip(".,;:") + "…"

def compute_dedup_hash(title: str, description: str, severity: str) -> str:
    payload = f"{_clean(title)}\x00{_clean(description)}\x00{severity.upper()}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

# ── Safe field extraction ─────────────────────────────────────────────────────

def _extract_str(raw: dict, *keys: str) -> str:
    """Try keys in order, return first non-empty string found."""
    for key in keys:
        val = raw.get(key)
        # Handle nested dicts like {"name": "..."} for protocol
        if isinstance(val, dict):
            val = val.get("name") or val.get("title") or val.get("slug") or ""
        if val and str(val).strip():
            return _clean(str(val))
    return ""

def _extract_nested_str(raw: dict, parent: str, *child_keys: str) -> str:
    """Safely extract from raw[parent][child_key]."""
    parent_val = raw.get(parent)
    if not isinstance(parent_val, dict):
        return ""
    for key in child_keys:
        val = parent_val.get(key)
        if val and str(val).strip():
            return _clean(str(val))
    return ""

# ── Solodit API fetcher ───────────────────────────────────────────────────────

def fetch_page(offset: int, limit: int) -> dict[str, Any]:
    page_number = (offset // limit) + 1
    payload = {
        "page": page_number,
        "pageSize": limit,
        "filters": {
            "impact": ["HIGH", "MEDIUM", "LOW", "GAS"],
            "sortField": "Recency",
            "sortDirection": "Desc",
        }
    }
    headers = {
        "X-Cyfrin-API-Key": SOLODIT_API_KEY,
        "Content-Type":     "application/json",
    }

    for attempt in range(1, 4):
        try:
            resp = requests.post(
                SOLODIT_ENDPOINT,
                headers=headers,
                json=payload,
                timeout=30,
            )
            if resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", "15"))
                log.warning("Rate limited — waiting %ds before retry…", wait)
                time.sleep(wait)
                continue
            if resp.status_code == 401:
                log.error("API key rejected (HTTP 401). Check SOLODIT_API_KEY.")
                sys.exit(1)
            if resp.status_code == 200:
                data = resp.json()
                log.info("Raw API response preview: %s", str(data)[:500])
                log.info("Metadata: %s", data.get("metadata", {}))
                return data
            log.warning("HTTP %d on attempt %d — body: %s",
                        resp.status_code, attempt, resp.text[:300])
            time.sleep(3 * attempt)
        except requests.RequestException as exc:
            log.warning("Network error on attempt %d: %s", attempt, exc)
            time.sleep(3 * attempt)

    raise RuntimeError(f"Failed to fetch offset={offset} after 3 attempts")

def extract_items(page: Any) -> list[dict]:
    """Handle multiple possible Solodit response shapes."""
    if isinstance(page, list):
        return page
    if isinstance(page, dict):
        for key in ("findings", "data", "results", "items"):
            val = page.get(key)
            if isinstance(val, list):
                return val
    log.warning("Unexpected API response shape. Top-level keys: %s",
                list(page.keys()) if isinstance(page, dict) else type(page).__name__)
    return []

# ── Record mapper ─────────────────────────────────────────────────────────────

def map_record(raw: dict, record_index: int) -> dict[str, Any] | None:
    """
    Map one raw Solodit record to our findings schema.
    Returns None if the record is not usable (missing title or description).
    Logs field mapping for early records to help debug.
    """
    # Log raw keys for first N records so you can verify the API shape
    if LOG_RAW_KEYS and record_index < LOG_RAW_KEYS_COUNT:
        log.info(
            "[record %d] Raw API keys: %s",
            record_index,
            list(raw.keys()),
        )
        # Log values of likely fields (not sensitive, just audit data)
        for inspect_key in ("title", "severity", "impact", "protocol",
                            "auditor", "description", "body", "id", "slug"):
            val = raw.get(inspect_key)
            if val is not None:
                preview = str(val)[:120].replace("\n", " ")
                log.info("  [record %d] %s = %r", record_index, inspect_key, preview)

    # ── Title ──
    title = _extract_str(raw, "title", "name", "heading")
    if not title:
        log.warning("[record %d] Skipping — no title found. Keys: %s",
                    record_index, list(raw.keys()))
        return None

    # ── Description ──
    description = _extract_str(raw, "description", "body", "content", "detail", "text")
    if not description:
        log.warning("[record %d] Skipping — no description found. Title: %r",
                    record_index, title[:80])
        return None

    # ── Severity ──
    raw_sev  = _extract_str(raw, "severity", "impact", "risk")
    severity = map_severity(raw_sev)

    # ── Dedup hash ──
    dedup_hash = compute_dedup_hash(title, description, severity)

    # ── Classification ──
    corpus = title + " " + description
    category, attack_vector, tags = classify(corpus)
    risk_score    = _RISK_BASE.get(severity, 50)
    short_summary = build_short_summary(title, description)

    # ── Source identifiers ──
    external_id = _extract_str(raw, "id", "external_id", "slug", "finding_id")
    if not external_id:
        external_id = dedup_hash[:16]   # stable fallback

    source_url = _extract_str(raw, "url", "source_url", "link", "report_url")
    # Try nested: raw["report"]["url"]
    if not source_url:
        source_url = _extract_nested_str(raw, "report", "url", "link")

    # ── Protocol ──
    protocol_name = (
        _extract_str(raw, "protocol", "protocol_name", "project")
        or _extract_nested_str(raw, "protocol", "name", "slug", "title")
        or None
    )

    # ── Firm / Auditor ──
    firm_name = (
        _extract_str(raw, "auditor", "firm", "firm_name", "audit_firm")
        or _extract_nested_str(raw, "auditor", "name", "slug")
        or _extract_nested_str(raw, "contest", "name", "platform")
        or None
    )

    mapped = {
        "title":                 title,
        "description":           description,
        "severity":              severity,
        "dedup_hash":            dedup_hash,
        "source_external_id":    external_id,
        "source_url":            source_url or "",
        "protocol_name":         protocol_name,
        "firm_name":             firm_name,
        "vulnerability_category": category,
        "attack_vector":         attack_vector,
        "tags":                  json.dumps(tags),
        "risk_score":            risk_score,
        "short_summary":         short_summary,
    }

    if LOG_RAW_KEYS and record_index < LOG_RAW_KEYS_COUNT:
        log.info(
            "[record %d] Mapped → severity=%s category=%s protocol=%r firm=%r tags=%s",
            record_index, severity, category, protocol_name, firm_name, tags,
        )

    return mapped

# ── DB insert ─────────────────────────────────────────────────────────────────

INSERT_SQL = """
INSERT INTO findings (
    id, canonical_id, tenant_id,
    source_type, source_external_id, source_url,
    dedup_hash, title, description, severity,
    protocol_name, firm_name,
    language, chain,
    vulnerability_category, attack_vector,
    tags, risk_score, short_summary,
    enrichment_status, knowledge_layer, visibility,
    valid_from, is_current, version,
    created_at, ingested_at, updated_at
)
VALUES (
    %(id)s, %(canonical_id)s, %(tenant_id)s,
    'SOLODIT', %(source_external_id)s, %(source_url)s,
    %(dedup_hash)s, %(title)s, %(description)s, %(severity)s,
    %(protocol_name)s, %(firm_name)s,
    'Solidity', 'EVM',
    %(vulnerability_category)s, %(attack_vector)s,
    %(tags)s::jsonb, %(risk_score)s, %(short_summary)s,
    'ENRICHED', 'CANONICAL_PUBLIC', 'PUBLIC',
    NOW(), TRUE, 1,
    NOW(), NOW(), NOW()
)
ON CONFLICT (dedup_hash) DO NOTHING
"""

def insert_finding(conn: Any, mapped: dict) -> bool:
    """Returns True if inserted, False if duplicate."""
    new_id = uuid.uuid4()
    params = {
        **mapped,
        "id":        new_id,
        "canonical_id": new_id,
        "tenant_id": TENANT_ID,
    }
    with conn.cursor() as cur:
        cur.execute(INSERT_SQL, params)
        return cur.rowcount == 1

# ── Main ──────────────────────────────────────────────────────────────────────

def run() -> None:
    log.info("=" * 60)
    log.info("Solodit ingestion starting")
    log.info("  DRY_RUN      = %s", DRY_RUN)
    log.info("  INGEST_LIMIT = %d", INGEST_LIMIT)
    log.info("  BATCH_SIZE   = %d", BATCH_SIZE)
    log.info("  LOG_RAW_KEYS = %s (first %d records)", LOG_RAW_KEYS, LOG_RAW_KEYS_COUNT)
    if DRY_RUN:
        log.info("  *** DRY RUN MODE — no writes to DB ***")
    log.info("=" * 60)

    # Only import psycopg if we actually need to write
    conn = None
    if not DRY_RUN:
        import psycopg
        conn = psycopg.connect(DATABASE_URL)
        conn.autocommit = False
        log.info("Connected to database.")

    total_fetched  = 0
    total_mapped   = 0
    total_inserted = 0
    total_dupes    = 0
    total_skipped  = 0
    record_index   = 0

    # Find how many findings already exist to skip past them
    if conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM findings")
            existing_count = cur.fetchone()[0]
    else:
        existing_count = 0

    # Start Solodit pagination from where we left off
    offset = existing_count
    log.info("DB has %d findings — starting Solodit fetch from offset %d",
             existing_count, offset)

    try:
        while True:
            batch_limit = BATCH_SIZE

            log.info("─" * 40)
            log.info("Fetching offset=%d limit=%d…", offset, batch_limit)

            page  = fetch_page(offset, batch_limit)
            items = extract_items(page)

            if not items:
                log.info("No items returned — reached end of Solodit data.")
                break

            log.info("Received %d items from API.", len(items))

            batch_inserted = 0
            batch_dupes    = 0
            batch_skipped  = 0
            batch_mapped   = []

            for raw in items:
                try:
                    mapped = map_record(raw, record_index)
                    record_index += 1
                    if mapped is None:
                        batch_skipped += 1
                        continue
                    batch_mapped.append(mapped)
                except Exception as exc:
                    log.warning("map_record error on record %d: %s", record_index, exc)
                    record_index += 1
                    batch_skipped += 1

            total_mapped += len(batch_mapped)

            if DRY_RUN:
                log.info(
                    "[DRY RUN] Would insert %d records, skip %d",
                    len(batch_mapped), batch_skipped,
                )
                # Print a sample of mapped records for inspection
                for i, m in enumerate(batch_mapped[:3]):
                    log.info(
                        "[DRY RUN sample %d] title=%r severity=%s "
                        "category=%s protocol=%r tags=%s risk=%d",
                        i,
                        m["title"][:80],
                        m["severity"],
                        m["vulnerability_category"],
                        m["protocol_name"],
                        m["tags"],
                        m["risk_score"],
                    )
            else:
                with conn.transaction():
                    for mapped in batch_mapped:
                        try:
                            inserted = insert_finding(conn, mapped)
                            if inserted:
                                batch_inserted += 1
                                log.info(
                                    "  ✓ inserted: %r [%s | %s]",
                                    mapped["title"][:70],
                                    mapped["severity"],
                                    mapped["vulnerability_category"],
                                )
                            else:
                                batch_dupes += 1
                                log.info(
                                    "  ~ duplicate: %r",
                                    mapped["title"][:70],
                                )
                        except Exception as exc:
                            log.warning(
                                "  ✗ insert error for %r: %s",
                                mapped.get("title","?")[:60], exc,
                            )
                            batch_skipped += 1

            total_fetched  += len(items)
            total_inserted += batch_inserted
            total_dupes    += batch_dupes
            total_skipped  += batch_skipped
            offset         += len(items)

            log.info(
                "Batch summary — mapped=%d inserted=%d dupes=%d skipped=%d",
                len(batch_mapped), batch_inserted, batch_dupes, batch_skipped,
            )

            # Polite pause between pages
            if len(items) == batch_limit:
                time.sleep(0.5)

            # Partial page = last page
            if len(items) < batch_limit:
                log.info("Partial page received — end of available data.")
                break

    finally:
        if conn:
            conn.close()

    log.info("=" * 60)
    log.info("Ingestion complete")
    log.info("  Total fetched  : %d", total_fetched)
    log.info("  Total mapped   : %d", total_mapped)
    log.info("  Total inserted : %d", total_inserted)
    log.info("  Total dupes    : %d", total_dupes)
    log.info("  Total skipped  : %d", total_skipped)
    if DRY_RUN:
        log.info("  (DRY RUN — nothing was written to DB)")
    log.info("=" * 60)


if __name__ == "__main__":
    run()
