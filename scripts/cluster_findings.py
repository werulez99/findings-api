#!/usr/bin/env python3
"""
Pattern clustering script for Valves Security.
Groups all findings into vulnerability pattern clusters.

Usage:
    DRY_RUN=true python scripts/cluster_findings.py   # preview only
    DRY_RUN=false python scripts/cluster_findings.py   # write to DB

Requires: DATABASE_URL env var (Supabase connection string)
"""

import logging
import os
import re
import sys
import uuid

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s")
log = logging.getLogger("cluster")

DATABASE_URL = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://")
if not DATABASE_URL:
    log.error("Missing DATABASE_URL"); sys.exit(1)

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() in ("1", "true", "yes")

# ══════════════════════════════════════════════════════════════════════════════
# CLUSTER DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

CLUSTERS = [
    # ── DEFI PRIMITIVES ──
    {
        "name": "Vault Share Accounting",
        "slug": "vault-share-accounting",
        "section": "defi_primitives",
        "description": "ERC4626 share inflation, first depositor attacks, donation attacks, totalAssets/totalShares desync, rounding in share calculations.",
        "invariant_template": "Share price must remain proportional to deposited assets. First depositor attacks must be prevented.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"erc.?4626|share.?price|vault.?inflation|first.?deposit|donation.?attack|share.?accounting|total.?assets.*total.?shares|shares?.?mint|redeem.*shares?", re.I),
        ],
        "category_match": ["Vault Inflation"],
    },
    {
        "name": "Lending & Liquidation",
        "slug": "lending-liquidation",
        "section": "defi_primitives",
        "description": "Health factor manipulation, liquidation threshold bypass, bad debt accumulation, interest rate manipulation, collateral factor abuse.",
        "invariant_template": "Position health must be accurately calculated. Liquidation must trigger exactly when positions become undercollateralized.",
        "difficulty": "advanced",
        "patterns": [
            re.compile(r"health.?factor|liquidat|collateral.?ratio|bad.?debt|borrow.?rate|interest.?rate.?manipul|ltv|loan.?to.?value|undercollateral|insolvenc", re.I),
        ],
        "category_match": [],
    },
    {
        "name": "DEX & AMM Logic",
        "slug": "dex-amm-logic",
        "section": "defi_primitives",
        "description": "Slippage manipulation, sandwich attacks, liquidity pool imbalance, swap path exploitation, tick/range accounting errors.",
        "invariant_template": "Swap outputs must reflect fair market value. Liquidity accounting must remain consistent across operations.",
        "difficulty": "advanced",
        "patterns": [
            re.compile(r"amm|swap.*slippage|liquidity.?pool|sandwich|constant.?product|uniswap|curve|tick|sqrtprice|pool.?balance", re.I),
        ],
        "category_match": [],
    },
    {
        "name": "Oracle Dependency",
        "slug": "oracle-dependency",
        "section": "defi_primitives",
        "description": "Spot price manipulation, stale price usage, TWAP manipulation, multi-oracle inconsistency, oracle failure modes.",
        "invariant_template": "Price data must reflect true market value and resist single-transaction manipulation.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"oracle|price.?feed|chainlink|twap|stale.?price|latestRoundData|staleness|heartbeat|price.?deviation", re.I),
        ],
        "category_match": ["Oracle Manipulation"],
    },
    {
        "name": "Flash Loan Attacks",
        "slug": "flash-loan-attacks",
        "section": "defi_primitives",
        "description": "Flash loan enabled price manipulation, governance attacks, collateral inflation, and arbitrage exploitation.",
        "invariant_template": "Protocol state must remain consistent across atomic transaction boundaries.",
        "difficulty": "advanced",
        "patterns": [
            re.compile(r"flash.?loan|flash.?mint|atomic.?arbitrage|borrowed.?capital|same.?block.?exploit", re.I),
        ],
        "category_match": ["Flash Loan"],
    },

    # ── EXECUTION FLOW ──
    {
        "name": "Reentrancy",
        "slug": "reentrancy",
        "section": "execution_flow",
        "description": "Classic single-function, cross-function, read-only, cross-contract reentrancy, and callback ordering issues.",
        "invariant_template": "State changes must complete before external calls. The check-effect-interaction pattern must hold.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"reentran|re.?entry|callback.*state|external.?call.*before.*state|cei.?pattern", re.I),
        ],
        "category_match": ["Reentrancy"],
    },
    {
        "name": "Access Control",
        "slug": "access-control",
        "section": "execution_flow",
        "description": "Missing modifiers, wrong role checks, initialization without auth, admin privilege abuse, two-step ownership issues.",
        "invariant_template": "Privileged operations must be restricted to authorized callers only.",
        "difficulty": "beginner",
        "patterns": [
            re.compile(r"access.?control|missing.?modifier|unauthorized|onlyowner|only.?admin|role.?check|permiss|privilege.?escalat", re.I),
        ],
        "category_match": ["Access Control"],
    },
    {
        "name": "Initialization Issues",
        "slug": "initialization",
        "section": "execution_flow",
        "description": "Uninitialized proxies, missing initializer guards, re-initialization attacks, constructor vs initializer confusion.",
        "invariant_template": "Initialization must occur exactly once. Critical parameters must be set before protocol use.",
        "difficulty": "beginner",
        "patterns": [
            re.compile(r"initializ|uninitializ|constructor.*proxy|re.?init|__init|setup.*missing", re.I),
        ],
        "category_match": ["Initialization"],
    },
    {
        "name": "Proxy & Upgrade Safety",
        "slug": "proxy-upgrade",
        "section": "execution_flow",
        "description": "Storage collision, function selector clashes, UUPS vs transparent proxy issues, delegatecall hazards.",
        "invariant_template": "Storage layout must remain consistent across implementation upgrades.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"proxy|delegatecall|storage.?collision|upgrade|uups|transparent|implementation.*slot|selector.*clash|eip.?1967", re.I),
        ],
        "category_match": ["Proxy / Upgrade"],
    },
    {
        "name": "Signature & Authentication",
        "slug": "signature-auth",
        "section": "execution_flow",
        "description": "Signature replay, malleability, EIP-712 domain issues, permit front-running, nonce management, ecrecover pitfalls.",
        "invariant_template": "Signatures must be validated correctly and resist replay across chains and contexts.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"signature|ecrecover|eip.?712|permit|replay.?attack|nonce|malleable|domain.?separator|sign.*verif", re.I),
        ],
        "category_match": ["Signature / Auth"],
    },

    # ── MATH & ACCOUNTING ──
    {
        "name": "Arithmetic Precision",
        "slug": "arithmetic-precision",
        "section": "math_accounting",
        "description": "Division before multiplication, precision loss, rounding direction errors, scaling factor mismatches.",
        "invariant_template": "Arithmetic operations must not lose precision beyond acceptable bounds. Rounding must favor the protocol.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"precision|rounding|truncat|division.?before|loss.?of.?precision|decimal|scaling.?factor|round.?down|round.?up", re.I),
        ],
        "category_match": ["Arithmetic / Precision"],
    },
    {
        "name": "Integer Overflow",
        "slug": "integer-overflow",
        "section": "math_accounting",
        "description": "Overflow/underflow in unchecked blocks, casting truncation, type narrowing, unsafe downcasts.",
        "invariant_template": "Arithmetic operations must not overflow or underflow. Type casts must preserve value.",
        "difficulty": "beginner",
        "patterns": [
            re.compile(r"overflow|underflow|unchecked|type.?cast|downcast|uint8.*uint256|narrow", re.I),
        ],
        "category_match": ["Integer Overflow"],
    },
    {
        "name": "Token Accounting",
        "slug": "token-accounting",
        "section": "math_accounting",
        "description": "Fee-on-transfer token issues, rebasing token incompatibility, ERC777 hooks, token decimal mismatches.",
        "invariant_template": "Token balances must be tracked accurately. Fee-on-transfer and rebasing tokens must be handled correctly.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"fee.?on.?transfer|rebasing|deflation|erc.?777|decimal.?mismatch|balance.?before.*after|token.?accounting|transfer.*amount", re.I),
        ],
        "category_match": [],
    },

    # ── CROSS-SYSTEM ──
    {
        "name": "Bridge & Cross-Chain",
        "slug": "bridge-cross-chain",
        "section": "cross_system",
        "description": "Message replay, chain ID confusion, bridge accounting errors, cross-chain oracle inconsistency.",
        "invariant_template": "Cross-chain messages must preserve integrity and prevent replay or forgery.",
        "difficulty": "advanced",
        "patterns": [
            re.compile(r"bridge|cross.?chain|layer.?zero|wormhole|ccip|chain.?id|message.?relay|l1.*l2|l2.*l1", re.I),
        ],
        "category_match": ["Bridge / Cross-Chain"],
    },
    {
        "name": "Front-Running & MEV",
        "slug": "frontrunning-mev",
        "section": "cross_system",
        "description": "Sandwich attacks, transaction ordering dependence, mempool exploitation, commit-reveal bypass.",
        "invariant_template": "Transaction outcomes must not depend on ordering that can be manipulated by miners or searchers.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"front.?run|mev|sandwich|mempool|transaction.?order|commit.?reveal|back.?run", re.I),
        ],
        "category_match": ["Front-Running / MEV"],
    },
    {
        "name": "Denial of Service",
        "slug": "denial-of-service",
        "section": "cross_system",
        "description": "Unbounded loops, griefing attacks, gas exhaustion, forced reverts blocking withdrawals.",
        "invariant_template": "Core protocol functions must remain callable regardless of external actor behavior.",
        "difficulty": "beginner",
        "patterns": [
            re.compile(r"denial.?of.?service|dos\b|grief|unbounded.?loop|gas.?limit|block.?gas|revert.*withdraw|stuck.?funds", re.I),
        ],
        "category_match": ["Denial of Service"],
    },
    {
        "name": "Governance Attacks",
        "slug": "governance-attacks",
        "section": "cross_system",
        "description": "Flash loan governance, proposal manipulation, timelock bypass, vote delegation exploits.",
        "invariant_template": "Governance decisions must reflect genuine stakeholder consensus and resist flash-loan manipulation.",
        "difficulty": "advanced",
        "patterns": [
            re.compile(r"governance|proposal|voting|timelock|delegate|quorum|snapshot.*vote", re.I),
        ],
        "category_match": [],
    },
    {
        "name": "Price Manipulation",
        "slug": "price-manipulation",
        "section": "defi_primitives",
        "description": "Spot price manipulation via large trades, LP token price manipulation, virtual price attacks.",
        "invariant_template": "Asset prices must resist manipulation through flash loans or large single trades.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"price.?manipulat|spot.?price|virtual.?price|lp.?token.?price", re.I),
        ],
        "category_match": ["Price Manipulation"],
    },
    {
        "name": "Logic Errors",
        "slug": "logic-errors",
        "section": "execution_flow",
        "description": "Wrong conditional logic, off-by-one errors, incorrect state machine transitions, missing edge cases.",
        "invariant_template": "Protocol logic must correctly implement intended behavior under all valid inputs.",
        "difficulty": "intermediate",
        "patterns": [
            re.compile(r"logic.?error|off.?by.?one|wrong.?condition|incorrect.?logic|state.?machine|edge.?case|boundary.?condition", re.I),
        ],
        "category_match": ["Logic Error"],
    },
]


def match_finding(title: str, description: str, category: str) -> list[tuple[str, float]]:
    """Return list of (cluster_slug, confidence) for a finding."""
    corpus = f"{title} {description}"
    matches = []

    for cluster in CLUSTERS:
        confidence = 0.0

        # Category exact match (highest confidence)
        if category and category in cluster["category_match"]:
            confidence = max(confidence, 0.9)

        # Pattern regex match
        for pattern in cluster["patterns"]:
            if pattern.search(corpus):
                confidence = max(confidence, 0.7)
                break

        if confidence > 0:
            matches.append((cluster["slug"], confidence))

    # If no match found, skip (don't force into a cluster)
    return matches


def run():
    import psycopg

    log.info("=" * 60)
    log.info("Pattern Clustering — Valves Security")
    log.info("  DRY_RUN = %s", DRY_RUN)
    log.info("  Clusters defined: %d", len(CLUSTERS))
    log.info("=" * 60)

    conn = psycopg.connect(DATABASE_URL)
    conn.autocommit = False

    # Step 1: Insert/update cluster definitions
    log.info("Step 1: Upserting %d cluster definitions...", len(CLUSTERS))
    if not DRY_RUN:
        with conn.transaction():
            for c in CLUSTERS:
                conn.execute("""
                    INSERT INTO pattern_clusters (name, slug, section, description, invariant_template, difficulty)
                    VALUES (%(name)s, %(slug)s, %(section)s, %(description)s, %(invariant_template)s, %(difficulty)s)
                    ON CONFLICT (slug) DO UPDATE SET
                        name = EXCLUDED.name,
                        section = EXCLUDED.section,
                        description = EXCLUDED.description,
                        invariant_template = EXCLUDED.invariant_template,
                        difficulty = EXCLUDED.difficulty
                """, {
                    "name": c["name"],
                    "slug": c["slug"],
                    "section": c["section"],
                    "description": c["description"],
                    "invariant_template": c["invariant_template"],
                    "difficulty": c["difficulty"],
                })
        log.info("  Clusters upserted.")
    else:
        for c in CLUSTERS:
            log.info("  [DRY] Would upsert: %s (%s)", c["name"], c["slug"])

    # Step 2: Load cluster IDs
    cluster_ids = {}
    if not DRY_RUN:
        with conn.cursor() as cur:
            cur.execute("SELECT id, slug FROM pattern_clusters")
            for row in cur.fetchall():
                cluster_ids[row[1]] = row[0]
        log.info("  Loaded %d cluster IDs", len(cluster_ids))

    # Step 3: Fetch all findings
    log.info("Step 2: Fetching all findings...")
    with conn.cursor() as cur:
        cur.execute("""
            SELECT id, title, description, vulnerability_category
            FROM findings
            WHERE enrichment_status = 'ENRICHED' AND visibility = 'PUBLIC'
        """)
        findings = cur.fetchall()
    log.info("  Found %d findings", len(findings))

    # Step 4: Classify each finding
    log.info("Step 3: Classifying findings...")
    cluster_counts = {}
    mapped_count = 0
    unmapped_count = 0
    mappings = []

    for fid, title, description, category in findings:
        matches = match_finding(title or "", description or "", category or "")
        if matches:
            mapped_count += 1
            for slug, confidence in matches:
                cluster_counts[slug] = cluster_counts.get(slug, 0) + 1
                mappings.append((fid, slug, confidence))
        else:
            unmapped_count += 1

    log.info("  Mapped: %d findings", mapped_count)
    log.info("  Unmapped: %d findings", unmapped_count)
    log.info("")
    log.info("  Cluster distribution:")
    for slug, count in sorted(cluster_counts.items(), key=lambda x: -x[1]):
        name = next((c["name"] for c in CLUSTERS if c["slug"] == slug), slug)
        log.info("    %-35s %d findings", name, count)

    # Step 5: Write mappings
    if not DRY_RUN:
        log.info("Step 4: Writing %d mappings to finding_cluster_map...", len(mappings))
        with conn.transaction():
            # Clear existing mappings
            conn.execute("DELETE FROM finding_cluster_map")
            # Insert new mappings
            batch = []
            for fid, slug, confidence in mappings:
                cid = cluster_ids.get(slug)
                if cid:
                    batch.append((fid, cid, confidence))

            for i in range(0, len(batch), 500):
                chunk = batch[i:i+500]
                conn.executemany(
                    "INSERT INTO finding_cluster_map (finding_id, cluster_id, confidence) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                    chunk,
                )
                log.info("  Inserted batch %d-%d", i, min(i+500, len(batch)))

        # Update counts
        log.info("Step 5: Updating cluster finding counts...")
        with conn.transaction():
            conn.execute("""
                UPDATE pattern_clusters SET finding_count = sub.cnt
                FROM (
                    SELECT cluster_id, COUNT(*) as cnt
                    FROM finding_cluster_map
                    GROUP BY cluster_id
                ) sub
                WHERE pattern_clusters.id = sub.cluster_id
            """)
        log.info("  Counts updated.")
    else:
        log.info("[DRY RUN] Would write %d mappings", len(mappings))

    conn.close()
    log.info("=" * 60)
    log.info("Done. %d clusters, %d findings mapped, %d unmapped.",
             len(CLUSTERS), mapped_count, unmapped_count)
    log.info("=" * 60)


if __name__ == "__main__":
    run()
