import json
import uuid
from typing import Any
import asyncpg


_BASE_WHERE = "enrichment_status = 'ENRICHED' AND visibility = 'PUBLIC'"


def _coerce_tags(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(t) for t in raw]
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return [str(t) for t in parsed] if isinstance(parsed, list) else []
        except Exception:
            return []
    return []


def _row_to_dict(r: asyncpg.Record) -> dict:
    return {
        "id": str(r["id"]),
        "title": r["title"],
        "severity": r["severity"],
        "protocol_name": r["protocol_name"],
        "firm_name": r["firm_name"],
        "vulnerability_category": r["vulnerability_category"],
        "attack_vector": r["attack_vector"],
        "tags": _coerce_tags(r["tags"]),
        "risk_score": r["risk_score"],
        "short_summary": r["short_summary"],
        "description": r["description"],
        "created_at": r["created_at"].isoformat() if r["created_at"] else None,
    }


class TrainingService:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def list_categories(self) -> list[dict]:
        sql = f"""
            SELECT vulnerability_category, COUNT(*) as count
            FROM findings
            WHERE {_BASE_WHERE}
              AND vulnerability_category IS NOT NULL
              AND vulnerability_category != 'Unknown'
            GROUP BY vulnerability_category
            ORDER BY count DESC
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql)
        return [{"category": r["vulnerability_category"], "count": r["count"]} for r in rows]

    async def random_finding(
        self,
        *,
        severity: str | None,
        category: str | None,
        exclude: list[uuid.UUID],
    ) -> dict | None:
        conditions = [_BASE_WHERE]
        params: list[Any] = []

        if severity:
            params.append(severity.upper())
            conditions.append(f"severity = ${len(params)}::severity_level")

        if category:
            params.append(category)
            conditions.append(f"vulnerability_category = ${len(params)}")

        if exclude:
            params.append(exclude)
            conditions.append(f"id != ALL(${len(params)}::uuid[])")

        where = " AND ".join(conditions)
        sql = f"""
            SELECT id, title, description, severity::text, protocol_name, firm_name,
                   vulnerability_category, attack_vector, tags, risk_score,
                   short_summary, created_at
            FROM findings
            WHERE {where}
            ORDER BY random()
            LIMIT 1
        """
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(sql, *params)
        if row is None:
            return None
        return _row_to_dict(row)

    async def variant_drill(self, *, category: str, count: int) -> dict:
        # Get findings from the requested category
        sql = f"""
            SELECT id, title, description, severity::text, protocol_name, firm_name,
                   vulnerability_category, attack_vector, tags, risk_score,
                   short_summary, created_at
            FROM findings
            WHERE {_BASE_WHERE}
              AND vulnerability_category = $1
            ORDER BY random()
            LIMIT $2
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, category, count)

        items = [_row_to_dict(r) for r in rows]
        return {
            "category": category,
            "count": len(items),
            "items": items,
        }

    async def db_stats(self) -> dict:
        sev_sql = f"""
            SELECT severity::text, COUNT(*) as count
            FROM findings
            WHERE {_BASE_WHERE}
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END
        """
        cat_sql = f"""
            SELECT vulnerability_category, COUNT(*) as count
            FROM findings
            WHERE {_BASE_WHERE}
              AND vulnerability_category IS NOT NULL
              AND vulnerability_category != 'Unknown'
            GROUP BY vulnerability_category
            ORDER BY count DESC
            LIMIT 20
        """
        total_sql = f"SELECT COUNT(*) FROM findings WHERE {_BASE_WHERE}"
        protocols_sql = f"SELECT COUNT(DISTINCT protocol_name) FROM findings WHERE {_BASE_WHERE} AND protocol_name IS NOT NULL"
        firms_sql = f"SELECT COUNT(DISTINCT firm_name) FROM findings WHERE {_BASE_WHERE} AND firm_name IS NOT NULL"

        async with self._pool.acquire() as conn:
            sev_rows = await conn.fetch(sev_sql)
            cat_rows = await conn.fetch(cat_sql)
            total = await conn.fetchval(total_sql)
            protocols = await conn.fetchval(protocols_sql)
            firms = await conn.fetchval(firms_sql)

        return {
            "total": total,
            "total_protocols": protocols,
            "total_firms": firms,
            "total_categories": len(cat_rows),
            "severity_distribution": {r["severity"]: r["count"] for r in sev_rows},
            "category_distribution": [
                {"category": r["vulnerability_category"], "count": r["count"]}
                for r in cat_rows
            ],
        }
