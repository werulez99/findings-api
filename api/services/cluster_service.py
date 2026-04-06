import json
import uuid
from typing import Any
import asyncpg


def _coerce_json(raw: Any) -> Any:
    if raw is None:
        return []
    if isinstance(raw, (list, dict)):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except Exception:
            return []
    return []


class ClusterService:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def list_clusters(self, *, section: str | None) -> list[dict]:
        conditions = []
        params: list[Any] = []

        if section:
            params.append(section)
            conditions.append(f"section = ${len(params)}")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sql = f"""
            SELECT id, name, slug, section, description, invariant_template,
                   finding_count, snippet_count, difficulty, created_at
            FROM pattern_clusters
            {where}
            ORDER BY finding_count DESC
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)

        return [
            {
                "id": str(r["id"]),
                "name": r["name"],
                "slug": r["slug"],
                "section": r["section"],
                "description": r["description"],
                "invariant_template": r["invariant_template"],
                "finding_count": r["finding_count"],
                "snippet_count": r["snippet_count"],
                "difficulty": r["difficulty"],
            }
            for r in rows
        ]

    async def get_cluster(self, slug: str) -> dict | None:
        sql = """
            SELECT id, name, slug, section, description, invariant_template,
                   finding_count, snippet_count, difficulty, created_at
            FROM pattern_clusters WHERE slug = $1
        """
        async with self._pool.acquire() as conn:
            r = await conn.fetchrow(sql, slug)
        if r is None:
            return None

        return {
            "id": str(r["id"]),
            "name": r["name"],
            "slug": r["slug"],
            "section": r["section"],
            "description": r["description"],
            "invariant_template": r["invariant_template"],
            "finding_count": r["finding_count"],
            "snippet_count": r["snippet_count"],
            "difficulty": r["difficulty"],
        }

    async def list_snippets(self, *, slug: str, difficulty: str | None) -> list[dict]:
        conditions = ["pc.slug = $1"]
        params: list[Any] = [slug]

        if difficulty:
            params.append(difficulty)
            conditions.append(f"ts.difficulty = ${len(params)}")

        where = "WHERE " + " AND ".join(conditions)
        sql = f"""
            SELECT ts.id, ts.difficulty, ts.title, ts.solidity_code,
                   ts.hints, ts.annotations, ts.invariant, ts.exploit_path,
                   ts.what_breaks, ts.why_missed, ts.attack_pattern,
                   ts.times_attempted, ts.times_solved
            FROM training_snippets ts
            JOIN pattern_clusters pc ON ts.cluster_id = pc.id
            {where}
            ORDER BY ts.difficulty, ts.created_at
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, *params)

        return [self._snippet_to_dict(r) for r in rows]

    async def random_snippet(
        self, *, slug: str, difficulty: str | None, exclude: list[uuid.UUID]
    ) -> dict | None:
        conditions = ["pc.slug = $1"]
        params: list[Any] = [slug]

        if difficulty:
            params.append(difficulty)
            conditions.append(f"ts.difficulty = ${len(params)}")

        if exclude:
            params.append(exclude)
            conditions.append(f"ts.id != ALL(${len(params)}::uuid[])")

        where = "WHERE " + " AND ".join(conditions)
        sql = f"""
            SELECT ts.id, ts.difficulty, ts.title, ts.solidity_code,
                   ts.hints, ts.annotations, ts.invariant, ts.exploit_path,
                   ts.what_breaks, ts.why_missed, ts.attack_pattern,
                   ts.times_attempted, ts.times_solved
            FROM training_snippets ts
            JOIN pattern_clusters pc ON ts.cluster_id = pc.id
            {where}
            ORDER BY random()
            LIMIT 1
        """
        async with self._pool.acquire() as conn:
            r = await conn.fetchrow(sql, *params)

        if r is None:
            return None
        return self._snippet_to_dict(r)

    async def cluster_findings(self, *, slug: str, limit: int) -> list[dict]:
        sql = """
            SELECT f.id, f.title, f.severity::text, f.protocol_name,
                   f.vulnerability_category, f.risk_score, f.short_summary
            FROM findings f
            JOIN finding_cluster_map fcm ON f.id = fcm.finding_id
            JOIN pattern_clusters pc ON fcm.cluster_id = pc.id
            WHERE pc.slug = $1
            ORDER BY f.risk_score DESC NULLS LAST
            LIMIT $2
        """
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(sql, slug, limit)

        return [
            {
                "id": str(r["id"]),
                "title": r["title"],
                "severity": r["severity"],
                "protocol_name": r["protocol_name"],
                "vulnerability_category": r["vulnerability_category"],
                "risk_score": r["risk_score"],
                "short_summary": r["short_summary"],
            }
            for r in rows
        ]

    def _snippet_to_dict(self, r: asyncpg.Record) -> dict:
        return {
            "id": str(r["id"]),
            "difficulty": r["difficulty"],
            "title": r["title"],
            "solidity_code": r["solidity_code"],
            "hints": _coerce_json(r["hints"]),
            "annotations": _coerce_json(r["annotations"]),
            "invariant": r["invariant"],
            "exploit_path": r["exploit_path"],
            "what_breaks": r["what_breaks"],
            "why_missed": r["why_missed"],
            "attack_pattern": r["attack_pattern"],
            "times_attempted": r["times_attempted"],
            "times_solved": r["times_solved"],
        }
