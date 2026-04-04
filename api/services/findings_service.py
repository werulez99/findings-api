import asyncio
import json
import uuid
from enum import Enum
from typing import Any
import asyncpg
from api.models import FindingDetail, FindingsPage, FindingSummary


class SortField(str, Enum):
    newest = "newest"
    severity = "severity"
    risk_score = "risk_score"


_SUMMARY_COLS = """
    id, title, severity::text, protocol_name, firm_name,
    vulnerability_category, attack_vector, tags, risk_score,
    short_summary, created_at
"""

_DETAIL_COLS = """
    id, title, description, severity::text, protocol_name, firm_name,
    vulnerability_category, attack_vector, tags, risk_score,
    short_summary, enrichment_status::text, created_at
"""

_ORDER_CLAUSES = {
    SortField.newest: "ORDER BY created_at DESC",
    SortField.severity: "ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END ASC, created_at DESC",
    SortField.risk_score: "ORDER BY risk_score DESC NULLS LAST, created_at DESC",
}

_BASE_CONDITIONS = ["enrichment_status = 'ENRICHED'", "visibility = 'PUBLIC'"]

_TSVECTOR_EXPR = "to_tsvector('english', coalesce(title,'') || ' ' || coalesce(description,'') || ' ' || coalesce(short_summary,''))"


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


def _to_summary(r: asyncpg.Record) -> FindingSummary:
    return FindingSummary(
        id=r["id"], title=r["title"], severity=r["severity"],
        protocol_name=r["protocol_name"], firm_name=r["firm_name"],
        vulnerability_category=r["vulnerability_category"],
        attack_vector=r["attack_vector"], tags=_coerce_tags(r["tags"]),
        risk_score=r["risk_score"], short_summary=r["short_summary"],
        created_at=r["created_at"],
    )


def _to_detail(r: asyncpg.Record) -> FindingDetail:
    return FindingDetail(
        id=r["id"], title=r["title"], description=r["description"],
        severity=r["severity"], protocol_name=r["protocol_name"],
        firm_name=r["firm_name"],
        vulnerability_category=r["vulnerability_category"],
        attack_vector=r["attack_vector"], tags=_coerce_tags(r["tags"]),
        risk_score=r["risk_score"], short_summary=r["short_summary"],
        enrichment_status=r["enrichment_status"], created_at=r["created_at"],
    )


def _build_where(severity, protocol_name, tags, search):
    conditions = list(_BASE_CONDITIONS)
    params: list[Any] = []
    search_param_index = None

    if severity:
        placeholders = ", ".join(f"${len(params)+1+i}" for i in range(len(severity)))
        conditions.append(f"severity = ANY(ARRAY[{placeholders}]::severity_level[])")
        params.extend(severity)

    if protocol_name:
        params.append(f"%{protocol_name}%")
        conditions.append(f"protocol_name ILIKE ${len(params)}")

    if tags:
        params.append(tags)
        conditions.append(f"tags ?| ${len(params)}::text[]")

    if search:
        params.append(search)
        search_param_index = len(params)
        conditions.append(f"{_TSVECTOR_EXPR} @@ plainto_tsquery('english', ${search_param_index})")

    return "WHERE " + " AND ".join(conditions), params, search_param_index


def _compose_sql(cols, where, sort, search, search_param_index, limit_ph, offset_ph):
    if search and search_param_index:
        rank = f"ts_rank({_TSVECTOR_EXPR}, plainto_tsquery('english', ${search_param_index}))"
        return f"SELECT {cols}, {rank} AS _rank FROM findings {where} ORDER BY _rank DESC, created_at DESC LIMIT ${limit_ph} OFFSET ${offset_ph}"
    return f"SELECT {cols} FROM findings {where} {_ORDER_CLAUSES[sort]} LIMIT ${limit_ph} OFFSET ${offset_ph}"


class FindingsService:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def list_findings(self, *, severity, protocol_name, tags, search, sort, limit, offset) -> FindingsPage:
        where, base_params, search_param_index = _build_where(severity, protocol_name, tags, search)
        count_sql = f"SELECT COUNT(*) FROM findings {where}"
        limit_ph = len(base_params) + 1
        offset_ph = len(base_params) + 2
        data_sql = _compose_sql(_SUMMARY_COLS, where, sort, search, search_param_index, limit_ph, offset_ph)
        data_params = [*base_params, limit, offset]
        async with self._pool.acquire() as conn:
            total = await conn.fetchval(count_sql, *base_params)
            rows = await conn.fetch(data_sql, *data_params)
        return FindingsPage(total=int(total or 0), limit=limit, offset=offset, items=[_to_summary(r) for r in rows])

    async def get_finding(self, finding_id: uuid.UUID) -> FindingDetail | None:
        sql = f"SELECT {_DETAIL_COLS} FROM findings WHERE id = $1 AND visibility = 'PUBLIC'"
        async with self._pool.acquire() as conn:
            record = await conn.fetchrow(sql, finding_id)
        return None if record is None else _to_detail(record)
