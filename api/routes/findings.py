import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from api.models import FindingDetail, FindingsPage
from api.services.findings_service import FindingsService, SortField

router = APIRouter()

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def get_service(request: Request) -> FindingsService:
    return FindingsService(request.app.state.pool)


@router.get("", response_model=FindingsPage)
async def list_findings(
    severity: list[str] | None = Query(default=None),
    protocol_name: str | None = Query(default=None, max_length=255),
    tags: list[str] | None = Query(default=None),
    search: str | None = Query(default=None, max_length=500),
    sort: SortField = Query(default=SortField.newest),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=100_000),
    service: FindingsService = Depends(get_service),
) -> FindingsPage:
    normalised_severity: list[str] | None = None
    if severity is not None:
        normalised_severity = [s.upper() for s in severity if s.upper() in _VALID_SEVERITIES]
        if not normalised_severity:
            return FindingsPage(total=0, limit=limit, offset=offset, items=[])
    normalised_search = search.strip() if search and search.strip() else None
    return await service.list_findings(
        severity=normalised_severity,
        protocol_name=protocol_name,
        tags=tags,
        search=normalised_search,
        sort=sort,
        limit=limit,
        offset=offset,
    )


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: uuid.UUID,
    service: FindingsService = Depends(get_service),
) -> FindingDetail:
    finding = await service.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
