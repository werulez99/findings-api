import uuid
from fastapi import APIRouter, Depends, Query, Request
from api.services.training_service import TrainingService

router = APIRouter()


def get_service(request: Request) -> TrainingService:
    return TrainingService(request.app.state.pool)


@router.get("/categories")
async def list_categories(
    service: TrainingService = Depends(get_service),
):
    """Return all vulnerability categories with finding counts."""
    return await service.list_categories()


@router.get("/random")
async def random_finding(
    severity: str | None = Query(default=None),
    category: str | None = Query(default=None),
    exclude: list[uuid.UUID] | None = Query(default=None),
    service: TrainingService = Depends(get_service),
):
    """Return a single random finding for challenge mode."""
    return await service.random_finding(
        severity=severity,
        category=category,
        exclude=exclude or [],
    )


@router.get("/drill")
async def variant_drill(
    category: str = Query(..., min_length=1),
    count: int = Query(default=5, ge=3, le=8),
    service: TrainingService = Depends(get_service),
):
    """
    Return a set of findings for variant drill mode.
    All from the same category. Includes a mix of severities.
    """
    return await service.variant_drill(category=category, count=count)


@router.get("/stats")
async def category_stats(
    service: TrainingService = Depends(get_service),
):
    """Return severity distribution and category breakdown for the whole DB."""
    return await service.db_stats()
