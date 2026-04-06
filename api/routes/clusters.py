import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from api.services.cluster_service import ClusterService

router = APIRouter()


def get_service(request: Request) -> ClusterService:
    return ClusterService(request.app.state.pool)


@router.get("")
async def list_clusters(
    section: str | None = Query(default=None),
    service: ClusterService = Depends(get_service),
):
    """List all pattern clusters, optionally filtered by section."""
    return await service.list_clusters(section=section)


@router.get("/{slug}")
async def get_cluster(
    slug: str,
    service: ClusterService = Depends(get_service),
):
    """Get a single cluster by slug with its snippets."""
    cluster = await service.get_cluster(slug)
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


@router.get("/{slug}/snippets")
async def list_snippets(
    slug: str,
    difficulty: str | None = Query(default=None),
    service: ClusterService = Depends(get_service),
):
    """Get training snippets for a cluster."""
    return await service.list_snippets(slug=slug, difficulty=difficulty)


@router.get("/{slug}/snippets/random")
async def random_snippet(
    slug: str,
    difficulty: str | None = Query(default=None),
    exclude: list[uuid.UUID] | None = Query(default=None),
    service: ClusterService = Depends(get_service),
):
    """Get a random snippet from a cluster."""
    snippet = await service.random_snippet(slug=slug, difficulty=difficulty, exclude=exclude or [])
    if snippet is None:
        raise HTTPException(status_code=404, detail="No snippets available")
    return snippet


@router.get("/{slug}/findings")
async def cluster_findings(
    slug: str,
    limit: int = Query(default=5, ge=1, le=20),
    service: ClusterService = Depends(get_service),
):
    """Get sample real findings from a cluster."""
    return await service.cluster_findings(slug=slug, limit=limit)
