import uuid
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from api.services.auth_service import AuthService

router = APIRouter()


def get_service(request: Request) -> AuthService:
    return AuthService(request.app.state.pool)


class NonceRequest(BaseModel):
    wallet_address: str


class VerifyRequest(BaseModel):
    wallet_address: str
    signature: str


class ProgressRequest(BaseModel):
    cluster_slug: str
    snippet_id: str
    score: int
    hints_used: int = 0


class SyncRequest(BaseModel):
    """Bulk sync localStorage progress to server."""
    cluster_progress: dict  # { slug: { attempted, solved, score_total, snippets_seen } }


@router.post("/nonce")
async def get_nonce(body: NonceRequest, service: AuthService = Depends(get_service)):
    """Get or create a nonce for wallet signature verification."""
    result = await service.get_or_create_nonce(body.wallet_address.lower())
    return result


@router.post("/verify")
async def verify_signature(body: VerifyRequest, service: AuthService = Depends(get_service)):
    """Verify wallet signature and return auth token."""
    result = await service.verify_and_login(
        body.wallet_address.lower(),
        body.signature,
    )
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid signature")
    return result


@router.get("/me")
async def get_me(request: Request, service: AuthService = Depends(get_service)):
    """Get current user profile from auth token."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    user = await service.get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.post("/progress")
async def record_progress(
    body: ProgressRequest,
    request: Request,
    service: AuthService = Depends(get_service),
):
    """Record a snippet score for the authenticated user."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="No token")
    user = await service.get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await service.record_progress(
        user_id=user["id"],
        cluster_slug=body.cluster_slug,
        snippet_id=body.snippet_id,
        score=body.score,
        hints_used=body.hints_used,
    )
    return result


@router.get("/progress")
async def get_progress(request: Request, service: AuthService = Depends(get_service)):
    """Get all progress for the authenticated user."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="No token")
    user = await service.get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    return await service.get_user_progress(user["id"])


@router.post("/sync")
async def sync_progress(
    body: SyncRequest,
    request: Request,
    service: AuthService = Depends(get_service),
):
    """Bulk sync localStorage progress to server (one-time migration)."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="No token")
    user = await service.get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    return await service.sync_local_progress(user["id"], body.cluster_progress)


@router.delete("/progress")
async def reset_progress(
    request: Request,
    service: AuthService = Depends(get_service),
):
    """Reset all progress for the authenticated user."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(status_code=401, detail="No token")
    user = await service.get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    return await service.reset_progress(user["id"])
