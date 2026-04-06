from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.db import close_pool, create_pool
from api.routes.findings import router as findings_router
from api.routes.training import router as training_router
from api.routes.clusters import router as clusters_router
from api.routes.auth import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await create_pool()
    yield
    await close_pool(app.state.pool)


app = FastAPI(title="Findings API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(findings_router, prefix="/findings", tags=["findings"])
app.include_router(training_router, prefix="/training", tags=["training"])
app.include_router(clusters_router, prefix="/clusters", tags=["clusters"])
app.include_router(auth_router, prefix="/auth", tags=["auth"])
