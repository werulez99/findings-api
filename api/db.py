import os
import asyncpg


async def create_pool() -> asyncpg.Pool:
    dsn = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
    pool = await asyncpg.create_pool(dsn=dsn, min_size=2, max_size=10, command_timeout=30)
    return pool


async def close_pool(pool: asyncpg.Pool) -> None:
    await pool.close()
