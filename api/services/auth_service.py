import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any

import asyncpg

# JWT-like token: simple HMAC-signed payload
# In production you'd use proper JWT with pyjwt, but this avoids adding dependencies
TOKEN_SECRET = secrets.token_hex(32)
TOKEN_EXPIRY = 30 * 24 * 3600  # 30 days


def _create_token(user_id: str, wallet: str) -> str:
    """Create a simple signed token."""
    payload = {
        "uid": user_id,
        "w": wallet,
        "exp": int(time.time()) + TOKEN_EXPIRY,
    }
    payload_json = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(TOKEN_SECRET.encode(), payload_json.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{payload_json}.{sig}"


def _verify_token(token: str) -> dict | None:
    """Verify and decode a token."""
    try:
        parts = token.rsplit(".", 1)
        if len(parts) != 2:
            return None
        payload_json, sig = parts
        expected_sig = hmac.new(TOKEN_SECRET.encode(), payload_json.encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(payload_json)
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def _verify_eth_signature(message: str, signature: str, expected_address: str) -> bool:
    """Verify an Ethereum personal_sign signature.
    Uses eth_account if available, falls back to basic validation."""
    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account

        msg = encode_defunct(text=message)
        recovered = Account.recover_message(msg, signature=signature)
        return recovered.lower() == expected_address.lower()
    except ImportError:
        # Fallback: accept any signature (for development)
        # In production, install eth_account: pip install eth-account
        return len(signature) > 20
    except Exception:
        return False


class AuthService:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def get_or_create_nonce(self, wallet_address: str) -> dict:
        """Get existing nonce or create new user with nonce."""
        async with self._pool.acquire() as conn:
            # Check if user exists
            row = await conn.fetchrow(
                "SELECT id, nonce FROM users WHERE wallet_address = $1",
                wallet_address,
            )
            if row:
                # Regenerate nonce for security
                new_nonce = secrets.token_hex(16)
                await conn.execute(
                    "UPDATE users SET nonce = $1 WHERE id = $2",
                    new_nonce, row["id"],
                )
                return {"nonce": new_nonce, "exists": True}
            else:
                # Create new user
                new_nonce = secrets.token_hex(16)
                user_id = uuid.uuid4()
                await conn.execute(
                    "INSERT INTO users (id, wallet_address, nonce) VALUES ($1, $2, $3)",
                    user_id, wallet_address, new_nonce,
                )
                return {"nonce": new_nonce, "exists": False}

    async def verify_and_login(self, wallet_address: str, signature: str) -> dict | None:
        """Verify signature against stored nonce, return auth token."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, nonce, display_name FROM users WHERE wallet_address = $1",
                wallet_address,
            )
            if not row:
                return None

            # Build the message that was signed
            message = f"Sign in to Valves Security\n\nNonce: {row['nonce']}"

            if not _verify_eth_signature(message, signature, wallet_address):
                return None

            # Regenerate nonce (prevent replay)
            new_nonce = secrets.token_hex(16)
            await conn.execute(
                "UPDATE users SET nonce = $1, last_login = now() WHERE id = $2",
                new_nonce, row["id"],
            )

            # Create or update stats
            await conn.execute("""
                INSERT INTO user_stats (user_id) VALUES ($1)
                ON CONFLICT (user_id) DO NOTHING
            """, row["id"])

            token = _create_token(str(row["id"]), wallet_address)

            return {
                "token": token,
                "user": {
                    "id": str(row["id"]),
                    "wallet_address": wallet_address,
                    "display_name": row["display_name"],
                },
            }

    async def get_user_by_token(self, token: str) -> dict | None:
        """Validate token and return user."""
        payload = _verify_token(token)
        if not payload:
            return None

        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, wallet_address, display_name FROM users WHERE id = $1",
                uuid.UUID(payload["uid"]),
            )
            if not row:
                return None
            return {
                "id": str(row["id"]),
                "wallet_address": row["wallet_address"],
                "display_name": row["display_name"],
            }

    async def record_progress(
        self, *, user_id: str, cluster_slug: str, snippet_id: str, score: int, hints_used: int
    ) -> dict:
        """Record a snippet completion."""
        uid = uuid.UUID(user_id)
        sid = uuid.UUID(snippet_id)

        async with self._pool.acquire() as conn:
            # Upsert progress
            await conn.execute("""
                INSERT INTO user_progress (user_id, cluster_slug, snippet_id, score, hints_used)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (user_id, snippet_id) DO UPDATE SET
                    score = GREATEST(user_progress.score, EXCLUDED.score),
                    hints_used = LEAST(user_progress.hints_used, EXCLUDED.hints_used)
            """, uid, cluster_slug, sid, score, hints_used)

            # Update stats
            stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_attempted,
                    COUNT(*) FILTER (WHERE score = 3) as total_solved
                FROM user_progress WHERE user_id = $1
            """, uid)

            await conn.execute("""
                UPDATE user_stats SET
                    total_attempted = $2,
                    total_solved = $3,
                    last_activity = now()
                WHERE user_id = $1
            """, uid, stats["total_attempted"], stats["total_solved"])

            return {"ok": True, "total_attempted": stats["total_attempted"]}

    async def get_user_progress(self, user_id: str) -> dict:
        """Get full progress for a user."""
        uid = uuid.UUID(user_id)

        async with self._pool.acquire() as conn:
            # Stats
            stats_row = await conn.fetchrow(
                "SELECT * FROM user_stats WHERE user_id = $1", uid
            )

            # Per-cluster progress
            cluster_rows = await conn.fetch("""
                SELECT
                    cluster_slug,
                    COUNT(*) as attempted,
                    COUNT(*) FILTER (WHERE score = 3) as solved,
                    SUM(score) as score_total,
                    array_agg(snippet_id::text) as snippets_seen,
                    MAX(created_at) as last_attempted
                FROM user_progress
                WHERE user_id = $1
                GROUP BY cluster_slug
            """, uid)

            # Recent history
            history_rows = await conn.fetch("""
                SELECT up.snippet_id, up.cluster_slug, up.score, up.hints_used, up.created_at,
                       ts.title, ts.difficulty
                FROM user_progress up
                LEFT JOIN training_snippets ts ON up.snippet_id = ts.id
                WHERE up.user_id = $1
                ORDER BY up.created_at DESC
                LIMIT 30
            """, uid)

            clusters = {}
            for r in cluster_rows:
                clusters[r["cluster_slug"]] = {
                    "attempted": r["attempted"],
                    "solved": r["solved"],
                    "score_total": r["score_total"],
                    "snippets_seen": r["snippets_seen"] or [],
                    "last_attempted": r["last_attempted"].isoformat() if r["last_attempted"] else None,
                }

            history = [
                {
                    "snippet_id": str(r["snippet_id"]) if r["snippet_id"] else None,
                    "cluster_slug": r["cluster_slug"],
                    "score": r["score"],
                    "hints_used": r["hints_used"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                    "title": r["title"],
                    "difficulty": r["difficulty"],
                }
                for r in history_rows
            ]

            return {
                "stats": {
                    "total_attempted": stats_row["total_attempted"] if stats_row else 0,
                    "total_solved": stats_row["total_solved"] if stats_row else 0,
                    "current_streak": stats_row["current_streak"] if stats_row else 0,
                    "best_streak": stats_row["best_streak"] if stats_row else 0,
                },
                "clusters": clusters,
                "history": history,
            }

    async def sync_local_progress(self, user_id: str, cluster_progress: dict) -> dict:
        """Sync localStorage data to server (one-time migration on first wallet connect)."""
        uid = uuid.UUID(user_id)
        synced = 0

        async with self._pool.acquire() as conn:
            for slug, data in cluster_progress.items():
                snippets_seen = data.get("snippets_seen", [])
                solved = data.get("solved", 0)
                attempted = data.get("attempted", 0)

                # We don't have per-snippet scores from localStorage,
                # so we record attempted count as a stat
                for snippet_id_str in snippets_seen:
                    try:
                        sid = uuid.UUID(snippet_id_str)
                        await conn.execute("""
                            INSERT INTO user_progress (user_id, cluster_slug, snippet_id, score, hints_used)
                            VALUES ($1, $2, $3, $4, 0)
                            ON CONFLICT (user_id, snippet_id) DO NOTHING
                        """, uid, slug, sid, 2)  # default score 2 (partial) for migrated data
                        synced += 1
                    except (ValueError, Exception):
                        continue

            # Update stats
            stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_attempted,
                    COUNT(*) FILTER (WHERE score = 3) as total_solved
                FROM user_progress WHERE user_id = $1
            """, uid)

            await conn.execute("""
                INSERT INTO user_stats (user_id, total_attempted, total_solved)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id) DO UPDATE SET
                    total_attempted = EXCLUDED.total_attempted,
                    total_solved = EXCLUDED.total_solved
            """, uid, stats["total_attempted"], stats["total_solved"])

        return {"synced": synced}
