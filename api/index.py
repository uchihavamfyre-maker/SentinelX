"""Vercel entry point for the SentinelX FastAPI service."""
from pathlib import Path
import sys
from typing import Any, Awaitable, Callable

# The application package lives in src/ in this repository.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sentinelx.api import app as fastapi_app  # noqa: E402


class StripVercelFunctionPrefix:
    """Restore the original route after Vercel rewrites /path to /api/index/path."""

    def __init__(self, app: Any):
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope["type"] == "http":
            path = scope.get("path", "")
            prefix = "/api/index"
            if path == prefix or path.startswith(prefix + "/"):
                restored = path[len(prefix):] or "/"
                scope = dict(scope)
                scope["path"] = restored
                scope["raw_path"] = restored.encode("utf-8")
        await self.app(scope, receive, send)


app = StripVercelFunctionPrefix(fastapi_app)
