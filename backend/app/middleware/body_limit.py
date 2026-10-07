"""Global request-body size limit.

A pure ASGI middleware: it buffers the request body while counting bytes and
rejects the request with 413 as soon as the configured limit is exceeded, so an
oversized (or chunked, Content-Length-less) body is never handed to the
application. Buffering is bounded by the limit itself (1 MB by default), which is
what makes this safe.

Upload endpoints additionally enforce their own streaming cap while reading, so
the limit applies even if this middleware is disabled.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.errors import error_envelope

MAX_READ_CHUNKS = 100_000


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_bytes``."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max(1024, max_bytes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        declared = headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send)
            return

        body = bytearray()
        sent_disconnect = False
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                sent_disconnect = True
                break
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await self._reject(send)
                return
            more_body = bool(message.get("more_body", False))

        if sent_disconnect:
            await self._reject(send, reason="disconnected")
            return

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay, send)

    async def _reject(self, send: Send, *, reason: str = "too_large") -> None:
        """Answer with a 413 using raw ASGI messages (no scope juggling)."""
        body = json.dumps(
            error_envelope(
                "payload_too_large",
                f"The request body exceeds the {self.max_bytes // 1024} KB limit.",
            )
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})


#: Type alias exported for readability in main.py.
AsgiCallable = Callable[[Scope, Receive, Send], Awaitable[None]]
