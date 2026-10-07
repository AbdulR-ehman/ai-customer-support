"""API routers.

Each router is mounted by :mod:`app.main`; importing this package does not pull
in the routers themselves (they are imported explicitly) to keep import order
predictable and avoid circular imports through dependencies.
"""

from __future__ import annotations

__all__ = ["admin", "auth", "chat", "health"]
