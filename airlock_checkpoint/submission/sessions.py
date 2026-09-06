"""Per-visitor isolation for the public demo.

The single-operator demo hands one process to one trusted person: one operator
token, one signing key, one evidence log. Exposing that unchanged would give
every visitor the same credential and the same audit trail.

Here each visitor gets a :class:`~.core.Runtime` of their own, holding their own
run id, signing key, agent credentials and assignments. The two expensive pieces
are shared: one SQLite evidence store and one loopback mock bank. Both are
filtered by ``run_id``, so a visitor can only ever read back their own rows.

Sessions live in memory. A process restart drops them, which is correct for a
demo: the front end asks for a new session and the walkthrough starts again.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .core import EvidenceStore, MockBank, Runtime

#: A visitor idle this long is collected.
IDLE_TTL = 30 * 60
#: A session is collected this long after creation regardless of activity.
ABSOLUTE_TTL = 2 * 60 * 60
#: Refuse new sessions beyond this, rather than letting one box be exhausted.
MAX_SESSIONS = 200
#: Stop accepting work when the shared store passes this many rows.
MAX_EVENTS = 200_000


@dataclass
class Session:
    id: str
    runtime: Runtime
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def expired(self, now: float, idle_ttl: float, absolute_ttl: float) -> bool:
        return (now - self.last_seen) > idle_ttl or (now - self.created_at) > absolute_ttl


class SessionExhaustedError(RuntimeError):
    """Raised when the demo is at capacity. Surfaced as 503, never as a crash."""


class SessionManager:
    """Owns the shared store and bank, and one Runtime per visitor."""

    def __init__(
        self,
        store: EvidenceStore,
        bank: MockBank,
        *,
        idle_ttl: float = IDLE_TTL,
        absolute_ttl: float = ABSOLUTE_TTL,
        max_sessions: int = MAX_SESSIONS,
        max_events: int = MAX_EVENTS,
    ) -> None:
        self.store = store
        self.bank = bank
        self.idle_ttl = idle_ttl
        self.absolute_ttl = absolute_ttl
        self.max_sessions = max_sessions
        self.max_events = max_events
        self._sessions: dict[str, Session] = {}
        self._lock = threading.RLock()

    # -- lifecycle ---------------------------------------------------------

    def create(self) -> Session:
        with self._lock:
            self.sweep()
            if len(self._sessions) >= self.max_sessions:
                raise SessionExhaustedError("demo at capacity")
            if self.store.count() >= self.max_events:
                raise SessionExhaustedError("evidence store full")
            sid = secrets.token_urlsafe(32)
            session = Session(sid, Runtime(store=self.store, bank=self.bank))
            self._sessions[sid] = session
            return session

    def get(self, sid: str | None) -> Session | None:
        """Return a live session and mark it seen. Expired or unknown ids give None."""
        if not sid:
            return None
        with self._lock:
            session = self._sessions.get(sid)
            if session is None:
                return None
            now = time.time()
            if session.expired(now, self.idle_ttl, self.absolute_ttl):
                self._discard([session])
                return None
            session.last_seen = now
            return session

    def drop(self, sid: str) -> None:
        with self._lock:
            session = self._sessions.get(sid)
            if session is not None:
                self._discard([session])

    def sweep(self) -> int:
        """Collect expired sessions and reclaim their storage. Returns how many went."""
        now = time.time()
        with self._lock:
            dead = [
                s
                for s in self._sessions.values()
                if s.expired(now, self.idle_ttl, self.absolute_ttl)
            ]
            self._discard(dead)
            return len(dead)

    def _discard(self, sessions: list[Session]) -> None:
        """Caller holds the lock."""
        if not sessions:
            return
        for session in sessions:
            self._sessions.pop(session.id, None)
        self.store.drop_runs({s.runtime.run_id for s in sessions})
        self.bank.prune({s.runtime.run_id for s in self._sessions.values()})

    def close(self) -> None:
        with self._lock:
            self._sessions.clear()
        self.bank.close()
        self.store.close()

    # -- introspection -----------------------------------------------------

    @property
    def live(self) -> int:
        with self._lock:
            return len(self._sessions)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "sessions": len(self._sessions),
                "capacity": self.max_sessions,
                "events": self.store.count(),
                "event_capacity": self.max_events,
            }


class RateLimiter:
    """Fixed-window counter keyed by caller. Enough for a demo box, not a WAF."""

    def __init__(self, limit: int, window: float) -> None:
        self.limit = limit
        self.window = window
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            if len(self._hits) > 10_000:  # bound the keyspace against spoofed clients
                self._hits = {
                    k: v for k, v in self._hits.items() if v and (now - v[-1]) < self.window
                }
            hits = [t for t in self._hits.get(key, []) if (now - t) < self.window]
            if len(hits) >= self.limit:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True
