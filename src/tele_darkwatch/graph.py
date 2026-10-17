"""Graph-based entity resolution over the entity index.

Infostealer logs are profoundly messy: one infected device leaks corporate
AD credentials, autofill names, and personal browser cookies all at once.
This module stitches those fragments into an *infected profile asset* by
treating co-occurrence (two entities appearing in the same message) as an
edge in a lightweight in-memory graph — no Neo4j required.

The graph supports:
  * ``neighbors(identity)`` – direct links around an identity
  * ``cluster(seed, max_hops)`` – full connected component up to N hops
  * ``risk_score(identity)`` – heuristic blast-radius score used to flag
    employees whose personal accounts keep resurfacing in unrelated breaches
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Iterable, Optional

from tele_darkwatch.entities import extract_all
from tele_darkwatch.storage.message_store import MessageStore


def _key(etype: str, value: str) -> str:
    return f"{etype}:{value.lower()}"


class EntityGraph:
    """Co-occurrence graph built from stored messages + the entity index."""

    def __init__(self, store: MessageStore) -> None:
        self.store = store
        # node key -> {"type":..., "value":..., "seen": int}
        self.nodes: dict[str, dict] = {}
        # node key -> set of neighbour keys
        self.edges: dict[str, set[str]] = defaultdict(set)
        self._build()

    # ------------------------------------------------------------------ build
    def _build(self) -> None:
        # Seed nodes from the persisted entity index (covers sanitised or
        # pruned originals as long as the entity row survives).
        for row in self.store.entities.top(limit=100000):
            k = _key(row["type"], row["value"])
            self.nodes[k] = {
                "type": row["type"],
                "value": row["value"],
                "seen": row["seen_count"],
                "channels": row.get("channels", []),
            }
        # Edges from co-occurrence inside raw message text.
        for msg in self.store.recent(limit=5000):
            ents = {(e.type.value, e.value) for e in extract_all(msg.content)}
            keys = [_key(t, v) for t, v in ents]
            for a in keys:
                self.nodes.setdefault(a, {"type": a.split(":")[0],
                                          "value": a.split(":", 1)[1],
                                          "seen": 1, "channels": [msg.channel]})
            for i, a in enumerate(keys):
                for b in keys[i + 1:]:
                    if a != b:
                        self.edges[a].add(b)
                        self.edges[b].add(a)

    # ------------------------------------------------------------------ query
    def resolve(self, identity: str) -> Optional[str]:
        """Find the canonical node key for a bare identity string."""
        needle = identity.lower()
        exact = [k for k in self.nodes if self.nodes[k]["value"].lower() == needle]
        if exact:
            return exact[0]
        partial = [k for k in self.nodes if needle in k.lower()]
        return partial[0] if partial else None

    def neighbors(self, key: str) -> list[dict]:
        out = []
        for n in sorted(self.edges.get(key, ())):
            node = self.nodes.get(n, {"value": n})
            out.append({"key": n, **node})
        return out

    def cluster(self, seed: str, max_hops: int = 2) -> list[dict]:
        """BFS connected component around ``seed`` up to ``max_hops`` depth."""
        start = self.resolve(seed)
        if start is None:
            return []
        visited = {start}
        frontier = deque([(start, 0)])
        result = []
        while frontier:
            key, depth = frontier.popleft()
            node = self.nodes.get(key, {"value": key})
            result.append({"key": key, "hops": depth, **node})
            if depth >= max_hops:
                continue
            for nb in self.edges.get(key, ()):
                if nb not in visited:
                    visited.add(nb)
                    frontier.append((nb, depth + 1))
        return sorted(result, key=lambda r: (r["hops"], r["key"]))

    def risk_score(self, identity: str) -> dict:
        """Heuristic exposure score: breadth of cluster + sighting volume."""
        start = self.resolve(identity)
        if start is None:
            return {"identity": identity, "found": False, "score": 0}
        cluster = self.cluster(identity, max_hops=2)
        sightings = sum(c.get("seen", 1) for c in cluster)
        types = {c["type"] for c in cluster if "type" in c}
        channels: set[str] = set()
        for c in cluster:
            channels.update(c.get("channels") or [])
        score = len(cluster) + sightings // 2 + 3 * len(types)
        if "email" in types and len(types) >= 3:
            score += 5  # identity grafting across vectors => higher blast radius
        return {
            "identity": identity,
            "found": True,
            "score": score,
            "cluster_size": len(cluster),
            "entity_types": sorted(types),
            "channels": sorted(channels),
        }


def build_graph(store: MessageStore) -> EntityGraph:
    return EntityGraph(store)
