"""RedCheck246 — Topology Engine.

Builds a host/service topology graph from scan results.
Uses union-find clustering to group hosts by subnet and reverse-DNS.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class HostNode:
    """A single discovered host."""

    address: str
    hostname: str | None = None
    os_guess: str | None = None
    os_confidence: float = 0.0
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    ttl: int | None = None
    banner: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "os_confidence": self.os_confidence,
            "open_ports": self.open_ports,
            "services": self.services,
            "ttl": self.ttl,
            "banner": self.banner,
        }


@dataclass
class SubnetCluster:
    """A cluster of hosts in the same logical subnet."""

    network: str
    hosts: list[HostNode] = field(default_factory=list)
    gateway: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "host_count": len(self.hosts),
            "hosts": [h.to_dict() for h in self.hosts],
            "gateway": self.gateway,
        }


# ---------------------------------------------------------------------------
# Union-Find for subnet clustering
# ---------------------------------------------------------------------------


class _UnionFind:
    """Simple union-find (disjoint set) data structure."""

    def __init__(self) -> None:
        self._parent: dict[str, str] = {}
        self._rank: dict[str, int] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            self._rank[x] = 0
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]  # path compression
            x = self._parent[x]
        return x

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

    def groups(self) -> dict[str, list[str]]:
        """Return groups keyed by root representative."""
        result: dict[str, list[str]] = {}
        for member in self._parent:
            root = self.find(member)
            result.setdefault(root, []).append(member)
        return result


# ---------------------------------------------------------------------------
# Topology Engine
# ---------------------------------------------------------------------------


class TopologyEngine:
    """Build network topology from discovered hosts and services."""

    def __init__(self) -> None:
        self._hosts: dict[str, HostNode] = {}

    def add_host(self, node: HostNode) -> None:
        """Register a discovered host."""
        self._hosts[node.address] = node

    def add_hosts(self, nodes: list[HostNode]) -> None:
        """Register multiple discovered hosts."""
        for node in nodes:
            self.add_host(node)

    @property
    def host_count(self) -> int:
        return len(self._hosts)

    def get_host(self, address: str) -> HostNode | None:
        return self._hosts.get(address)

    def infer_subnets(self, prefix_len: int = 24) -> list[SubnetCluster]:
        """Cluster hosts into subnets using IP prefix grouping.

        Args:
            prefix_len: CIDR prefix length for grouping (default /24).

        Returns:
            List of ``SubnetCluster`` objects, each containing hosts in
            the same subnet.
        """
        uf = _UnionFind()
        ip_hosts: dict[str, HostNode] = {}

        for addr, node in self._hosts.items():
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            ip_hosts[addr] = node
            # Map to network prefix
            if isinstance(ip, ipaddress.IPv4Address):
                network = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
            else:
                network = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
            net_key = str(network)
            uf.find(addr)  # ensure registered
            # Union all hosts in the same network prefix
            uf.union(addr, net_key)

        # Build clusters
        clusters: list[SubnetCluster] = []
        seen_roots: set[str] = set()

        for addr, node in ip_hosts.items():
            root = uf.find(addr)
            if root in seen_roots:
                # Add to existing cluster
                for cl in clusters:
                    if cl.network == root or any(h.address == addr for h in cl.hosts):
                        continue
                    existing_root = uf.find(cl.hosts[0].address) if cl.hosts else None
                    if existing_root == root:
                        cl.hosts.append(node)
                        break
            else:
                seen_roots.add(root)
                try:
                    ip = ipaddress.ip_address(addr)
                    net = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
                    net_str = str(net)
                except ValueError:
                    net_str = root
                clusters.append(SubnetCluster(network=net_str, hosts=[node]))

        # Merge hosts that share the same root but ended up in different
        # SubnetCluster objects  (defensive merge pass).
        merged: dict[str, SubnetCluster] = {}
        for cl in clusters:
            for h in cl.hosts:
                root = uf.find(h.address)
                if root not in merged:
                    merged[root] = SubnetCluster(network=cl.network, hosts=[])
                if h not in merged[root].hosts:
                    merged[root].hosts.append(h)

        return list(merged.values())

    def infer_os(self, address: str) -> tuple[str, float]:
        """Heuristic OS fingerprinting from TTL, banner, and window size.

        Read-only — examines only pre-collected data.

        Returns:
            ``(os_name, confidence)`` where confidence is in ``[0, 1]``.
        """
        node = self._hosts.get(address)
        if not node:
            return "unknown", 0.0

        os_name = "unknown"
        confidence = 0.0

        # TTL heuristic
        if node.ttl is not None:
            if node.ttl <= 64:
                os_name = "Linux/Unix"
                confidence = 0.4
            elif node.ttl <= 128:
                os_name = "Windows"
                confidence = 0.4
            else:
                os_name = "Network Device"
                confidence = 0.3

        # Banner heuristic (additive confidence)
        if node.banner:
            banner_lower = node.banner.lower()
            if "ubuntu" in banner_lower or "debian" in banner_lower:
                os_name = "Linux (Debian/Ubuntu)"
                confidence = min(1.0, confidence + 0.4)
            elif "centos" in banner_lower or "red hat" in banner_lower:
                os_name = "Linux (RHEL/CentOS)"
                confidence = min(1.0, confidence + 0.4)
            elif "windows" in banner_lower or "iis" in banner_lower:
                os_name = "Windows Server"
                confidence = min(1.0, confidence + 0.4)
            elif "nginx" in banner_lower or "apache" in banner_lower:
                os_name = os_name if os_name != "unknown" else "Linux/Unix"
                confidence = min(1.0, confidence + 0.2)

        node.os_guess = os_name
        node.os_confidence = confidence
        return os_name, confidence

    def to_dict(self) -> dict[str, Any]:
        """Serialize the entire topology."""
        subnets = self.infer_subnets()
        return {
            "total_hosts": self.host_count,
            "subnets": [s.to_dict() for s in subnets],
            "hosts": {addr: n.to_dict() for addr, n in self._hosts.items()},
        }
