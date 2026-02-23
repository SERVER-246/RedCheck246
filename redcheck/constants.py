"""RedCheck246 — Immutable constants.

All values are hard caps.  Configuration fields may be LOWER than these
but are rejected by ``field_validator`` if set HIGHER.
"""

from __future__ import annotations

# ── Rate Limits ──────────────────────────────────────────────────
HTTP_RPS_DEFAULT: int = 10
HTTP_RPS_HARD_CAP: int = 50

TCP_CPS_DEFAULT: int = 5
TCP_CPS_HARD_CAP: int = 20

PAYLOAD_BATCH_SIZE_DEFAULT: int = 50
PAYLOAD_BATCH_SIZE_HARD: int = 200

OSINT_API_RATE_DEFAULT: int = 5
OSINT_API_RATE_HARD: int = 20

MAX_CONCURRENT_PLUGINS_DEFAULT: int = 3
MAX_CONCURRENT_PLUGINS_HARD: int = 10

MAX_CONCURRENT_TARGETS_DEFAULT: int = 3
MAX_CONCURRENT_TARGETS_HARD: int = 10

# ── Timeouts ─────────────────────────────────────────────────────
PER_REQUEST_TIMEOUT_DEFAULT: int = 10
PER_REQUEST_TIMEOUT_HARD: int = 30

PER_TARGET_TIMEOUT_DEFAULT: int = 60
PER_TARGET_TIMEOUT_HARD: int = 120

GLOBAL_SCAN_TIMEOUT_DEFAULT: int = 300
GLOBAL_SCAN_TIMEOUT_HARD: int = 600

# ── Activation (Argon2id) ───────────────────────────────────────
ARGON2_TIME: int = 3
ARGON2_MEMORY_KB: int = 65536
ARGON2_PARALLELISM: int = 4
ARGON2_HASHLEN: int = 32

ACTIVATION_MAX_ATTEMPTS: int = 5
ACTIVATION_LOCKOUT_SECONDS: int = 300
ACTIVATION_COOLDOWN_SECONDS: int = 2

# ── Audit ────────────────────────────────────────────────────────
AUDIT_IV_BYTES: int = 12
AUDIT_AAD: bytes = b"redcheck-audit-v1"
AUDIT_HASH_TRUNCATION: int = 16

# ── Packet Craft ─────────────────────────────────────────────────
PACKET_MAX_PAYLOAD_BYTES: int = 4096
PACKET_MAX_REPEAT: int = 3
PACKET_INTER_GAP_SECONDS: float = 1.0

# ── Evidence ─────────────────────────────────────────────────────
EVIDENCE_MAX_SAMPLE_BYTES: int = 256
EVIDENCE_RETENTION_HOURS_DEFAULT: int = 72
EVIDENCE_RETENTION_HOURS_PRODUCTION: int = 8760

# ── OSINT Cache ──────────────────────────────────────────────────
OSINT_CACHE_TTL_SECONDS: int = 3600
OSINT_CACHE_LRU_SIZE: int = 2000

# ── Typosquatting ────────────────────────────────────────────────
TYPOSQUAT_LEVENSHTEIN_THRESHOLD: int = 2

# ── Scope ────────────────────────────────────────────────────────
SCOPE_MAX_CIDR_EXPANSION: int = 256

# ── Crawler ──────────────────────────────────────────────────────
CRAWLER_MAX_PAGES_DEFAULT: int = 100
CRAWLER_MAX_DEPTH_DEFAULT: int = 5

# ── Attack Graph ─────────────────────────────────────────────────
ATTACK_GRAPH_MAX_NODES: int = 1000
ATTACK_GRAPH_MAX_EDGES: int = 5000

# Per-attacker-class graph constraints
ATTACK_GRAPH_AC1_MAX_DEPTH: int = 1
ATTACK_GRAPH_AC1_MAX_NODES: int = 50
ATTACK_GRAPH_AC2_MAX_DEPTH: int = 3
ATTACK_GRAPH_AC2_MAX_NODES: int = 200
ATTACK_GRAPH_AC3_MAX_DEPTH: int = 4
ATTACK_GRAPH_AC3_MAX_NODES: int = 500
ATTACK_GRAPH_AC4_MAX_DEPTH: int = 6
ATTACK_GRAPH_AC4_MAX_NODES: int = 1000

# ── Detection Validation ─────────────────────────────────────────
DETECTION_COVERAGE_THRESHOLD_PERCENT: float = 50.0
DETECTION_MARKER_DIGEST_LEN: int = 24
DETECTION_MAX_PROBE_COUNT: int = 20
DETECTION_LATENCY_POLL_TIMEOUT_CAP: int = 300
DETECTION_DEFAULT_EXPECTED_LATENCY_MS: float = 1000.0
DETECTION_SLA_PASS_THRESHOLD_PERCENT: float = 80.0

# ── Multi-Tenant Isolation ────────────────────────────────────────
TENANT_ID_MIN_LENGTH: int = 2
TENANT_ID_MAX_LENGTH: int = 64
TENANT_ID_PATTERN: str = r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}[a-zA-Z0-9]$"
TENANT_DIR_MODE: int = 0o700
TENANT_SUBDIRS: tuple[str, ...] = ("engagements", "evidence", "logs", "reports")

# ── RBAC ─────────────────────────────────────────────────────────
RBAC_DEFAULT_ROLE: str = "viewer"
RBAC_ACTIONS: tuple[str, ...] = (
    "read_reports",
    "run_passive",
    "run_active",
    "run_destructive",
    "manage_tenants",
    "export_evidence",
)

# ── Metrics ──────────────────────────────────────────────────────
METRICS_ROTATION_DAYS_DEFAULT: int = 1
METRICS_TABLE_NAME: str = "metrics_ts"
