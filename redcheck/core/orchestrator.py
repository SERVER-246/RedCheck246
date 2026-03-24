"""RedCheck246 — Orchestrator.

Central execution coordinator.  Manages engagement lifecycle, plugin
dispatch, and ensures all policy gates are enforced (Spec 1).

The orchestrator uses the canonical Pydantic ``EngagementContext`` from
``redcheck.models`` as the single source of truth.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from redcheck.core.audit import get_audit_logger
from redcheck.core.contract_validator import validate_contract
from redcheck.core.enrichment import enrich_plugin_result
from redcheck.core.evidence_store import EvidenceStore
from redcheck.core.fake_metric_detector import detect_fake_metrics
from redcheck.core.policy_engine import get_policy_engine
from redcheck.exceptions import (
    ActivationError,
    IsolationError,
    OffensiveControlError,
    PluginError,
    PluginNotFoundError,
    PolicyDeniedException,
    RoEValidationError,
    ScanTimeoutError,
)
from redcheck.models import EngagementContext, OffensiveControls, PluginCapability, RuntimeMode
from redcheck.plugins.base_plugin import PluginRegistry, PluginResult
from redcheck.security.crypto import CryptoEngine

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Capability × RuntimeMode enforcement matrix
# ---------------------------------------------------------------------------

_CAPABILITY_MODE_MATRIX: dict[RuntimeMode, dict[PluginCapability, bool]] = {
    RuntimeMode.DEV: {
        PluginCapability.PASSIVE: True,
        PluginCapability.ACTIVE: False,
        PluginCapability.DESTRUCTIVE: False,
    },
    RuntimeMode.CI: {
        PluginCapability.PASSIVE: True,
        PluginCapability.ACTIVE: False,
        PluginCapability.DESTRUCTIVE: False,
    },
    RuntimeMode.STAGING: {
        PluginCapability.PASSIVE: True,
        PluginCapability.ACTIVE: True,
        PluginCapability.DESTRUCTIVE: False,
    },
    RuntimeMode.PRODUCTION: {
        PluginCapability.PASSIVE: True,
        PluginCapability.ACTIVE: True,
        PluginCapability.DESTRUCTIVE: True,
    },
    RuntimeMode.RESEARCH: {
        PluginCapability.PASSIVE: True,
        PluginCapability.ACTIVE: True,
        PluginCapability.DESTRUCTIVE: False,
    },
    RuntimeMode.TEST: {
        PluginCapability.PASSIVE: True,
        PluginCapability.ACTIVE: True,
        PluginCapability.DESTRUCTIVE: True,
    },
}


def _is_capability_allowed(mode: RuntimeMode, capability: PluginCapability) -> bool:
    """Check the RuntimeMode × PluginCapability matrix."""
    return _CAPABILITY_MODE_MATRIX.get(mode, {}).get(capability, False)


class Orchestrator:
    """Central orchestrator for RedCheck engagements."""

    def __init__(self, *, signature_verifier: Any | None = None) -> None:
        self.policy = get_policy_engine()
        self.audit = get_audit_logger()
        self._current_engagement: EngagementContext | None = None
        self._signature_verifier = signature_verifier
        self._evidence_store: EvidenceStore | None = None
        self._trusted_plugin_hashes: dict[str, str] | None = None

    @property
    def current_engagement(self) -> EngagementContext | None:
        return self._current_engagement

    def load_engagement(self, roe_path: str | Path) -> _LegacyEngagementAdapter:
        """Load and validate an engagement from its RoE file.

        Returns a legacy-compatible adapter that provides ``to_dict()``
        and direct attribute access for backward compatibility.

        Raises ``PolicyDeniedException`` if the RoE is invalid.
        """
        valid, message, roe_data = self.policy.validate_roe(
            roe_path, verifier=self._signature_verifier
        )

        if not valid:
            log.error("engagement_load_failed", reason=message)
            self.audit.log(action="ENGAGEMENT_LOAD_FAILED", details=message, level="ERROR")
            raise PolicyDeniedException("orchestrator", message)

        ctx = _build_engagement_from_roe(roe_data, str(roe_path))
        self._current_engagement = ctx

        # Initialize evidence store from RoE path
        if ctx.roe_path:
            evidence_dir = Path(ctx.roe_path).resolve().parent / "evidence"
            self._evidence_store = EvidenceStore(evidence_dir)
            log.debug("evidence_store_initialized", path=str(evidence_dir))

        log.info(
            "engagement_loaded",
            engagement_id=ctx.engagement_id,
            authorizer=ctx.authorizer,
        )
        self.audit.log_engagement_action(
            action="ENGAGEMENT_LOADED",
            engagement_id=ctx.engagement_id,
            details=f"RoE validated, authorizer: {ctx.authorizer}",
        )
        return _LegacyEngagementAdapter(ctx)

    def activate(self, code: str) -> bool:
        """Activate the current engagement with the given activation code."""
        if not self._current_engagement:
            log.warning("activation_failed", reason="no_engagement")
            self.audit.log(action="ACTIVATION_FAILED", details="No engagement loaded", level="WARN")
            return False

        valid = self.policy.validate_activation_code(code)
        if valid:
            self._current_engagement = self._current_engagement.model_copy(
                update={"activation_verified": True}
            )
            log.info("engagement_activated", engagement_id=self._current_engagement.engagement_id)
            self.audit.log_engagement_action(
                action="ENGAGEMENT_ACTIVATED",
                engagement_id=self._current_engagement.engagement_id,
            )
        return valid

    def run_plugin(
        self,
        plugin_name: str,
        dry_run: bool = False,
        extra_context: dict[str, Any] | None = None,
    ) -> PluginResult:
        """Execute a plugin within the current engagement context (sync)."""
        plugin = PluginRegistry.get_instance(plugin_name)
        if plugin is None:
            suggestions = PluginRegistry.suggest(plugin_name)
            hint = ""
            if suggestions:
                hint = f" Did you mean: {', '.join(suggestions)}?"
            return PluginResult(
                plugin_name=plugin_name,
                success=False,
                errors=[f"Plugin '{plugin_name}' not found in registry.{hint}"],
            )

        context: dict[str, Any] = {}
        if self._current_engagement:
            context = self._current_engagement.model_dump(mode="json")
            context.setdefault("authorized_targets", context.get("targets", []))
            context.setdefault("roe_validated", context.get("roe_signed", False))
            context.setdefault(
                "safety_mode",
                "authorized-active" if context.get("activation_verified") else "dry-run",
            )
            # Derive evidence_dir from roe_path so plugins can write artefacts.
            roe_p = self._current_engagement.roe_path
            if roe_p:
                roe_parent = Path(roe_p).resolve().parent
                context.setdefault("evidence_dir", str(roe_parent / "evidence"))
                context.setdefault("reports_dir", str(roe_parent / "reports"))
        if extra_context:
            context.update(extra_context)

        if dry_run:
            log.info("plugin_dry_run", plugin=plugin_name)
            self.audit.log(
                action="PLUGIN_DRY_RUN",
                details=f"Dry run: {plugin_name}",
                plugin=plugin_name,
                engagement_id=context.get("engagement_id", ""),
            )
            return plugin.dry_run(context)

        # Policy gate
        if plugin.requires_authorization:
            context["plugin_category"] = getattr(plugin, "category", "")
            self.policy.authorize(
                plugin_name=plugin_name,
                engagement=context,
                requires_authorization=True,
            )

        valid, reason = plugin.validate_context(context)
        if not valid:
            return PluginResult(
                plugin_name=plugin_name,
                success=False,
                errors=[f"Context validation failed: {reason}"],
            )

        log.info("plugin_execute", plugin=plugin_name)
        self.audit.log(
            action="PLUGIN_EXECUTE",
            details=f"Executing: {plugin_name}",
            plugin=plugin_name,
            engagement_id=context.get("engagement_id", ""),
        )

        start_time = time.monotonic()
        try:
            result = plugin.execute(context)
        except Exception as exc:
            result = PluginResult(
                plugin_name=plugin_name,
                success=False,
                errors=[f"Plugin execution error: {exc}"],
            )

        duration_ms = int((time.monotonic() - start_time) * 1000)
        result.metadata["duration_ms"] = duration_ms
        result.metadata["duration_seconds"] = round(duration_ms / 1000, 3)

        # Evidence indexing (opt-in)
        self._index_evidence(result)

        # Finding enrichment (CWE, CVSS, remediation, MITRE)
        enrich_plugin_result(result)

        # Mode separation (C6)
        if dry_run:
            result.metadata["execution_mode"] = "dry_run"
        elif not result.metadata.get("execution_mode"):
            result.metadata["execution_mode"] = "real"

        # Fake metric detection (FM-1..FM-3)
        detect_fake_metrics(result)

        # Contract validation (C1-C6)
        validate_contract(result)

        log.info(
            "plugin_complete",
            plugin=plugin_name,
            success=result.success,
            findings=len(result.findings),
            duration_ms=duration_ms,
        )
        self.audit.log(
            action="PLUGIN_COMPLETE",
            details=(
                f"{plugin_name}: success={result.success}, "
                f"findings={len(result.findings)}, {duration_ms}ms"
            ),
            plugin=plugin_name,
            engagement_id=context.get("engagement_id", ""),
        )
        return result

    async def arun_plugin(
        self,
        plugin_name: str,
        engagement: EngagementContext,
        *,
        dry_run: bool = False,
        isolation_available: bool = False,
        extra_context: dict[str, Any] | None = None,
    ) -> PluginResult:
        """Execute a plugin with full 11-step enforcement sequence (async).

        Steps:
          1. Resolve plugin in PluginRegistry
          2. Validate EngagementContext (Pydantic strict)
          3. Check engagement time window
          4. Verify RoE signature
          5. Verify activation code
          6. Check RuntimeMode × PluginCapability matrix
          7. Check OffensiveControls.has_controls(plugin.required_controls)
          8. Confirm isolation for DESTRUCTIVE plugins
          9. Enforce rate limits (placeholder for TokenBucket integration)
         10. If dry_run: log + return simulated PluginResult
         11. Execute: asyncio.wait_for(plugin.aexecute(...), timeout)
        """
        eid = engagement.engagement_id

        # Step 1 — Resolve plugin
        plugin = PluginRegistry.get_instance(plugin_name)
        if plugin is None:
            raise PluginNotFoundError(plugin_name, engagement_id=eid)

        # Step 2 — Validate EngagementContext
        EngagementContext.model_validate(engagement.model_dump())

        # Step 3 — Check engagement time window
        if engagement.is_expired():
            raise PolicyDeniedException(
                plugin_name, "Engagement time window has expired", engagement_id=eid
            )
        if not engagement.is_within_window():
            raise PolicyDeniedException(
                plugin_name, "Current time is outside engagement window", engagement_id=eid
            )

        # Step 4 — Verify RoE signature
        if not engagement.roe_signed and not engagement.roe_path:
            raise RoEValidationError("RoE not validated for this engagement", engagement_id=eid)

        # Step 5 — Verify activation code
        if not engagement.activation_verified:
            raise ActivationError("Activation code not verified", engagement_id=eid)

        # Step 5b — Enforce allowed_tests
        if engagement.allowed_tests:
            plugin_category = getattr(plugin, "category", "")
            name_prefix = plugin_name.split(".")[0] if "." in plugin_name else ""
            if (
                plugin_name not in engagement.allowed_tests
                and plugin_category not in engagement.allowed_tests
                and name_prefix not in engagement.allowed_tests
            ):
                raise PolicyDeniedException(
                    plugin_name,
                    f"Plugin '{plugin_name}' not in allowed tests: "
                    f"{engagement.allowed_tests}",
                    engagement_id=eid,
                )

        # Step 6 — RuntimeMode × PluginCapability matrix
        if not _is_capability_allowed(engagement.runtime_mode, plugin.capability):
            raise PolicyDeniedException(
                plugin_name,
                f"Capability '{plugin.capability.value}' not allowed in "
                f"mode '{engagement.runtime_mode.value}'",
                engagement_id=eid,
            )

        # Step 7 — OffensiveControls check
        required = getattr(plugin, "required_controls", [])
        if required and not engagement.offensive_controls.has_controls(required):
            missing = [
                ctrl for ctrl in required if not getattr(engagement.offensive_controls, ctrl, False)
            ]
            raise OffensiveControlError(plugin_name, missing, engagement_id=eid)

        # Step 8 — Isolation check for DESTRUCTIVE plugins
        if plugin.capability == PluginCapability.DESTRUCTIVE:
            needs_isolation = getattr(plugin, "requires_isolation", True)
            if needs_isolation and not isolation_available:
                raise IsolationError(plugin_name, engagement_id=eid)

        # Step 8b — Plugin hash verification (TEST mode, opt-in)
        if engagement.runtime_mode == RuntimeMode.TEST and self._trusted_plugin_hashes is not None:
            self._verify_plugin_hash(plugin_name, plugin)

        # Step 9 — Rate limit enforcement (placeholder — integrated in Module 1.3)

        # Step 10 — Dry run
        if dry_run:
            log.info("async_plugin_dry_run", plugin=plugin_name, engagement_id=eid)
            self.audit.log(
                action="ASYNC_PLUGIN_DRY_RUN",
                details=f"Async dry run: {plugin_name}",
                plugin=plugin_name,
                engagement_id=eid,
            )
            context = engagement.model_dump(mode="json")
            context["plugin_category"] = getattr(plugin, "category", "")
            if extra_context:
                context.update(extra_context)
            return plugin.dry_run(context)

        # Step 11 — Execute with timeout
        timeout = getattr(plugin, "timeout_seconds", 60)
        context = engagement.model_dump(mode="json")
        context["plugin_category"] = getattr(plugin, "category", "")
        if extra_context:
            context.update(extra_context)

        log.info("async_plugin_execute", plugin=plugin_name, engagement_id=eid)
        self.audit.log(
            action="ASYNC_PLUGIN_EXECUTE",
            details=f"Async executing: {plugin_name}",
            plugin=plugin_name,
            engagement_id=eid,
        )

        start_time = time.monotonic()
        try:
            if hasattr(plugin, "aexecute"):
                result = await asyncio.wait_for(
                    plugin.aexecute(context),
                    timeout=timeout,
                )
            else:
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, plugin.execute, context),
                    timeout=timeout,
                )
        except asyncio.TimeoutError:
            raise ScanTimeoutError(
                plugin_name,
                float(timeout),
                engagement_id=eid,
            ) from None
        except Exception as exc:
            result = PluginResult(
                plugin_name=plugin_name,
                success=False,
                errors=[f"Plugin execution error: {exc}"],
            )

        duration_ms = int((time.monotonic() - start_time) * 1000)
        result.metadata["duration_ms"] = duration_ms
        result.metadata["duration_seconds"] = round(duration_ms / 1000, 3)

        # Evidence indexing (opt-in)
        self._index_evidence(result)

        # Finding enrichment (CWE, CVSS, remediation, MITRE)
        enrich_plugin_result(result)

        # Mode separation (C6)
        if dry_run:
            result.metadata["execution_mode"] = "dry_run"
        elif not result.metadata.get("execution_mode"):
            result.metadata["execution_mode"] = "real"

        # Fake metric detection (FM-1..FM-3)
        detect_fake_metrics(result)

        # Contract validation (C1-C6)
        validate_contract(result)

        log.info(
            "async_plugin_complete",
            plugin=plugin_name,
            success=result.success,
            findings=len(result.findings),
            duration_ms=duration_ms,
        )
        self.audit.log(
            action="ASYNC_PLUGIN_COMPLETE",
            details=(
                f"{plugin_name}: success={result.success}, "
                f"findings={len(result.findings)}, {duration_ms}ms"
            ),
            plugin=plugin_name,
            engagement_id=eid,
        )
        return result

    def set_evidence_store(self, store: Any) -> None:
        """Attach an EvidenceStore for automatic evidence indexing."""
        self._evidence_store = store

    def set_trusted_plugin_hashes(self, hashes: dict[str, str]) -> None:
        """Set trusted plugin SHA-256 hashes for verification.

        Keys are plugin names, values are expected SHA-256 hex digests
        of the plugin source file.
        """
        self._trusted_plugin_hashes = dict(hashes)

    def _index_evidence(self, result: PluginResult) -> None:
        """Index any evidence attached to a plugin result."""
        if self._evidence_store is None:
            return
        if not result.evidence:
            return
        for ev in result.evidence:
            try:
                ev_path = Path(ev.path)
                data = ev_path.read_bytes() if ev_path.is_file() else ev.sha256.encode("utf-8")
                self._evidence_store.store(
                    data=data,
                    evidence_type=ev.evidence_type,
                    finding_ref=ev.provenance_tag,
                    plugin_name=result.plugin_name,
                )
            except Exception:
                log.warning(
                    "evidence_index_failed",
                    plugin=result.plugin_name,
                    sha256=ev.sha256[:12],
                    exc_info=True,
                )

    def _verify_plugin_hash(self, plugin_name: str, plugin: Any) -> None:
        """Verify plugin source file hash against trusted hashes."""
        if self._trusted_plugin_hashes is None:
            return
        expected = self._trusted_plugin_hashes.get(plugin_name)
        if expected is None:
            return

        import inspect

        source_file = inspect.getfile(type(plugin))
        actual = CryptoEngine.hash_file(source_file)
        if not CryptoEngine.secure_compare(actual, expected):
            raise PluginError(
                plugin_name,
                f"Plugin hash verification failed: expected {expected[:12]}…, got {actual[:12]}…",
            )

    def shutdown(self) -> None:
        """Clean shutdown of the orchestrator."""
        if self._current_engagement:
            log.info("engagement_shutdown", engagement_id=self._current_engagement.engagement_id)
            self.audit.log_engagement_action(
                action="ENGAGEMENT_SHUTDOWN",
                engagement_id=self._current_engagement.engagement_id,
            )
        self._current_engagement = None


# ---------------------------------------------------------------------------
# Legacy adapter — backward compatibility for code that accessed the old
# dataclass EngagementContext attributes directly.
# ---------------------------------------------------------------------------


class _LegacyEngagementAdapter:
    """Thin wrapper around the Pydantic ``EngagementContext`` that exposes
    the legacy dataclass interface expected by existing tests / CLI code.
    """

    def __init__(self, ctx: EngagementContext) -> None:
        self._ctx = ctx

    def __getattr__(self, name: str) -> Any:
        try:
            return getattr(self._ctx, name)
        except AttributeError:
            pass
        aliases: dict[str, str] = {
            "authorized_targets": "_authorized_targets",
            "roe_validated": "_roe_validated",
            "safety_mode": "_safety_mode",
        }
        if name in aliases:
            key = aliases[name]
            if key == "_authorized_targets":
                return [{"host": t} if isinstance(t, str) else t for t in self._ctx.targets]
            if key == "_roe_validated":
                return self._ctx.roe_signed
            if key == "_safety_mode":
                return "authorized-active" if self._ctx.activation_verified else "dry-run"
        raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")

    def to_dict(self) -> dict[str, Any]:
        """Legacy dict format expected by old orchestrator tests."""
        d = self._ctx.model_dump(mode="json")
        d["authorized_targets"] = [
            {"host": t} if isinstance(t, str) else t for t in (self._ctx.targets or [])
        ]
        d["roe_validated"] = self._ctx.roe_signed
        d["safety_mode"] = "authorized-active" if self._ctx.activation_verified else "dry-run"
        return d


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_engagement_from_roe(roe_data: dict[str, Any], roe_path: str) -> EngagementContext:
    """Build a Pydantic EngagementContext from validated RoE data."""
    raw_targets = roe_data.get("authorized_targets", roe_data.get("targets", []))
    targets: list[str] = []
    for t in raw_targets:
        if isinstance(t, dict):
            targets.append(t.get("host", str(t)))
        else:
            targets.append(str(t))

    def _parse_time(val: Any) -> datetime:
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val
        raw = str(val)
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        return datetime.fromisoformat(raw)

    # Parse offensive_controls from RoE YAML
    oc_raw = roe_data.get("offensive_controls", {})
    offensive_controls = OffensiveControls(**(oc_raw if isinstance(oc_raw, dict) else {}))

    # Parse runtime_mode from RoE YAML
    rm_raw = roe_data.get("runtime_mode", "dev")
    try:
        runtime_mode = RuntimeMode(rm_raw) if rm_raw else RuntimeMode.DEV
    except ValueError:
        runtime_mode = RuntimeMode.DEV

    return EngagementContext(
        engagement_id=str(roe_data.get("engagement_id", "")),
        authorizer=str(roe_data.get("authorizer", "")),
        targets=targets or ["placeholder.invalid"],
        allowed_tests=roe_data.get("allowed_tests", ["passive-recon"]),
        start_time_utc=_parse_time(roe_data.get("start_time_utc", datetime.now(timezone.utc))),
        end_time_utc=_parse_time(roe_data.get("end_time_utc", datetime.now(timezone.utc))),
        sensitivity=str(roe_data.get("sensitivity", "standard")),
        roe_path=roe_path,
        roe_signed=bool(roe_data.get("signature")),
        offensive_controls=offensive_controls,
        runtime_mode=runtime_mode,
        otp_email=roe_data.get("otp_email"),
    )
