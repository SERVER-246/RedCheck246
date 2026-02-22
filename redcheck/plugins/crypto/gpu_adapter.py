"""RedCheck246 — GPU Hash-Rate Adapter (Simulation Mode).

Provides estimated GPU hash-rate benchmarks for crack-time calculations.
Operates in **simulation mode only** — uses pre-computed benchmark tables
rather than actual GPU acceleration.
"""

from __future__ import annotations

from typing import Any

import structlog

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Benchmark table — estimated H/s per GPU model (single GPU)
# ---------------------------------------------------------------------------

_GPU_BENCHMARKS: dict[str, dict[str, int]] = {
    "rtx_4090": {
        "MD5": 164_000_000_000,
        "SHA-1": 26_000_000_000,
        "SHA-256": 22_000_000_000,
        "SHA-512": 4_300_000_000,
        "bcrypt_cost12": 184_000,
        "scrypt": 2_500,
        "argon2id": 800,
        "PBKDF2_SHA256": 4_500_000,
        "NTLM": 300_000_000_000,
    },
    "rtx_3090": {
        "MD5": 64_000_000_000,
        "SHA-1": 16_000_000_000,
        "SHA-256": 8_000_000_000,
        "SHA-512": 3_000_000_000,
        "bcrypt_cost12": 105_000,
        "scrypt": 1_000,
        "argon2id": 500,
        "PBKDF2_SHA256": 2_500_000,
        "NTLM": 100_000_000_000,
    },
    "a100": {
        "MD5": 100_000_000_000,
        "SHA-1": 20_000_000_000,
        "SHA-256": 15_000_000_000,
        "SHA-512": 3_800_000_000,
        "bcrypt_cost12": 150_000,
        "scrypt": 2_000,
        "argon2id": 700,
        "PBKDF2_SHA256": 3_500_000,
        "NTLM": 200_000_000_000,
    },
}

_DEFAULT_GPU = "rtx_3090"


class GPUAdapter:
    """Simulated GPU hash-rate provider.

    Does NOT perform actual GPU computation.
    Provides pre-computed benchmark values for crack-time estimation.

    Args:
        gpu_model: GPU model key (default ``rtx_3090``).
        gpu_count: Number of GPUs (scales linearly).
    """

    def __init__(
        self,
        gpu_model: str = _DEFAULT_GPU,
        gpu_count: int = 1,
    ) -> None:
        if gpu_model not in _GPU_BENCHMARKS:
            log.warning(
                "gpu_model_unknown",
                model=gpu_model,
                default=_DEFAULT_GPU,
            )
            gpu_model = _DEFAULT_GPU

        if gpu_count < 1:
            gpu_count = 1

        self._model = gpu_model
        self._count = gpu_count
        self._benchmarks = _GPU_BENCHMARKS[gpu_model]

    @property
    def model(self) -> str:
        return self._model

    @property
    def gpu_count(self) -> int:
        return self._count

    def rate_for(self, algorithm: str) -> int:
        """Get estimated hashes/second for the given algorithm.

        Returns 0 if algorithm is not in the benchmark table.
        Scales linearly by ``gpu_count``.
        """
        base = self._benchmarks.get(algorithm, 0)
        return base * self._count

    def all_rates(self) -> dict[str, int]:
        """Return all benchmark rates scaled by gpu_count."""
        return {algo: rate * self._count for algo, rate in self._benchmarks.items()}

    @staticmethod
    def available_gpus() -> list[str]:
        """List available GPU model keys."""
        return list(_GPU_BENCHMARKS.keys())

    @staticmethod
    def available_algorithms(gpu_model: str = _DEFAULT_GPU) -> list[str]:
        """List algorithms benchmarked for a GPU model."""
        return list(_GPU_BENCHMARKS.get(gpu_model, {}).keys())

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self._model,
            "gpu_count": self._count,
            "mode": "simulation",
            "rates": self.all_rates(),
        }
