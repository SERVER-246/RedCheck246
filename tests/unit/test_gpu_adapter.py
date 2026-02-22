"""Tests for redcheck.plugins.crypto.gpu_adapter — GPUAdapter.

Coverage: rate lookup, scaling, available GPUs/algorithms, fallback.
"""

from __future__ import annotations

from redcheck.plugins.crypto.gpu_adapter import GPUAdapter


class TestGPUAdapter:
    def test_default_model(self):
        adapter = GPUAdapter()
        assert adapter.model == "rtx_3090"

    def test_custom_model(self):
        adapter = GPUAdapter(gpu_model="rtx_4090")
        assert adapter.model == "rtx_4090"

    def test_unknown_model_fallback(self):
        adapter = GPUAdapter(gpu_model="unknown_gpu")
        assert adapter.model == "rtx_3090"

    def test_gpu_count(self):
        adapter = GPUAdapter(gpu_count=4)
        assert adapter.gpu_count == 4

    def test_negative_gpu_count_clamped(self):
        adapter = GPUAdapter(gpu_count=-1)
        assert adapter.gpu_count == 1

    def test_rate_for_known_algo(self):
        adapter = GPUAdapter(gpu_model="rtx_3090")
        rate = adapter.rate_for("MD5")
        assert rate > 0

    def test_rate_scales_with_count(self):
        single = GPUAdapter(gpu_count=1).rate_for("MD5")
        quad = GPUAdapter(gpu_count=4).rate_for("MD5")
        assert quad == single * 4

    def test_rate_for_unknown_algo(self):
        adapter = GPUAdapter()
        assert adapter.rate_for("nonexistent") == 0

    def test_all_rates(self):
        adapter = GPUAdapter()
        rates = adapter.all_rates()
        assert isinstance(rates, dict)
        assert len(rates) > 0
        assert all(isinstance(v, int) for v in rates.values())

    def test_available_gpus(self):
        gpus = GPUAdapter.available_gpus()
        assert "rtx_3090" in gpus
        assert "rtx_4090" in gpus
        assert "a100" in gpus

    def test_available_algorithms(self):
        algos = GPUAdapter.available_algorithms("rtx_3090")
        assert "MD5" in algos
        assert "bcrypt_cost12" in algos
        assert "argon2id" in algos

    def test_to_dict(self):
        adapter = GPUAdapter(gpu_model="rtx_4090", gpu_count=2)
        d = adapter.to_dict()
        assert d["model"] == "rtx_4090"
        assert d["gpu_count"] == 2
        assert d["mode"] == "simulation"
        assert "rates" in d
