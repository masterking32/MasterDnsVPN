"""Tests for dns_utils/DNSBalancer.py."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.DNSBalancer import DNSBalancer


def make_server(resolver: str, domain: str, is_valid: bool = True) -> dict:
    return {
        "resolver": resolver,
        "domain": domain,
        "is_valid": is_valid,
    }


def make_servers(count: int, valid: bool = True) -> list[dict]:
    return [make_server(f"10.0.0.{i}", f"vpn{i}.example.com", valid) for i in range(1, count + 1)]


# ---------------------------------------------------------------------------
# Initialization and set_balancers
# ---------------------------------------------------------------------------


class TestDNSBalancerInit:
    def test_round_robin_is_default(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        assert b.valid_servers_count == 3

    def test_filters_invalid_servers(self) -> None:
        servers = make_servers(2) + make_servers(2, valid=False)
        b = DNSBalancer(servers, strategy=0)
        assert b.valid_servers_count == 2

    def test_set_balancers_adds_key(self) -> None:
        servers = make_servers(2)
        b = DNSBalancer(servers, strategy=0)
        for s in b.valid_servers:
            assert "_key" in s

    def test_empty_resolvers(self) -> None:
        b = DNSBalancer([], strategy=0)
        assert b.valid_servers_count == 0
        assert b.get_best_server() is None

    def test_set_balancers_resets_rr_index(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        b.get_unique_servers(2)  # Advance rr_index
        b.set_balancers(make_servers(3))
        assert b.rr_index == 0


# ---------------------------------------------------------------------------
# Round-robin strategy
# ---------------------------------------------------------------------------


class TestRoundRobin:
    def test_returns_requested_count(self) -> None:
        b = DNSBalancer(make_servers(5), strategy=0)
        result = b.get_unique_servers(3)
        assert len(result) == 3

    def test_wraps_around(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        r1 = b.get_unique_servers(2)
        r2 = b.get_unique_servers(2)
        # Total 4 requests from 3 servers; should wrap
        assert len(r1) == 2
        assert len(r2) == 2

    def test_single_server(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        result = b.get_unique_servers(1)
        assert len(result) == 1

    def test_count_exceeds_available_returns_all(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        result = b.get_unique_servers(10)
        assert len(result) == 3

    def test_get_best_server(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        server = b.get_best_server()
        assert server is not None

    def test_get_servers_for_stream(self) -> None:
        b = DNSBalancer(make_servers(4), strategy=0)
        result = b.get_servers_for_stream(stream_id=1, required_count=2)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Random strategy
# ---------------------------------------------------------------------------


class TestRandomStrategy:
    def test_returns_requested_count(self) -> None:
        b = DNSBalancer(make_servers(5), strategy=1)
        result = b.get_unique_servers(3)
        assert len(result) == 3

    def test_returns_random_subset(self) -> None:
        b = DNSBalancer(make_servers(10), strategy=1)
        results = set()
        for _ in range(20):
            r = b.get_unique_servers(1)
            results.add(r[0]["resolver"])
        assert len(results) > 1  # Should see variety


# ---------------------------------------------------------------------------
# Least-loss strategy
# ---------------------------------------------------------------------------


class TestLeastLossStrategy:
    def test_prefers_lowest_loss_server(self) -> None:
        servers = make_servers(3)
        b = DNSBalancer(servers, strategy=3)

        # Make server 0 have perfect stats
        key0 = b.valid_servers[0]["_key"]
        b.server_stats[key0]["sent"] = 100
        b.server_stats[key0]["acked"] = 100  # 0% loss

        # Server 1 has high loss
        key1 = b.valid_servers[1]["_key"]
        b.server_stats[key1]["sent"] = 100
        b.server_stats[key1]["acked"] = 10  # 90% loss

        result = b.get_unique_servers(1)
        assert result[0]["_key"] == key0

    def test_unknown_servers_have_default_loss(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=3)
        result = b.get_unique_servers(3)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# Lowest latency strategy
# ---------------------------------------------------------------------------


class TestLowestLatencyStrategy:
    def test_prefers_lowest_rtt_server(self) -> None:
        servers = make_servers(3)
        b = DNSBalancer(servers, strategy=4)

        # Server 0: fast
        key0 = b.valid_servers[0]["_key"]
        b.server_stats[key0]["rtt_sum"] = 5.0
        b.server_stats[key0]["rtt_count"] = 5

        # Server 1: slow
        key1 = b.valid_servers[1]["_key"]
        b.server_stats[key1]["rtt_sum"] = 500.0
        b.server_stats[key1]["rtt_count"] = 5

        result = b.get_unique_servers(1)
        assert result[0]["_key"] == key0


# ---------------------------------------------------------------------------
# Stats reporting
# ---------------------------------------------------------------------------


class TestServerStats:
    def test_report_send_increments(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.report_send(key)
        b.report_send(key)
        assert b.server_stats[key]["sent"] == 2

    def test_report_success_increments_acked(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.report_success(key, rtt=0.1)
        assert b.server_stats[key]["acked"] == 1
        assert b.server_stats[key]["rtt_sum"] == pytest.approx(0.1)
        assert b.server_stats[key]["rtt_count"] == 1

    def test_report_success_without_rtt(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.report_success(key, rtt=0.0)
        assert b.server_stats[key]["acked"] == 1
        assert b.server_stats[key]["rtt_count"] == 0

    def test_stats_decay_when_sent_exceeds_1000(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.server_stats[key]["sent"] = 1001
        b.server_stats[key]["acked"] = 800
        b.server_stats[key]["rtt_sum"] = 100.0
        b.server_stats[key]["rtt_count"] = 100
        b.report_success(key, rtt=0.5)
        # After decay, sent should be halved
        assert b.server_stats[key]["sent"] < 600

    def test_reset_server_stats(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.report_send(key)
        b.reset_server_stats(key)
        assert key not in b.server_stats

    def test_get_loss_rate_no_data_returns_default(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        assert b.get_loss_rate("unknown_key") == 0.5

    def test_get_loss_rate_few_sent_returns_default(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.server_stats[key]["sent"] = 3
        b.server_stats[key]["acked"] = 0
        assert b.get_loss_rate(key) == 0.5

    def test_get_loss_rate_calculation(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.server_stats[key]["sent"] = 100
        b.server_stats[key]["acked"] = 75
        rate = b.get_loss_rate(key)
        assert rate == pytest.approx(0.25)

    def test_get_loss_rate_clamped_to_0_1(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.server_stats[key]["sent"] = 100
        b.server_stats[key]["acked"] = 200  # More acked than sent
        rate = b.get_loss_rate(key)
        assert 0.0 <= rate <= 1.0

    def test_get_avg_rtt_no_data(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        assert b.get_avg_rtt("unknown") == 999.0

    def test_get_avg_rtt_few_samples(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.server_stats[key]["rtt_count"] = 3
        assert b.get_avg_rtt(key) == 999.0

    def test_get_avg_rtt_calculation(self) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.server_stats[key]["rtt_sum"] = 50.0
        b.server_stats[key]["rtt_count"] = 10
        assert b.get_avg_rtt(key) == pytest.approx(5.0)


# ---------------------------------------------------------------------------
# Normalize required count
# ---------------------------------------------------------------------------


class TestNormalizeRequiredCount:
    def test_zero_servers_returns_zero(self) -> None:
        b = DNSBalancer([], strategy=0)
        assert b._normalize_required_count(5) == 0

    def test_count_zero_defaults_to_one(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        assert b._normalize_required_count(0) == 1

    def test_count_negative_defaults_to_one(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        assert b._normalize_required_count(-1) == 1

    def test_count_exceeds_available(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        assert b._normalize_required_count(100) == 3

    def test_non_int_falls_back_to_default(self) -> None:
        b = DNSBalancer(make_servers(3), strategy=0)
        result = b._normalize_required_count("abc")  # type: ignore[arg-type]
        assert result == 1


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisDNSBalancer:
    @given(st.integers(min_value=1, max_value=10), st.integers(min_value=0, max_value=3))
    @settings(max_examples=40)
    def test_get_unique_servers_within_valid_count(self, n_servers: int, n_request: int) -> None:
        b = DNSBalancer(make_servers(n_servers), strategy=0)
        result = b.get_unique_servers(max(1, n_request))
        assert len(result) <= b.valid_servers_count

    @given(st.integers(min_value=1, max_value=10))
    @settings(max_examples=30)
    def test_get_best_server_returns_valid_server(self, n_servers: int) -> None:
        b = DNSBalancer(make_servers(n_servers), strategy=0)
        result = b.get_best_server()
        assert result is not None
        assert result in b.valid_servers

    @given(
        st.integers(min_value=0, max_value=1000),
        st.integers(min_value=0, max_value=1000),
    )
    @settings(max_examples=50)
    def test_loss_rate_always_between_zero_and_one(self, sent: int, acked: int) -> None:
        b = DNSBalancer(make_servers(1), strategy=0)
        key = b.valid_servers[0]["_key"]
        b.server_stats[key]["sent"] = sent
        b.server_stats[key]["acked"] = acked
        rate = b.get_loss_rate(key)
        assert 0.0 <= rate <= 1.0

    @given(st.integers(min_value=1, max_value=8))
    @settings(max_examples=20)
    def test_normalize_required_count_within_bounds(self, n_servers: int) -> None:
        b = DNSBalancer(make_servers(n_servers), strategy=0)
        for req in range(0, n_servers + 5):
            result = b._normalize_required_count(req)
            assert 1 <= result <= n_servers
