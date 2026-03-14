"""Tests for dns_utils/__init__.py."""

from __future__ import annotations

import importlib

import dns_utils
from dns_utils.ARQ import ARQ
from dns_utils.DNSBalancer import DNSBalancer
from dns_utils.DnsPacketParser import DnsPacketParser
from hypothesis import given, settings
from hypothesis import strategies as st


class TestTryExport:
    def test_successful_export_populates_all(self) -> None:
        # Re-import to ensure module is loaded
        importlib.reload(dns_utils)
        assert "DnsPacketParser" in dns_utils.__all__
        assert "ARQ" in dns_utils.__all__
        assert "DNSBalancer" in dns_utils.__all__
        assert "PingManager" in dns_utils.__all__
        assert "PrependReader" in dns_utils.__all__
        assert "PacketQueueMixin" in dns_utils.__all__

    def test_successful_export_creates_attribute(self) -> None:
        assert hasattr(dns_utils, "DnsPacketParser")
        assert hasattr(dns_utils, "ARQ")
        assert hasattr(dns_utils, "DNSBalancer")
        assert hasattr(dns_utils, "PingManager")
        assert hasattr(dns_utils, "PrependReader")
        assert hasattr(dns_utils, "PacketQueueMixin")

    def test_failed_import_silently_ignored(self) -> None:
        """_try_export should silently ignore import errors."""
        original_all = list(dns_utils.__all__)
        # Call _try_export with a non-existent module
        dns_utils._try_export("NonExistentClass", "non_existent_module")
        # Should not raise and non-existent class should not be in __all__
        assert "NonExistentClass" not in dns_utils.__all__
        assert original_all  # suppress unused variable warning

    def test_try_export_from_module(self) -> None:
        """_try_export with from_module param resolves attribute from that module."""
        # Export Packet_Type from DNS_ENUMS
        dns_utils._try_export("Packet_Type", "DNS_ENUMS")
        assert hasattr(dns_utils, "Packet_Type")
        assert "Packet_Type" in dns_utils.__all__

    def test_exported_classes_are_correct_types(self) -> None:
        assert dns_utils.DnsPacketParser is DnsPacketParser
        assert dns_utils.ARQ is ARQ
        assert dns_utils.DNSBalancer is DNSBalancer


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisInit:
    @given(st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_"),
        min_size=1,
        max_size=30,
    ))
    @settings(max_examples=50)
    def test_try_export_arbitrary_names_never_raises(self, name: str) -> None:
        # _try_export with a non-existent module should silently ignore errors
        try:
            dns_utils._try_export(name, "non_existent_module_xyz_" + name)
        except Exception as e:
            raise AssertionError(f"_try_export raised unexpectedly: {e}") from e
