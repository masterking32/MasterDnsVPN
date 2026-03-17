"""Tests for dns_utils/__init__.py."""

from __future__ import annotations

import importlib

import dns_utils
from dns_utils.ARQ import ARQ
from dns_utils.DNSBalancer import DNSBalancer
from dns_utils.DnsPacketParser import DnsPacketParser
class TestPublicAPI:
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

    def test_exported_classes_are_correct_types(self) -> None:
        assert dns_utils.DnsPacketParser is DnsPacketParser
        assert dns_utils.ARQ is ARQ
        assert dns_utils.DNSBalancer is DNSBalancer


