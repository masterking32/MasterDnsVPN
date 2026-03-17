"""Tests for dns_utils/DNS_ENUMS.py - enum value correctness and uniqueness."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.DNS_ENUMS import (
    DNS_QClass,
    DNS_Record_Type,
    DNS_rCode,
    Packet_Type,
    Stream_State,
)


def _public_attrs(cls: type) -> dict[str, int]:
    return {k: v for k, v in vars(cls).items() if not k.startswith("_")}


# ---------------------------------------------------------------------------
# Packet_Type
# ---------------------------------------------------------------------------


class TestPacketType:
    def test_all_values_unique(self) -> None:
        attrs = _public_attrs(Packet_Type)
        values = list(attrs.values())
        assert len(values) == len(set(values)), "Duplicate Packet_Type values found"

    def test_session_packets_range(self) -> None:
        assert Packet_Type.MTU_UP_REQ == 0x01
        assert Packet_Type.MTU_UP_RES == 0x02
        assert Packet_Type.MTU_DOWN_REQ == 0x03
        assert Packet_Type.MTU_DOWN_RES == 0x04
        assert Packet_Type.SESSION_INIT == 0x05
        assert Packet_Type.SESSION_ACCEPT == 0x06
        assert Packet_Type.SET_MTU_REQ == 0x07
        assert Packet_Type.SET_MTU_RES == 0x08

    def test_ping_pong(self) -> None:
        assert Packet_Type.PING == 0x09
        assert Packet_Type.PONG == 0x0A

    def test_stream_lifecycle(self) -> None:
        assert Packet_Type.STREAM_SYN == 0x0B
        assert Packet_Type.STREAM_SYN_ACK == 0x0C
        assert Packet_Type.STREAM_DATA == 0x0D
        assert Packet_Type.STREAM_DATA_ACK == 0x0E
        assert Packet_Type.STREAM_RESEND == 0x0F

    def test_packed_control_blocks(self) -> None:
        assert Packet_Type.PACKED_CONTROL_BLOCKS == 0x10

    def test_stream_close_reset(self) -> None:
        assert Packet_Type.STREAM_FIN == 0x11
        assert Packet_Type.STREAM_FIN_ACK == 0x12
        assert Packet_Type.STREAM_RST == 0x13
        assert Packet_Type.STREAM_RST_ACK == 0x14

    def test_error_drop(self) -> None:
        assert Packet_Type.ERROR_DROP == 0xFF

    def test_socks5_types_exist(self) -> None:
        assert hasattr(Packet_Type, "SOCKS5_SYN")
        assert hasattr(Packet_Type, "SOCKS5_SYN_ACK")
        assert hasattr(Packet_Type, "SOCKS5_CONNECT_FAIL")

    def test_all_values_are_integers(self) -> None:
        for name, val in _public_attrs(Packet_Type).items():
            assert isinstance(val, int), f"Packet_Type.{name} is not an int"


# ---------------------------------------------------------------------------
# Stream_State
# ---------------------------------------------------------------------------


class TestStreamState:
    def test_all_values_unique(self) -> None:
        attrs = _public_attrs(Stream_State)
        values = list(attrs.values())
        assert len(values) == len(set(values)), "Duplicate Stream_State values found"

    def test_expected_values(self) -> None:
        assert Stream_State.OPEN == 1
        assert Stream_State.HALF_CLOSED_LOCAL == 2
        assert Stream_State.HALF_CLOSED_REMOTE == 3
        assert Stream_State.DRAINING == 4
        assert Stream_State.CLOSING == 5
        assert Stream_State.TIME_WAIT == 6
        assert Stream_State.RESET == 7
        assert Stream_State.CLOSED == 8

    def test_all_values_are_integers(self) -> None:
        for name, val in _public_attrs(Stream_State).items():
            assert isinstance(val, int), f"Stream_State.{name} is not an int"


# ---------------------------------------------------------------------------
# DNS_Record_Type
# ---------------------------------------------------------------------------


class TestDNSRecordType:
    def test_all_values_unique(self) -> None:
        attrs = _public_attrs(DNS_Record_Type)
        values = list(attrs.values())
        assert len(values) == len(set(values)), "Duplicate DNS_Record_Type values found"

    def test_common_types(self) -> None:
        assert DNS_Record_Type.A == 1
        assert DNS_Record_Type.NS == 2
        assert DNS_Record_Type.CNAME == 5
        assert DNS_Record_Type.MX == 15
        assert DNS_Record_Type.TXT == 16
        assert DNS_Record_Type.AAAA == 28
        assert DNS_Record_Type.ANY == 255

    def test_all_values_are_integers(self) -> None:
        for name, val in _public_attrs(DNS_Record_Type).items():
            assert isinstance(val, int), f"DNS_Record_Type.{name} is not an int"


# ---------------------------------------------------------------------------
# DNS_rCode
# ---------------------------------------------------------------------------


class TestDNSrCode:
    def test_all_values_unique(self) -> None:
        attrs = _public_attrs(DNS_rCode)
        values = list(attrs.values())
        assert len(values) == len(set(values)), "Duplicate DNS_rCode values found"

    def test_no_error(self) -> None:
        assert DNS_rCode.NO_ERROR == 0

    def test_server_failure(self) -> None:
        assert DNS_rCode.SERVER_FAILURE == 2

    def test_refused(self) -> None:
        assert DNS_rCode.REFUSED == 5


# ---------------------------------------------------------------------------
# DNS_QClass
# ---------------------------------------------------------------------------


class TestDNSQClass:
    def test_all_values_unique(self) -> None:
        attrs = _public_attrs(DNS_QClass)
        values = list(attrs.values())
        assert len(values) == len(set(values)), "Duplicate DNS_QClass values found"

    def test_internet_class(self) -> None:
        assert DNS_QClass.IN == 1

    def test_any_class(self) -> None:
        assert DNS_QClass.ANY == 255


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------

_ALL_ENUM_CLASSES = [Packet_Type, Stream_State, DNS_Record_Type, DNS_rCode, DNS_QClass]


class TestHypothesisDNSEnums:
    @given(st.sampled_from(_ALL_ENUM_CLASSES))
    @settings(max_examples=20)
    def test_enum_class_values_are_integers(self, enum_cls: type) -> None:
        for name, val in _public_attrs(enum_cls).items():
            assert isinstance(val, int), f"{enum_cls.__name__}.{name} is not int"

    @given(st.sampled_from(_ALL_ENUM_CLASSES))
    @settings(max_examples=20)
    def test_enum_class_has_unique_values(self, enum_cls: type) -> None:
        vals = list(_public_attrs(enum_cls).values())
        assert len(vals) == len(set(vals)), f"{enum_cls.__name__} has duplicate values"

    @given(st.sampled_from(_ALL_ENUM_CLASSES))
    @settings(max_examples=20)
    def test_enum_class_is_non_empty(self, enum_cls: type) -> None:
        assert len(_public_attrs(enum_cls)) > 0
