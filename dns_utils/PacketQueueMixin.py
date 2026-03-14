# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import heapq

from .DNS_ENUMS import Packet_Type


class PacketQueueMixin:
    """Shared queue/priority bookkeeping for client and server packet schedulers."""

    _PRIORITY_ZERO_TYPES = {
        Packet_Type.STREAM_DATA_ACK,
        Packet_Type.STREAM_RST,
        Packet_Type.STREAM_RST_ACK,
        Packet_Type.STREAM_FIN_ACK,
        Packet_Type.STREAM_SYN_ACK,
        Packet_Type.SOCKS5_SYN_ACK,
    }
    _SYN_TRACK_TYPES = {
        Packet_Type.STREAM_SYN,
        Packet_Type.STREAM_SYN_ACK,
        Packet_Type.SOCKS5_SYN_ACK,
    }

    def _compute_mtu_based_pack_limit(
        self, mtu_size: int, usage_percent: float, block_size: int = 5
    ) -> int:
        """
        Convert MTU budget to max packable control blocks.
        Example: mtu=200, percent=100, block_size=5 -> 40 blocks.
        """
        try:
            mtu = max(0, int(mtu_size))
            pct = max(1.0, min(100.0, float(usage_percent)))
            blk = max(1, int(block_size))
        except Exception:
            return 1

        usable_budget = int(mtu * (pct / 100.0))
        return max(1, usable_budget // blk)

    def _inc_priority_counter(self, owner: dict, priority: int) -> None:
        counters = owner.setdefault("priority_counts", {})
        p = int(priority)
        counters[p] = counters.get(p, 0) + 1

    def _dec_priority_counter(self, owner: dict, priority: int) -> None:
        counters = owner.get("priority_counts")
        if not counters:
            return
        p = int(priority)
        cur = counters.get(p, 0)
        if cur <= 1:
            counters.pop(p, None)
        else:
            counters[p] = cur - 1

    def _release_tracking_on_pop(self, owner: dict, packet_type: int, sn: int) -> None:
        ptype = int(packet_type)
        if ptype in (Packet_Type.STREAM_DATA, Packet_Type.SOCKS5_SYN):
            track_data = owner.get("track_data")
            if track_data is not None:
                track_data.discard(sn)
        elif ptype == Packet_Type.STREAM_DATA_ACK:
            track_ack = owner.get("track_ack")
            if track_ack is not None:
                track_ack.discard(sn)
        elif ptype == Packet_Type.STREAM_RESEND:
            track_resend = owner.get("track_resend")
            if track_resend is not None:
                track_resend.discard(sn)
        elif ptype == Packet_Type.STREAM_FIN:
            track_fin = owner.get("track_fin")
            if track_fin is not None:
                track_fin.discard(ptype)
            track_types = owner.get("track_types")
            if track_types is not None:
                track_types.discard(ptype)
        elif ptype in self._SYN_TRACK_TYPES:
            track_syn_ack = owner.get("track_syn_ack")
            if track_syn_ack is not None:
                track_syn_ack.discard(ptype)
            track_types = owner.get("track_types")
            if track_types is not None:
                track_types.discard(ptype)

    def _on_queue_pop(self, owner: dict, queue_item: tuple) -> None:
        priority, _, ptype, _, sn, _ = queue_item
        self._dec_priority_counter(owner, priority)
        self._release_tracking_on_pop(owner, ptype, sn)

    def _pop_packable_control_block(
        self,
        queue,
        owner: dict,
        priority: int,
        packet_type: int | None = None,
    ):
        if not queue:
            return None
        item = queue[0]
        if int(item[0]) != int(priority):
            return None
        ptype = int(item[2])
        if packet_type is not None and ptype != int(packet_type):
            return None
        payload = item[5]
        if ptype not in self._packable_control_types or payload:
            return None
        popped = heapq.heappop(queue)
        self._on_queue_pop(owner, popped)
        return popped

    def _owner_has_priority(self, owner: dict, priority: int) -> bool:
        counters = owner.get("priority_counts")
        if not counters:
            return False
        return counters.get(int(priority), 0) > 0

    def _resolve_arq_packet_type(self, **flags) -> int:
        if flags.get("is_ack"):
            return Packet_Type.STREAM_DATA_ACK
        if flags.get("is_fin"):
            return Packet_Type.STREAM_FIN
        if flags.get("is_fin_ack"):
            return Packet_Type.STREAM_FIN_ACK
        if flags.get("is_rst"):
            return Packet_Type.STREAM_RST
        if flags.get("is_rst_ack"):
            return Packet_Type.STREAM_RST_ACK
        if flags.get("is_syn_ack"):
            return Packet_Type.STREAM_SYN_ACK
        if flags.get("is_socks_syn_ack"):
            return Packet_Type.SOCKS5_SYN_ACK
        if flags.get("is_socks_syn"):
            return Packet_Type.SOCKS5_SYN
        if flags.get("is_resend"):
            return Packet_Type.STREAM_RESEND
        return Packet_Type.STREAM_DATA

    def _effective_priority_for_packet(self, packet_type: int, priority: int) -> int:
        ptype = int(packet_type)
        eff = int(priority)
        if ptype in self._PRIORITY_ZERO_TYPES:
            return 0
        if ptype == Packet_Type.STREAM_FIN:
            return 4
        if ptype == Packet_Type.STREAM_RESEND:
            return 1
        return eff

    def _track_main_packet_once(self, owner: dict, ptype: int, sn: int) -> bool:
        if ptype == Packet_Type.STREAM_RESEND:
            if sn in owner.get("track_data", set()) or sn in owner.get(
                "track_resend", set()
            ):
                return False
            owner.setdefault("track_resend", set()).add(sn)
            return True
        if ptype == Packet_Type.STREAM_FIN or ptype in self._SYN_TRACK_TYPES:
            if ptype in owner.get("track_types", set()):
                return False
            owner.setdefault("track_types", set()).add(ptype)
            return True
        if ptype == Packet_Type.STREAM_DATA_ACK:
            if sn in owner.get("track_ack", set()):
                return False
            owner.setdefault("track_ack", set()).add(sn)
            return True
        if ptype == Packet_Type.STREAM_DATA:
            if sn in owner.get("track_data", set()):
                return False
            owner.setdefault("track_data", set()).add(sn)
            return True
        return True

    def _track_stream_packet_once(
        self,
        stream_data: dict,
        ptype: int,
        sn: int,
        data_packet_types=(Packet_Type.STREAM_DATA,),
    ) -> bool:
        if ptype == Packet_Type.STREAM_RESEND:
            if sn in stream_data["track_data"] or sn in stream_data["track_resend"]:
                return False
            stream_data["track_resend"].add(sn)
            return True
        if ptype == Packet_Type.STREAM_FIN:
            if ptype in stream_data["track_fin"]:
                return False
            stream_data["track_fin"].add(ptype)
            return True
        if ptype in (Packet_Type.STREAM_SYN_ACK, Packet_Type.SOCKS5_SYN_ACK):
            if ptype in stream_data["track_syn_ack"]:
                return False
            stream_data["track_syn_ack"].add(ptype)
            return True
        if ptype == Packet_Type.STREAM_DATA_ACK:
            if sn in stream_data["track_ack"]:
                return False
            stream_data["track_ack"].add(sn)
            return True
        if ptype in data_packet_types:
            if sn in stream_data["track_data"]:
                return False
            stream_data["track_data"].add(sn)
            return True
        return True

    def _push_queue_item(
        self, queue, owner: dict, queue_item: tuple, tx_event=None
    ) -> None:
        heapq.heappush(queue, queue_item)
        self._inc_priority_counter(owner, queue_item[0])
        if tx_event is not None:
            tx_event.set()
