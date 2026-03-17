# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import heapq

from .DNS_ENUMS import Packet_Type


class PacketQueueMixin:
    """Shared queue/priority bookkeeping for client and server packet schedulers."""

    # These packet types always bypass caller-provided priority and are sent ASAP.
    _PRIORITY_ZERO_TYPES = {
        Packet_Type.STREAM_DATA_ACK,
        Packet_Type.STREAM_RST,
        Packet_Type.STREAM_RST_ACK,
        Packet_Type.STREAM_FIN_ACK,
        Packet_Type.STREAM_SYN_ACK,
        Packet_Type.SOCKS5_SYN_ACK,
    }
    # SYN-family packets keep extra per-type tracking so only one copy stays queued.
    _SYN_TRACK_TYPES = {
        Packet_Type.STREAM_SYN,
        Packet_Type.STREAM_SYN_ACK,
    }
    # These control packets should exist at most once per queue owner until popped.
    _SINGLE_INSTANCE_QUEUE_TYPES = {
        Packet_Type.STREAM_FIN,
        Packet_Type.STREAM_RST,
        Packet_Type.STREAM_RST_ACK,
        Packet_Type.STREAM_FIN_ACK,
        Packet_Type.STREAM_SYN,
        Packet_Type.STREAM_SYN_ACK,
    }
    # These packets may appear multiple times over a stream lifetime, but only one
    # queued copy per (packet_type, sequence_num) is useful at a time.
    _SEQ_KEYED_QUEUE_TYPES = {
        Packet_Type.STREAM_KEEPALIVE,
        Packet_Type.STREAM_KEEPALIVE_ACK,
        Packet_Type.STREAM_WINDOW_UPDATE,
        Packet_Type.STREAM_WINDOW_UPDATE_ACK,
        Packet_Type.STREAM_PROBE,
        Packet_Type.STREAM_PROBE_ACK,
        Packet_Type.SOCKS5_CONNECT_FAIL,
        Packet_Type.SOCKS5_CONNECT_FAIL_ACK,
        Packet_Type.SOCKS5_RULESET_DENIED,
        Packet_Type.SOCKS5_RULESET_DENIED_ACK,
        Packet_Type.SOCKS5_NETWORK_UNREACHABLE,
        Packet_Type.SOCKS5_NETWORK_UNREACHABLE_ACK,
        Packet_Type.SOCKS5_HOST_UNREACHABLE,
        Packet_Type.SOCKS5_HOST_UNREACHABLE_ACK,
        Packet_Type.SOCKS5_CONNECTION_REFUSED,
        Packet_Type.SOCKS5_CONNECTION_REFUSED_ACK,
        Packet_Type.SOCKS5_TTL_EXPIRED,
        Packet_Type.SOCKS5_TTL_EXPIRED_ACK,
        Packet_Type.SOCKS5_COMMAND_UNSUPPORTED,
        Packet_Type.SOCKS5_COMMAND_UNSUPPORTED_ACK,
        Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED,
        Packet_Type.SOCKS5_ADDRESS_TYPE_UNSUPPORTED_ACK,
        Packet_Type.SOCKS5_AUTH_FAILED,
        Packet_Type.SOCKS5_AUTH_FAILED_ACK,
        Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE,
        Packet_Type.SOCKS5_UPSTREAM_UNAVAILABLE_ACK,
    }
    # Fragment-aware / payload-keyed packets: keep exact duplicates out of the queue
    # without collapsing distinct fragments or per-fragment ACK payloads together.
    _FRAGMENT_KEYED_QUEUE_TYPES = {
        Packet_Type.SOCKS5_SYN,
        Packet_Type.SOCKS5_SYN_ACK,
    }
    # These packet types are never meant to live in tx queues directly.
    _DROP_QUEUE_TYPES = {
        Packet_Type.PACKED_CONTROL_BLOCKS,
        Packet_Type.ERROR_DROP,
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
        # Keep a cheap "does this queue have priority X?" index for dequeue logic.
        counters = owner.setdefault("priority_counts", {})
        p = int(priority)
        counters[p] = counters.get(p, 0) + 1

    def _dec_priority_counter(self, owner: dict, priority: int) -> None:
        # Mirror _inc_priority_counter so the index stays exact after pops/transfers.
        counters = owner.get("priority_counts")
        if not counters:
            return
        p = int(priority)
        cur = counters.get(p, 0)
        if cur <= 1:
            counters.pop(p, None)
        else:
            counters[p] = cur - 1

    def _owner_track_key(self, owner: dict, stream_id: int, value: int):
        # Stream-local owners already isolate tracking by stream_id, but session/main
        # queue tracking must include stream_id so stream 1 and stream 2 do not block
        # each other when they both enqueue the same packet type or sequence number.
        sid = int(stream_id)
        if "stream_id" in owner or sid <= 0:
            return value
        return (sid, value)

    def _payload_track_value(self, payload) -> bytes:
        # Payload-keyed dedupe is only used for small fragment/control packets.
        if not payload:
            return b""
        return payload if isinstance(payload, bytes) else bytes(payload)

    def _release_tracking_on_pop(
        self, owner: dict, packet_type: int, stream_id: int, sn: int
    ) -> None:
        # Every successful pop must release the same dedupe markers that were set at
        # enqueue time; otherwise future legitimate retransmits would be suppressed.
        ptype = int(packet_type)
        sn_key = self._owner_track_key(owner, stream_id, sn)
        ptype_key = self._owner_track_key(owner, stream_id, ptype)
        if ptype == Packet_Type.STREAM_DATA:
            track_data = owner.get("track_data")
            if track_data is not None:
                track_data.discard(sn_key)
                if sn_key != sn:
                    track_data.discard(sn)
        elif ptype == Packet_Type.STREAM_DATA_ACK:
            track_ack = owner.get("track_ack")
            if track_ack is not None:
                track_ack.discard(sn_key)
                if sn_key != sn:
                    track_ack.discard(sn)
        elif ptype == Packet_Type.STREAM_RESEND:
            track_resend = owner.get("track_resend")
            if track_resend is not None:
                track_resend.discard(sn_key)
                if sn_key != sn:
                    track_resend.discard(sn)
        elif ptype == Packet_Type.STREAM_FIN:
            track_fin = owner.get("track_fin")
            if track_fin is not None:
                track_fin.discard(ptype)
            track_types = owner.get("track_types")
            if track_types is not None:
                track_types.discard(ptype_key)
                if ptype_key != ptype:
                    track_types.discard(ptype)
        elif ptype in (
            Packet_Type.STREAM_RST,
            Packet_Type.STREAM_RST_ACK,
            Packet_Type.STREAM_FIN_ACK,
        ):
            track_types = owner.get("track_types")
            if track_types is not None:
                track_types.discard(ptype_key)
                if ptype_key != ptype:
                    track_types.discard(ptype)
        elif ptype in self._SYN_TRACK_TYPES:
            track_syn_ack = owner.get("track_syn_ack")
            if track_syn_ack is not None:
                track_syn_ack.discard(ptype)
            track_types = owner.get("track_types")
            if track_types is not None:
                track_types.discard(ptype_key)
                if ptype_key != ptype:
                    track_types.discard(ptype)
        elif ptype in self._SEQ_KEYED_QUEUE_TYPES:
            track_seq_packets = owner.get("track_seq_packets")
            if track_seq_packets is not None:
                seq_key = self._owner_track_key(owner, stream_id, (ptype, int(sn)))
                track_seq_packets.discard(seq_key)
                if seq_key != (ptype, int(sn)):
                    track_seq_packets.discard((ptype, int(sn)))

    def _on_queue_pop(self, owner: dict, queue_item: tuple) -> None:
        # A heap pop changes both the priority index and the packet-type tracking sets.
        priority, _, ptype, stream_id, sn, data = queue_item
        self._dec_priority_counter(owner, priority)
        if int(ptype) in self._FRAGMENT_KEYED_QUEUE_TYPES:
            track_fragment_packets = owner.get("track_fragment_packets")
            if track_fragment_packets is not None:
                frag_value = (
                    int(ptype),
                    int(sn),
                    self._payload_track_value(data),
                )
                frag_key = self._owner_track_key(owner, stream_id, frag_value)
                track_fragment_packets.discard(frag_key)
                if frag_key != frag_value:
                    track_fragment_packets.discard(frag_value)
        self._release_tracking_on_pop(owner, ptype, stream_id, sn)

    def _pop_packable_control_block(
        self,
        queue,
        owner: dict,
        priority: int,
    ):
        # Packing only consumes the queue head to preserve per-queue ordering.
        if not queue:
            return None
        item = queue[0]
        if int(item[0]) != int(priority):
            return None
        ptype = int(item[2])
        payload = item[5]
        # Only payload-less control packets are safe to coalesce into a packed block.
        if ptype not in self._packable_control_types or payload:
            return None
        popped = heapq.heappop(queue)
        self._on_queue_pop(owner, popped)
        return popped

    def _owner_has_priority(self, owner: dict, priority: int) -> bool:
        # Fast negative check used by dequeue/packing so we can skip whole queues.
        counters = owner.get("priority_counts")
        if not counters:
            return False
        return counters.get(int(priority), 0) > 0

    def _resolve_arq_packet_type(self, **flags) -> int:
        # Legacy ARQ callers still pass boolean flags; normalize them once here.
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
        # Some control packets always override caller priority to keep protocol state
        # converging quickly even if data traffic is backed up.
        ptype = int(packet_type)
        eff = int(priority)
        if ptype in self._PRIORITY_ZERO_TYPES:
            return 0
        if ptype == Packet_Type.STREAM_FIN:
            return 4
        if ptype == Packet_Type.STREAM_RESEND:
            return 1
        return eff

    def _track_main_packet_once(
        self, owner: dict, stream_id: int, ptype: int, sn: int, payload=b""
    ) -> bool:
        if ptype in self._DROP_QUEUE_TYPES:
            return False

        # The main queue is shared by the whole session, so all dedupe keys must be
        # stream-aware unless they truly belong to stream 0 / session-wide traffic.
        sn_key = self._owner_track_key(owner, stream_id, sn)
        ptype_key = self._owner_track_key(owner, stream_id, ptype)

        if ptype == Packet_Type.STREAM_RESEND:
            # Never queue a resend request while the original DATA is still queued,
            # and never queue duplicate resend requests for the same stream/sn.
            track_data = owner.get("track_data")
            if track_data is not None and (sn_key in track_data or sn in track_data):
                return False
            track_resend = owner.setdefault("track_resend", set())
            if sn_key in track_resend or sn in track_resend:
                return False
            track_resend.add(sn_key)
            return True
        if ptype in self._SINGLE_INSTANCE_QUEUE_TYPES:
            # FIN/RST/SYN-style control packets are single-instance until popped.
            track_types = owner.setdefault("track_types", set())
            if ptype_key in track_types or ptype in track_types:
                return False
            track_types.add(ptype_key)
            return True
        if ptype == Packet_Type.STREAM_DATA_ACK:
            # ACKs are keyed by sequence number so the same ack does not pile up.
            track_ack = owner.setdefault("track_ack", set())
            if sn_key in track_ack or sn in track_ack:
                return False
            track_ack.add(sn_key)
            return True
        if ptype in self._SEQ_KEYED_QUEUE_TYPES:
            track_seq_packets = owner.setdefault("track_seq_packets", set())
            seq_value = (ptype, int(sn))
            seq_key = self._owner_track_key(owner, stream_id, seq_value)
            if seq_key in track_seq_packets or seq_value in track_seq_packets:
                return False
            track_seq_packets.add(seq_key)
            return True
        if ptype in self._FRAGMENT_KEYED_QUEUE_TYPES:
            track_fragment_packets = owner.setdefault("track_fragment_packets", set())
            frag_value = (
                ptype,
                int(sn),
                self._payload_track_value(payload),
            )
            frag_key = self._owner_track_key(owner, stream_id, frag_value)
            if (
                frag_key in track_fragment_packets
                or frag_value in track_fragment_packets
            ):
                return False
            track_fragment_packets.add(frag_key)
            return True
        if ptype == Packet_Type.STREAM_DATA:
            # DATA and RESEND are mutually exclusive per stream/sn while queued.
            track_resend = owner.get("track_resend")
            if track_resend is not None and (
                sn_key in track_resend or sn in track_resend
            ):
                return False
            track_data = owner.setdefault("track_data", set())
            if sn_key in track_data or sn in track_data:
                return False
            track_data.add(sn_key)
            return True
        return True

    def _track_stream_packet_once(
        self,
        stream_data: dict,
        ptype: int,
        sn: int,
        data_packet_types=(Packet_Type.STREAM_DATA,),
        payload=b"",
    ) -> bool:
        if ptype in self._DROP_QUEUE_TYPES:
            return False
        # Stream-local queues can track raw sequence/type values because stream_id is
        # already implicit in the owner dict.
        track_types = stream_data.setdefault("track_types", set())
        track_ack = stream_data.setdefault("track_ack", set())
        track_fin = stream_data.setdefault("track_fin", set())
        track_syn_ack = stream_data.setdefault("track_syn_ack", set())
        track_data = stream_data.setdefault("track_data", set())
        track_resend = stream_data.setdefault("track_resend", set())
        track_seq_packets = stream_data.setdefault("track_seq_packets", set())
        track_fragment_packets = stream_data.setdefault("track_fragment_packets", set())

        if ptype == Packet_Type.STREAM_RESEND:
            # Do not ask for resend if DATA is still waiting to be sent.
            if sn in track_data or sn in track_resend:
                return False
            track_resend.add(sn)
            return True
        if ptype in self._SINGLE_INSTANCE_QUEUE_TYPES:
            # Single-instance control packets should not stack up in one stream queue.
            if ptype in track_types:
                return False
            track_types.add(ptype)
            if ptype == Packet_Type.STREAM_FIN:
                track_fin.add(ptype)
            elif ptype == Packet_Type.STREAM_SYN_ACK:
                track_syn_ack.add(ptype)
            return True
        if ptype == Packet_Type.STREAM_DATA_ACK:
            if sn in track_ack:
                return False
            track_ack.add(sn)
            return True
        if ptype in self._SEQ_KEYED_QUEUE_TYPES:
            seq_key = (ptype, int(sn))
            if seq_key in track_seq_packets:
                return False
            track_seq_packets.add(seq_key)
            return True
        if ptype in self._FRAGMENT_KEYED_QUEUE_TYPES:
            frag_key = (
                ptype,
                int(sn),
                self._payload_track_value(payload),
            )
            if frag_key in track_fragment_packets:
                return False
            track_fragment_packets.add(frag_key)
            return True
        if ptype in data_packet_types:
            # Prevent the queue from holding both DATA and RESEND for the same sn.
            if sn in track_data or sn in track_resend:
                return False
            track_data.add(sn)
            return True
        return True

    def _push_queue_item(
        self, queue, owner: dict, queue_item: tuple, tx_event=None
    ) -> None:
        # Centralized push path so heap state, priority counters, and wakeups stay in sync.
        heapq.heappush(queue, queue_item)
        self._inc_priority_counter(owner, queue_item[0])
        if tx_event is not None:
            tx_event.set()
