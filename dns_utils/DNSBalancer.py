# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import random


class DNSBalancer:
    def __init__(self, resolvers, strategy):
        self.resolvers = resolvers
        self.strategy = strategy
        self.rr_index = 0
        self.valid_servers = [s for s in resolvers if s.get("is_valid", False)]
        self.valid_servers_count = len(self.valid_servers)
        self.server_stats = {}

    def set_balancers(self, balancers):
        self.resolvers = balancers
        self.valid_servers = [s for s in balancers if s.get("is_valid", False)]
        self.valid_servers_count = len(self.valid_servers)

    def report_success(self, server_key):
        stats = self.server_stats.setdefault(
            server_key, {"sent": 0, "acked": 0, "rtt_sum": 0.0}
        )
        stats["acked"] += 1

    def report_send(self, server_key):
        stats = self.server_stats.setdefault(
            server_key, {"sent": 0, "acked": 0, "rtt_sum": 0.0}
        )
        stats["sent"] += 1

    def get_loss_rate(self, server_key):
        stats = self.server_stats.get(server_key, {})
        sent = stats.get("sent", 0)
        if sent < 5:
            return 0.5
        return 1.0 - (stats.get("acked", 0) / sent)

    def get_best_server(self):
        servers = self.get_unique_servers(1)
        return servers[0] if servers else None

    def get_unique_servers(self, required_count):
        actual_count = min(required_count, self.valid_servers_count)
        if actual_count == 0:
            return []

        if self.strategy == 1:  # Random
            return random.sample(self.valid_servers, actual_count)
        elif self.strategy == 3:  # Least Loss
            scored = sorted(
                self.valid_servers,
                key=lambda s: self.get_loss_rate(f"{s['resolver']}:{s['domain']}"),
            )
            return scored[:actual_count]
        else:  # Round Robin
            selected = []
            for _ in range(actual_count):
                selected.append(self.valid_servers[self.rr_index])
                self.rr_index = (self.rr_index + 1) % self.valid_servers_count
            return selected

    def get_servers_for_stream(self, stream_id, required_count):
        """
        Return a list of servers to use for a given stream.
        If required_count==1, prefer affinity: deterministic selection by stream_id.
        Otherwise fall back to get_unique_servers.
        """
        actual_count = min(required_count, self.valid_servers_count)
        if actual_count == 0:
            return []

        if actual_count == 1:
            # affinity: stable mapping from stream_id to server index
            try:
                idx = hash(stream_id) % self.valid_servers_count
            except Exception:
                idx = self.rr_index % self.valid_servers_count

            if 0 <= idx < self.valid_servers_count:
                return [self.valid_servers[idx]]

        return self.get_unique_servers(required_count)
