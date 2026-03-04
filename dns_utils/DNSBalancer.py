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

    def set_balancers(self, balancers):
        self.resolvers = balancers
        self.valid_servers = [s for s in balancers if s.get("is_valid", False)]
        self.valid_servers_count = len(self.valid_servers)

    def get_best_server(self):
        servers = self.get_unique_servers(1)
        return servers[0] if servers else None

    def get_unique_servers(self, required_count):
        actual_count = min(required_count, self.valid_servers_count)

        if actual_count == 0:
            return []

        if self.strategy == 1:  # Random
            return random.sample(self.valid_servers, actual_count)
        else:  # Round Robin
            selected = []
            for _ in range(actual_count):
                selected.append(self.valid_servers[self.rr_index])
                self.rr_index = (self.rr_index + 1) % self.valid_servers_count
            return selected
