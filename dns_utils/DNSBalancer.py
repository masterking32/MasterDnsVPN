import random


class DNSBalancer:
    def __init__(self, resolvers, strategy):
        self.resolvers = resolvers
        self.strategy = strategy
        self.rr_index = 0

    def get_best_server(self):
        servers = self.get_unique_servers(1)
        return servers[0] if servers else None

    def get_unique_servers(self, required_count):
        valid_servers = [s for s in self.resolvers if s.get("is_valid", False)]
        actual_count = min(required_count, len(valid_servers))

        if actual_count == 0:
            return []

        if self.strategy == 1:  # Random
            return random.sample(valid_servers, actual_count)

        elif self.strategy == 2:  # Round Robin
            selected = []
            for _ in range(actual_count):
                selected.append(valid_servers[self.rr_index])
                self.rr_index = (self.rr_index + 1) % len(valid_servers)
            return selected

        elif self.strategy == 3:  # Less Packet Loss
            # Packet Loss
            sorted_servers = sorted(
                valid_servers, key=lambda s: s.get("packet_loss", 0.0)
            )
            return sorted_servers[:actual_count]

        else:  # Fallback (Default)
            return valid_servers[:actual_count]
