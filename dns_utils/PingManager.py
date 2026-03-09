# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import asyncio
import time


class PingManager:
    def __init__(self, send_func):
        self.send_func = send_func
        self.last_data_activity = time.monotonic()
        self.last_ping_time = self.last_data_activity
        self.active_connections = 0

    def update_activity(self):
        self.last_data_activity = time.monotonic()

    async def ping_loop(self):
        _sleep = asyncio.sleep
        _monotonic = time.monotonic
        _send_func = self.send_func

        while True:
            now = _monotonic()
            idle_time = now - self.last_data_activity

            if self.active_connections == 0 and idle_time > 20.0:
                ping_interval = 10.0
                max_sleep = 1.0
            elif idle_time >= 10.0:
                ping_interval = 3.0
                max_sleep = 0.5
            elif idle_time >= 5.0:
                ping_interval = 1.0
                max_sleep = 0.2
            else:
                ping_interval = 0.2
                max_sleep = 0.18

            time_since_last_ping = now - self.last_ping_time

            if time_since_last_ping >= ping_interval:
                _send_func()
                self.last_ping_time = _monotonic()
                time_to_sleep = ping_interval
            else:
                time_to_sleep = ping_interval - time_since_last_ping

            actual_sleep = time_to_sleep if time_to_sleep < max_sleep else max_sleep
            if actual_sleep > 0:
                await _sleep(actual_sleep)
