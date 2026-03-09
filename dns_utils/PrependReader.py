# MasterDnsVPN
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026
import asyncio


class PrependReader:
    """Wraps an asyncio.StreamReader to prepend initial data (like SOCKS5 target) before reading from the actual socket."""

    def __init__(self, original_reader: asyncio.StreamReader, initial_data: bytes):
        self.reader = original_reader
        self.initial_data = initial_data

    async def read(self, n: int = -1) -> bytes:
        if self.initial_data:
            if n > 0 and len(self.initial_data) > n:
                chunk = self.initial_data[:n]
                self.initial_data = self.initial_data[n:]
                return chunk
            else:
                chunk = self.initial_data
                self.initial_data = b""
                return chunk
        return await self.reader.read(n)
