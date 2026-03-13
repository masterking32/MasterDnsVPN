"""MasterDnsVPN payload compression helpers."""

import zlib

try:
    import zstandard as zstd

    ZSTD_AVAILABLE = True
except ImportError:  # pragma: no cover
    ZSTD_AVAILABLE = False  # pragma: no cover

try:
    import lz4.block as lz4block

    LZ4_AVAILABLE = True
except ImportError:  # pragma: no cover
    LZ4_AVAILABLE = False  # pragma: no cover


class Compression_Type:
    OFF = 0
    ZSTD = 1
    LZ4 = 2
    ZLIB = 3


SUPPORTED_COMPRESSION_TYPES = (
    Compression_Type.OFF,
    Compression_Type.ZSTD,
    Compression_Type.LZ4,
    Compression_Type.ZLIB,
)

_COMPRESSION_NAME = {
    Compression_Type.OFF: "OFF",
    Compression_Type.ZSTD: "ZSTD",
    Compression_Type.LZ4: "LZ4",
    Compression_Type.ZLIB: "ZLIB",
}

# Reuse codec instances to avoid per-packet allocations.
_ZSTD_COMPRESSOR = zstd.ZstdCompressor(level=1) if ZSTD_AVAILABLE else None
_ZSTD_DECOMPRESSOR = zstd.ZstdDecompressor() if ZSTD_AVAILABLE else None


def normalize_compression_type(compression_type: int) -> int:
    ctype = int(compression_type or 0)
    if ctype in SUPPORTED_COMPRESSION_TYPES:
        return ctype
    return Compression_Type.OFF


def get_compression_name(compression_type: int) -> str:
    return _COMPRESSION_NAME.get(compression_type, "UNKNOWN")


def is_compression_type_available(comp_type: int) -> bool:
    if comp_type == Compression_Type.ZLIB:
        return True
    if comp_type == Compression_Type.ZSTD:
        return ZSTD_AVAILABLE
    if comp_type == Compression_Type.LZ4:
        return LZ4_AVAILABLE
    return False


def compress_payload(
    data: bytes, comp_type: int, min_size: int = 100
) -> tuple[bytes, int]:
    """
    Compress payload only when useful.
    Returns: (processed_data, actual_compression_type_used)
    """
    if not data:
        return data, Compression_Type.OFF

    if comp_type == Compression_Type.OFF:
        return data, Compression_Type.OFF

    if len(data) <= min_size:
        return data, Compression_Type.OFF

    if not is_compression_type_available(comp_type):
        return data, Compression_Type.OFF

    try:
        if comp_type == Compression_Type.ZLIB:
            comp_obj = zlib.compressobj(level=1, wbits=-15)
            comp_data = comp_obj.compress(data) + comp_obj.flush()
        elif comp_type == Compression_Type.ZSTD:
            comp_data = _ZSTD_COMPRESSOR.compress(data)
        elif comp_type == Compression_Type.LZ4:
            comp_data = lz4block.compress(data, store_size=True)
        else:
            return data, Compression_Type.OFF

        # Keep compressed form only when strictly smaller.
        if len(comp_data) < len(data):
            return comp_data, comp_type
    except Exception:
        pass

    return data, Compression_Type.OFF


def try_decompress_payload(data: bytes, comp_type: int) -> tuple[bytes, bool]:
    """
    Try to decompress payload.
    Returns: (payload, success)
    """
    if not data or comp_type == Compression_Type.OFF:
        return data, True

    if not is_compression_type_available(comp_type):
        return b"", False

    try:
        if comp_type == Compression_Type.ZLIB:
            dec = zlib.decompressobj(wbits=-15)
            out = dec.decompress(data)
            # Accept only complete, fully-consumed raw DEFLATE frames.
            if not dec.eof or dec.unused_data:
                return b"", False
            tail = dec.flush()
            if tail:
                out += tail
            return out, True
        if comp_type == Compression_Type.ZSTD:
            return _ZSTD_DECOMPRESSOR.decompress(data), True
        if comp_type == Compression_Type.LZ4:
            return lz4block.decompress(data), True
    except Exception:
        pass

    return b"", False


def decompress_payload(data: bytes, comp_type: int) -> bytes:
    """Backward-compatible decompression helper."""
    out, ok = try_decompress_payload(data, comp_type)
    return out if ok else data
