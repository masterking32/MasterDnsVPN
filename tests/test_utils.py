"""Tests for dns_utils/utils.py."""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from dns_utils.utils import (
    async_recvfrom,
    async_sendto,
    generate_random_hex_text,
    get_encrypt_key,
    getLogger,
    load_text,
    save_text,
)


# ---------------------------------------------------------------------------
# load_text / save_text
# ---------------------------------------------------------------------------


class TestLoadText:
    def test_load_existing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "hello.txt"
        f.write_text("  hello world  ", encoding="utf-8")
        result = load_text(str(f))
        assert result == "hello world"

    def test_load_missing_file_returns_none(self, tmp_path: Path) -> None:
        result = load_text(str(tmp_path / "nonexistent.txt"))
        assert result is None

    def test_load_strips_whitespace(self, tmp_path: Path) -> None:
        f = tmp_path / "ws.txt"
        f.write_text("\n  content\n\n", encoding="utf-8")
        assert load_text(str(f)) == "content"

    def test_load_empty_file_returns_empty_string(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")
        result = load_text(str(f))
        assert result == ""

    def test_load_returns_none_on_permission_error(self, tmp_path: Path) -> None:
        f = tmp_path / "perm.txt"
        f.write_text("data", encoding="utf-8")
        with patch("builtins.open", side_effect=PermissionError):
            result = load_text(str(f))
        assert result is None


class TestSaveText:
    def test_save_creates_file(self, tmp_path: Path) -> None:
        f = tmp_path / "out.txt"
        result = save_text(str(f), "hello")
        assert result is True
        assert f.read_text(encoding="utf-8") == "hello"

    def test_save_returns_false_on_error(self, tmp_path: Path) -> None:
        with patch("builtins.open", side_effect=PermissionError):
            result = save_text("/invalid/path/file.txt", "content")
        assert result is False

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        f = tmp_path / "roundtrip.txt"
        content = "round trip content"
        assert save_text(str(f), content) is True
        assert load_text(str(f)) == content

    def test_overwrite_existing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "overwrite.txt"
        f.write_text("old content", encoding="utf-8")
        save_text(str(f), "new content")
        assert f.read_text(encoding="utf-8") == "new content"


# ---------------------------------------------------------------------------
# generate_random_hex_text
# ---------------------------------------------------------------------------


class TestGenerateRandomHexText:
    def test_correct_length(self) -> None:
        for length in [16, 24, 32, 8]:
            result = generate_random_hex_text(length)
            assert len(result) == length

    def test_is_hex_string(self) -> None:
        result = generate_random_hex_text(32)
        assert all(c in "0123456789abcdef" for c in result)

    def test_randomness(self) -> None:
        results = {generate_random_hex_text(32) for _ in range(10)}
        assert len(results) > 1

    def test_length_zero(self) -> None:
        result = generate_random_hex_text(0)
        assert result == ""


# ---------------------------------------------------------------------------
# get_encrypt_key
# ---------------------------------------------------------------------------


class TestGetEncryptKey:
    def test_method_3_returns_16_chars(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = get_encrypt_key(3)
        assert len(result) == 16
        assert all(c in "0123456789abcdef" for c in result)

    def test_method_4_returns_24_chars(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = get_encrypt_key(4)
        assert len(result) == 24

    def test_other_method_returns_32_chars(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        result = get_encrypt_key(5)
        assert len(result) == 32

    def test_persists_key_to_disk(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        key1 = get_encrypt_key(5)
        key2 = get_encrypt_key(5)
        assert key1 == key2
        key_file = tmp_path / "encrypt_key.txt"
        assert key_file.exists()

    def test_uses_existing_valid_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        existing_key = "abcdef0123456789abcdef0123456789"  # 32 valid hex chars
        (tmp_path / "encrypt_key.txt").write_text(existing_key, encoding="utf-8")
        result = get_encrypt_key(5)
        assert result == existing_key

    def test_regenerates_key_if_wrong_length(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "encrypt_key.txt").write_text("tooshort", encoding="utf-8")
        result = get_encrypt_key(5)
        assert len(result) == 32


# ---------------------------------------------------------------------------
# getLogger
# ---------------------------------------------------------------------------


class TestGetLogger:
    def test_creates_logger(self) -> None:
        logger = getLogger(log_level="DEBUG")
        assert logger is not None

    def test_server_logger(self) -> None:
        logger = getLogger(log_level="INFO", is_server=True)
        assert logger is not None

    def test_with_log_file(self, tmp_path: Path) -> None:
        log_file = str(tmp_path / "test.log")
        logger = getLogger(log_level="DEBUG", logFile=log_file)
        assert logger is not None


# ---------------------------------------------------------------------------
# async_recvfrom
# ---------------------------------------------------------------------------


class TestAsyncRecvfrom:
    @pytest.mark.asyncio
    async def test_uses_sock_recvfrom_when_available(self) -> None:
        """Uses loop.sock_recvfrom on Python 3.11+."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        expected = (b"data", ("127.0.0.1", 53))

        with patch.object(loop, "sock_recvfrom", new=AsyncMock(return_value=expected)):
            if sys.version_info >= (3, 11):
                result = await async_recvfrom(loop, mock_sock, 512)
                assert result == expected

    @pytest.mark.asyncio
    async def test_fallback_blocking_recvfrom(self) -> None:
        """Falls back to synchronous sock.recvfrom when not blocking."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.recvfrom = MagicMock(return_value=(b"data", ("127.0.0.1", 53)))

        # Simulate loop without sock_recvfrom
        with patch.object(loop, "sock_recvfrom", side_effect=AttributeError):
            with patch("sys.version_info", (3, 10, 0)):
                result = await async_recvfrom(loop, mock_sock, 512)
        assert result == (b"data", ("127.0.0.1", 53))

    @pytest.mark.asyncio
    async def test_blocking_io_error_triggers_future(self) -> None:
        """BlockingIOError on recvfrom triggers reader registration."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)
        mock_sock.recvfrom = MagicMock(side_effect=BlockingIOError)

        add_reader_calls: list = []

        def fake_add_reader(fd, cb):
            add_reader_calls.append((fd, cb))
            # Simulate immediate data available by calling the callback
            cb()

        mock_sock.recvfrom = MagicMock(
            side_effect=[BlockingIOError, (b"late_data", ("1.2.3.4", 53))]
        )

        with patch.object(loop, "sock_recvfrom", side_effect=AttributeError), \
             patch("sys.version_info", (3, 10, 0)), \
             patch.object(loop, "add_reader", side_effect=fake_add_reader), \
             patch.object(loop, "remove_reader"):
            result = await async_recvfrom(loop, mock_sock, 512)
        assert result == (b"late_data", ("1.2.3.4", 53))

    @pytest.mark.asyncio
    async def test_sock_recvfrom_attribute_error_fallback(self) -> None:
        """sock_recvfrom raises AttributeError on 3.11+ falls through to sync."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.recvfrom = MagicMock(return_value=(b"data", ("127.0.0.1", 53)))

        if sys.version_info >= (3, 11):
            with patch.object(loop, "sock_recvfrom", side_effect=AttributeError):
                result = await async_recvfrom(loop, mock_sock, 512)
            assert result == (b"data", ("127.0.0.1", 53))

    @pytest.mark.asyncio
    async def test_sock_recvfrom_not_implemented_fallback(self) -> None:
        """sock_recvfrom raises NotImplementedError on 3.11+ falls through to sync."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.recvfrom = MagicMock(return_value=(b"hello", ("10.0.0.1", 5300)))

        if sys.version_info >= (3, 11):
            with patch.object(loop, "sock_recvfrom", side_effect=NotImplementedError):
                result = await async_recvfrom(loop, mock_sock, 512)
            assert result == (b"hello", ("10.0.0.1", 5300))

    @pytest.mark.asyncio
    async def test_recvfrom_blocking_in_callback_then_success(self) -> None:
        """Callback receives BlockingIOError (line 35 pass) then succeeds on next call."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)

        def fake_add_reader(fd, cb):
            # First cb() call raises BlockingIOError -> pass (line 35)
            # Second cb() call returns data -> resolves future
            mock_sock.recvfrom = MagicMock(
                side_effect=[BlockingIOError, (b"later", ("1.2.3.4", 53))]
            )
            cb()
            cb()

        # Initial recvfrom raises BlockingIOError to reach add_reader path
        mock_sock.recvfrom = MagicMock(side_effect=BlockingIOError)

        with patch.object(loop, "sock_recvfrom", side_effect=AttributeError), \
             patch("sys.version_info", (3, 10, 0)), \
             patch.object(loop, "add_reader", side_effect=fake_add_reader), \
             patch.object(loop, "remove_reader"):
            result = await async_recvfrom(loop, mock_sock, 512)
        assert result == (b"later", ("1.2.3.4", 53))

    @pytest.mark.asyncio
    async def test_recvfrom_cancelled_removes_reader(self) -> None:
        """CancelledError during recvfrom future removes the reader (lines 45-46)."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)
        mock_sock.recvfrom = MagicMock(side_effect=BlockingIOError)
        remove_reader_called: list[int] = []

        async def run_recvfrom():
            with patch.object(loop, "sock_recvfrom", side_effect=AttributeError), \
                 patch("sys.version_info", (3, 10, 0)), \
                 patch.object(loop, "add_reader"), \
                 patch.object(loop, "remove_reader", side_effect=lambda fd: remove_reader_called.append(fd)):
                await async_recvfrom(loop, mock_sock, 512)

        task = asyncio.create_task(run_recvfrom())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(remove_reader_called) > 0


# ---------------------------------------------------------------------------
# async_sendto
# ---------------------------------------------------------------------------


class TestAsyncSendto:
    @pytest.mark.asyncio
    async def test_uses_sock_sendto_when_available(self) -> None:
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()

        with patch.object(loop, "sock_sendto", new=AsyncMock(return_value=5)):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 5

    @pytest.mark.asyncio
    async def test_fallback_sync_sendto(self) -> None:
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.sendto = MagicMock(return_value=4)

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 4

    @pytest.mark.asyncio
    async def test_connection_reset_returns_zero(self) -> None:
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()

        with patch.object(loop, "sock_sendto", side_effect=ConnectionResetError):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 0

    @pytest.mark.asyncio
    async def test_broken_pipe_returns_zero(self) -> None:
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()

        with patch.object(loop, "sock_sendto", side_effect=BrokenPipeError):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 0

    @pytest.mark.asyncio
    async def test_oserror_winerror_ignored(self) -> None:
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        err = OSError("network error")
        err.winerror = 10054

        with patch.object(loop, "sock_sendto", side_effect=err):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 0

    @pytest.mark.asyncio
    async def test_oserror_errno_ignored(self) -> None:
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        err = OSError("broken pipe")
        err.errno = 32

        with patch.object(loop, "sock_sendto", side_effect=err):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 0

    @pytest.mark.asyncio
    async def test_other_oserror_reraises(self) -> None:
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        err = OSError("unexpected error")
        err.errno = 99  # Not in ignore list

        with patch.object(loop, "sock_sendto", side_effect=err):
            with pytest.raises(OSError):
                await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))

    @pytest.mark.asyncio
    async def test_sendto_blocking_io_error_fallback_to_writer(self) -> None:
        """Covers BlockingIOError fallback with add_writer pattern."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)

        write_calls: list = []

        def fake_add_writer(fd: int, cb: object) -> None:
            write_calls.append(fd)
            cb()  # type: ignore[operator]

        mock_sock.sendto = MagicMock(
            side_effect=[BlockingIOError, 5]  # First call blocks, second succeeds
        )

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError), \
             patch.object(loop, "add_writer", side_effect=fake_add_writer), \
             patch.object(loop, "remove_writer"):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 5

    @pytest.mark.asyncio
    async def test_sendto_blocking_io_error_cb_exception_ignored(self) -> None:
        """BlockingIOError in callback with ignorable error."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)

        def fake_add_writer(fd: int, cb: object) -> None:
            # Call cb which raises an ignorable error
            ignored_err = ConnectionResetError("reset")
            ignored_err.errno = 104
            mock_sock.sendto = MagicMock(side_effect=ignored_err)
            cb()  # type: ignore[operator]

        mock_sock.sendto = MagicMock(side_effect=BlockingIOError)

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError), \
             patch.object(loop, "add_writer", side_effect=fake_add_writer), \
             patch.object(loop, "remove_writer"):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 0

    @pytest.mark.asyncio
    async def test_recvfrom_blocking_io_error_exception_in_cb(self) -> None:
        """Exception in recvfrom callback sets future exception."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)

        call_count = 0

        def fake_add_reader(fd: int, cb: object) -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Simulate error in callback
                mock_sock.recvfrom = MagicMock(side_effect=OSError("recv error"))
                cb()  # type: ignore[operator]

        mock_sock.recvfrom = MagicMock(side_effect=BlockingIOError)

        with patch.object(loop, "sock_recvfrom", side_effect=AttributeError), \
             patch("sys.version_info", (3, 10, 0)), \
             patch.object(loop, "add_reader", side_effect=fake_add_reader), \
             patch.object(loop, "remove_reader"):
            with pytest.raises(OSError):
                await async_recvfrom(loop, mock_sock, 512)

    @pytest.mark.asyncio
    async def test_sendto_not_implemented_then_blocking_to_future_error(self) -> None:
        """NotImplementedError on sock_sendto, then blocking, callback sets exception."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)

        def fake_add_writer(fd: int, cb: object) -> None:
            # Callback raises non-ignored error
            unexpected_err = OSError("disk full")
            unexpected_err.errno = 28  # ENOSPC
            mock_sock.sendto = MagicMock(side_effect=unexpected_err)
            cb()  # type: ignore[operator]

        mock_sock.sendto = MagicMock(side_effect=BlockingIOError)

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError), \
             patch.object(loop, "add_writer", side_effect=fake_add_writer), \
             patch.object(loop, "remove_writer"):
            with pytest.raises(OSError):
                await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))

    @pytest.mark.asyncio
    async def test_sendto_sync_fallback_ignored_exception(self) -> None:
        """Sync sendto raises ignored exception (lines 76-78) -> returns 0."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.sendto = MagicMock(side_effect=ConnectionResetError("reset"))

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 0

    @pytest.mark.asyncio
    async def test_sendto_sync_fallback_reraises_unknown_error(self) -> None:
        """Sync sendto raises non-ignored exception after NotImplementedError (line 79)."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        err = OSError("disk full")
        err.errno = 28
        mock_sock.sendto = MagicMock(side_effect=err)

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError):
            with pytest.raises(OSError):
                await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))

    @pytest.mark.asyncio
    async def test_sendto_cb_blocking_io_then_success(self) -> None:
        """Callback BlockingIOError (line 94 pass) then succeeds on second call."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)

        def fake_add_writer(fd: int, cb: object) -> None:
            mock_sock.sendto = MagicMock(side_effect=[BlockingIOError, 5])
            cb()  # type: ignore[operator]  # BlockingIOError -> pass (line 94)
            cb()  # type: ignore[operator]  # Returns 5 -> resolves future

        mock_sock.sendto = MagicMock(side_effect=BlockingIOError)

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError), \
             patch.object(loop, "add_writer", side_effect=fake_add_writer), \
             patch.object(loop, "remove_writer"):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 5

    @pytest.mark.asyncio
    async def test_sendto_cb_remove_writer_raises_on_success(self) -> None:
        """remove_writer raises Exception on success path (lines 89-90 pass)."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)
        remove_writer_mock = MagicMock(side_effect=Exception("writer gone"))

        def fake_add_writer(fd: int, cb: object) -> None:
            mock_sock.sendto = MagicMock(return_value=7)
            with patch.object(loop, "remove_writer", remove_writer_mock):
                cb()  # type: ignore[operator]

        mock_sock.sendto = MagicMock(side_effect=BlockingIOError)

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError), \
             patch.object(loop, "add_writer", side_effect=fake_add_writer), \
             patch.object(loop, "remove_writer"):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 7

    @pytest.mark.asyncio
    async def test_sendto_cb_remove_writer_raises_on_error(self) -> None:
        """remove_writer raises Exception in error callback path (lines 98-99 pass)."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)
        remove_writer_mock = MagicMock(side_effect=Exception("writer gone"))
        ignored_err = ConnectionResetError("reset")

        def fake_add_writer(fd: int, cb: object) -> None:
            mock_sock.sendto = MagicMock(side_effect=ignored_err)
            with patch.object(loop, "remove_writer", remove_writer_mock):
                cb()  # type: ignore[operator]

        mock_sock.sendto = MagicMock(side_effect=BlockingIOError)

        with patch.object(loop, "sock_sendto", side_effect=NotImplementedError), \
             patch.object(loop, "add_writer", side_effect=fake_add_writer), \
             patch.object(loop, "remove_writer"):
            result = await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))
        assert result == 0

    @pytest.mark.asyncio
    async def test_sendto_cancelled_removes_writer(self) -> None:
        """CancelledError during sendto future removes the writer (lines 113-117)."""
        loop = asyncio.get_event_loop()
        mock_sock = MagicMock()
        mock_sock.fileno = MagicMock(return_value=10)
        mock_sock.sendto = MagicMock(side_effect=BlockingIOError)
        remove_writer_called: list[int] = []

        async def run_sendto():
            with patch.object(loop, "sock_sendto", side_effect=NotImplementedError), \
                 patch.object(loop, "add_writer"), \
                 patch.object(loop, "remove_writer", side_effect=lambda fd: remove_writer_called.append(fd)):
                await async_sendto(loop, mock_sock, b"data", ("127.0.0.1", 53))

        task = asyncio.create_task(run_sendto())
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(remove_writer_called) > 0


# ---------------------------------------------------------------------------
# Hypothesis property-based tests
# ---------------------------------------------------------------------------


class TestHypothesisUtils:
    @given(st.integers(min_value=0, max_value=128).map(lambda n: n * 2))
    def test_generate_random_hex_length_property(self, length: int) -> None:
        # generate_random_hex_text uses secrets.token_hex(length // 2), so
        # only even lengths are guaranteed to match exactly.
        result = generate_random_hex_text(length)
        assert len(result) == length

    @given(st.integers(min_value=0, max_value=64).map(lambda n: n * 2))
    def test_generate_random_hex_is_lowercase_hex(self, length: int) -> None:
        result = generate_random_hex_text(length)
        assert all(c in "0123456789abcdef" for c in result)

    @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\r"), min_size=0, max_size=512))
    @settings(max_examples=50)
    def test_save_load_roundtrip_property(self, content: str) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "prop_test.txt"
            save_text(str(f), content)
            loaded = load_text(str(f))
            assert loaded == content.strip()

    @given(st.binary(min_size=0, max_size=64).map(lambda b: b.hex()))
    @settings(max_examples=50)
    def test_save_load_hex_content_roundtrip(self, content: str) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "hex_test.txt"
            save_text(str(f), content)
            loaded = load_text(str(f))
            assert loaded == content.strip()
