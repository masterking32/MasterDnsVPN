# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

from loguru import logger
import sys
from typing import Optional
import secrets
import asyncio
import socket


async def async_recvfrom(loop, sock: socket.socket, nbytes: int):
    """Backwards compatible async UDP receive for Python < 3.11"""
    if hasattr(loop, "sock_recvfrom"):
        return await loop.sock_recvfrom(sock, nbytes)

    try:
        return sock.recvfrom(nbytes)
    except BlockingIOError:
        pass

    future = loop.create_future()
    fd = sock.fileno()

    def cb():
        try:
            data, addr = sock.recvfrom(nbytes)
            loop.remove_reader(fd)
            if not future.done():
                future.set_result((data, addr))
        except BlockingIOError:
            pass
        except Exception as e:
            loop.remove_reader(fd)
            if not future.done():
                future.set_exception(e)

    loop.add_reader(fd, cb)
    try:
        return await future
    except asyncio.CancelledError:
        loop.remove_reader(fd)
        raise


async def async_sendto(loop, sock: socket.socket, data: bytes, addr):
    """Backwards compatible async UDP send for Python < 3.11"""
    if hasattr(loop, "sock_sendto"):
        return await loop.sock_sendto(sock, data, addr)

    try:
        return sock.sendto(data, addr)
    except BlockingIOError:
        pass

    future = loop.create_future()
    fd = sock.fileno()

    def cb():
        try:
            sent = sock.sendto(data, addr)
            loop.remove_writer(fd)
            if not future.done():
                future.set_result(sent)
        except BlockingIOError:
            pass
        except Exception as e:
            loop.remove_writer(fd)
            if not future.done():
                future.set_exception(e)

    loop.add_writer(fd, cb)
    try:
        return await future
    except asyncio.CancelledError:
        loop.remove_writer(fd)
        raise


def load_text(file_path: str) -> Optional[str]:
    """
    Load and return the contents of a text file, stripped of leading/trailing whitespace.
    Returns None if the file does not exist or error occurs.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return file.read().strip()
    except FileNotFoundError:
        return None
    except Exception:
        return None


def save_text(file_path: str, text: str) -> bool:
    """
    Save the given text to a file. Returns True on success, False otherwise.
    """
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(text)
        return True
    except Exception:
        return False


def get_encrypt_key(method_id: int) -> str:
    """
    Retrieve or generate an encryption key of appropriate length based on method_id.
    method_id: 3 -> 16 chars, 4 -> 24 chars, else 32 chars.
    Returns the key as a hex string.
    """
    if method_id == 3:
        length = 16
    elif method_id == 4:
        length = 24
    else:
        length = 32
    key_path = "encrypt_key.txt"
    random_key = load_text(key_path)
    if not random_key or len(random_key) != length:
        random_key = generate_random_hex_text(length)
        save_text(key_path, random_key)
    return random_key


def generate_random_hex_text(length: int) -> str:
    """
    Generate a random hexadecimal string of the specified length.
    """
    return secrets.token_hex(length // 2)


def getLogger(
    log_level: str = "DEBUG",
    logFile: str = None,
    max_log_size: int = 1,
    backup_count: int = 3,
    is_server: bool = True,
):
    # ---------------------------------------------#
    # Logging configuration
    LOG_LEVEL = log_level.upper()
    appName = "MasterDnsVPN Server" if is_server else "MasterDnsVPN Client"
    log_format = f"<cyan>[{appName}]</cyan> <green>[{{time:HH:mm:ss}}]</green> <level>[{{level}}]</level> <white><b>{{message}}</b></white>"

    logger.remove()
    logger.add(
        sink=sys.stdout,
        level=LOG_LEVEL,
        format=log_format,
        colorize=True,
    )

    if logFile:
        log_file_format = f"[{appName}] [{{time:HH:mm:ss}}] [{{level}}] {{message}}"

        logger.add(
            logFile,
            level=LOG_LEVEL,
            format=log_file_format,
            rotation=max_log_size * 1024 * 1024,
            retention=backup_count,
            encoding="utf-8",
            colorize=True,
        )

    logger_final = logger.opt(colors=True)
    return logger_final
