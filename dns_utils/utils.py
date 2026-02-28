# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

from loguru import logger
import sys
from typing import Optional
import secrets


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
):
    # ---------------------------------------------#
    # Logging configuration
    LOG_LEVEL = log_level.upper()
    log_format = f"<cyan>[DNSTT Python]</cyan> <green>[{{time:HH:mm:ss}}]</green> <level>[{{level}}]</level> <white><b>{{message}}</b></white>"

    logger.remove()
    logger.add(
        sink=sys.stdout,
        level=LOG_LEVEL,
        format=log_format,
        colorize=True,
    )

    if logFile:
        log_file_format = "[DNSTT Python] [{time:HH:mm:ss}] [{level}] {message}"

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
