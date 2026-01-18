# MasterDnsVPN Server
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import json
from loguru import logger
import sys


def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)


def getLogger(log_level="DEBUG", logFile=None, max_log_size=1, backup_count=3):
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


# # Regular Text Colors
bl = "\033[30m"  # black
r = "\033[31m"  # red
g = "\033[32m"  # green
y = "\033[33m"  # yellow
b = "\033[34m"  # blue
m = "\033[35m"  # magenta
c = "\033[36m"  # cyan
w = "\033[37m"  # white

# Bright Text Colors
blt = "\033[90m"  # black_bright
rt = "\033[91m"  # red_bright
gt = "\033[92m"  # green_bright
yt = "\033[93m"  # yellow_bright
bt = "\033[94m"  # blue_bright
mt = "\033[95m"  # magenta_bright
ct = "\033[96m"  # cyan_bright
wt = "\033[97m"  # white_bright

# Bold Text Colors
blb = "\033[1;30m"  # black_bold
rb = "\033[1;31m"  # red_bold
gb = "\033[1;32m"  # green_bold
yb = "\033[1;33m"  # yellow_bold
bb = "\033[1;34m"  # blue_bold
mb = "\033[1;35m"  # magenta_bold
cb = "\033[1;36m"  # cyan_bold
wb = "\033[1;37m"  # white_bold

# Reset Color
rs = "\033[0m"
