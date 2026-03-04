# MasterDnsVPN Config Loader
# Author: MasterkinG32
# Github: https://github.com/masterking32
# Year: 2026

import os
import sys

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        raise ImportError(
            "TOML support requires Python 3.11+ or the 'tomli' package. "
            "Install it with: pip install tomli"
        )


def get_app_dir() -> str:
    """Return the directory of the running executable or main script."""
    if getattr(sys, "frozen", False):
        # Running as a PyInstaller bundle — use the directory of the .exe
        return os.path.dirname(os.path.abspath(sys.executable))
    # Running as a plain Python script — use the directory of the main script
    main_script = sys.argv[0] if sys.argv else ""
    if main_script:
        return os.path.dirname(os.path.abspath(main_script))
    return os.getcwd()


def get_config_path(config_filename: str) -> str:
    """Return the full path to the config file next to the exe/script."""
    return os.path.join(get_app_dir(), config_filename)


def load_config(config_filename: str) -> dict:
    """
    Load configuration from a TOML file located next to the executable or main script.
    Returns an empty dict if the file is not found or cannot be parsed.
    """
    config_path = get_config_path(config_filename)
    if not os.path.isfile(config_path):
        return {}
    try:
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    except Exception as e:
        print(f"[MasterDnsVPN] Failed to parse config file '{config_path}': {e}")
        return {}
