BUILD_VERSION = "dev"


def get_build_version() -> str:
    return str(BUILD_VERSION or "dev").strip() or "dev"
