from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup


def build_extensions() -> list[Extension]:
    base_dir = Path(__file__).resolve().parent
    utils_dir = base_dir / "dns_utils"
    extensions: list[Extension] = []

    # Compile package modules.
    for py_file in sorted(utils_dir.glob("*.py")):
        if py_file.name == "__init__.py":
            continue
        module_name = f"dns_utils.{py_file.stem}"
        extensions.append(Extension(module_name, [str(py_file)]))

    # Compile top-level runtime modules.
    for entry_name in ("client.py", "server.py"):
        entry_path = base_dir / entry_name
        if entry_path.is_file():
            module_name = entry_path.stem
            extensions.append(Extension(module_name, [str(entry_path)]))

    return extensions


extensions = build_extensions()
if not extensions:
    raise RuntimeError("No Python modules found for Cython build.")

setup(
    name="masterdnsvpn_cython_build",
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
            "nonecheck": False,
        },
        annotate=False,
    ),
)
