from pathlib import Path

from Cython.Build import cythonize
from setuptools import Extension, setup


def build_dns_utils_extensions() -> list[Extension]:
    base_dir = Path(__file__).resolve().parent
    utils_dir = base_dir / "dns_utils"
    extensions: list[Extension] = []

    for py_file in sorted(utils_dir.glob("*.py")):
        if py_file.name == "__init__.py":
            continue

        module_name = f"dns_utils.{py_file.stem}"
        extensions.append(Extension(module_name, [str(py_file)]))

    return extensions


extensions = build_dns_utils_extensions()

if not extensions:
    raise RuntimeError("No Python modules found in dns_utils for Cython build.")

setup(
    name="dns_utils_cython_build",
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
