from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [
    Extension("dns_utils.DnsPacketParser", ["dns_utils/DnsPacketParser.py"]),
    Extension("dns_utils.ARQ", ["dns_utils/ARQ.py"]),
    Extension("dns_utils.DNSBalancer", ["dns_utils/DNSBalancer.py"]),
    Extension("dns_utils.PingManager", ["dns_utils/PingManager.py"]),
]

setup(
    ext_modules=cythonize(
        extensions,
        compiler_directives={"language_level": "3"},
    )
)
