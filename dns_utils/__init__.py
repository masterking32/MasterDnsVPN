__all__ = []


def _try_export(name, from_module=None):
    try:
        if from_module:
            mod = __import__(f"dns_utils.{from_module}", fromlist=[name])
            obj = getattr(mod, name)
        else:
            mod = __import__(f"dns_utils.{name}", fromlist=[name])
            obj = getattr(mod, name, mod)
        globals()[name] = obj
        __all__.append(name)
    except Exception:
        pass


_try_export("DnsPacketParser")
_try_export("ARQ")
_try_export("DNSBalancer")
_try_export("PingManager")
