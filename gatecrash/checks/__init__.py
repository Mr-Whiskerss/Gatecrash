"""Check registry - importing this package registers every built-in check."""
from .base import REGISTRY, Check, register       # noqa: F401
from . import passive          # noqa: F401
from . import authz           # noqa: F401
from . import misconfig       # noqa: F401
from . import jwt             # noqa: F401
from . import ssrf            # noqa: F401
from . import inventory       # noqa: F401
from . import bizflow         # noqa: F401


def all_checks():
    return dict(REGISTRY)


def select(profile: str, only=None, skip=None):
    """Return check classes enabled for `profile`, honouring --only / --skip."""
    only = set(only or [])
    skip = set(skip or [])
    out = []
    for check_id, cls in sorted(REGISTRY.items()):
        if only and check_id not in only and not any(
                check_id.startswith(o.rstrip("*")) for o in only):
            continue
        if check_id in skip or any(check_id.startswith(s.rstrip("*")) for s in skip if s.endswith("*")):
            continue
        if not only and profile not in cls.profiles:
            continue
        out.append(cls)
    return out
