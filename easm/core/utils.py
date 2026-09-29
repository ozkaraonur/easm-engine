import re

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")


def normalize_domain(value: str) -> str:
    """Lowercase, strip scheme/path/port/trailing dot; raise ValueError if invalid."""
    domain = value.strip().lower()
    domain = re.sub(r"^[a-z][a-z0-9+.-]*://", "", domain)
    domain = domain.split("/", 1)[0].split(":", 1)[0].rstrip(".")
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain: {value!r}")
    return domain


def is_in_scope(hostname: str, domain: str) -> bool:
    """True if hostname is the domain itself or a subdomain of it."""
    return hostname == domain or hostname.endswith(f".{domain}")
