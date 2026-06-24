import secrets


def _new_scan_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"
