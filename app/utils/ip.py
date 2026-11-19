import ipaddress


def validate_ip(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def is_private_ip(value: str | None) -> bool:
    if not value:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return address.is_private or address.is_loopback or address.is_link_local


def is_public_ip(value: str | None) -> bool:
    return bool(value) and not is_private_ip(value)


def is_valid_port(value: object) -> bool:
    try:
        port = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    return 0 <= port <= 65535
