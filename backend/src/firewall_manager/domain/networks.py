"""Canonical IP-network parsing and complete-containment rules."""

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

IpNetwork = IPv4Network | IPv6Network
IpAddress = IPv4Address | IPv6Address


def normalize_ip_value(value: str) -> str:
    """Return a canonical host, network, or ordered same-family address range."""
    stripped = value.strip()
    if stripped.count("-") == 1:
        start_text, end_text = (item.strip() for item in stripped.split("-", 1))
        start = ip_address(start_text)
        end = ip_address(end_text)
        if start.version != end.version or int(start) > int(end):
            raise ValueError("network range endpoints must share a version and be ordered")
        return f"{start}-{end}"
    return str(ip_network(stripped, strict=False)) if "/" in stripped else str(ip_address(stripped))


def normalize_ip_network(value: str) -> str:
    """Return a canonical host or network value, rejecting ranges and invalid text."""
    stripped = value.strip()
    if "/" in stripped:
        return str(ip_network(stripped, strict=False))
    address = ip_address(stripped)
    return str(ip_network(f"{address}/{address.max_prefixlen}"))


def network_is_contained(requested: str, authorized: str) -> bool:
    """Return true only when the complete requested host/network fits in the grant."""

    def bounds(value: str) -> tuple[int, int, int]:
        normalized = normalize_ip_value(value)
        if normalized.count("-") == 1:
            start_text, end_text = normalized.split("-", 1)
            start = ip_address(start_text)
            end = ip_address(end_text)
            return start.version, int(start), int(end)
        network = ip_network(normalized, strict=True)
        return network.version, int(network.network_address), int(network.broadcast_address)

    try:
        requested_version, requested_start, requested_end = bounds(requested)
        authorized_version, authorized_start, authorized_end = bounds(authorized)
    except ValueError:
        return False
    return (
        requested_version == authorized_version
        and authorized_start <= requested_start
        and requested_end <= authorized_end
    )
