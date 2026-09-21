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
    authorized_network = ip_network(normalize_ip_network(authorized), strict=True)
    normalized_requested = normalize_ip_value(requested)
    if normalized_requested.count("-") == 1:
        start_text, end_text = normalized_requested.split("-", 1)
        endpoints: tuple[IpAddress, IpAddress] = (ip_address(start_text), ip_address(end_text))
        return all(
            endpoint.version == authorized_network.version and endpoint in authorized_network
            for endpoint in endpoints
        )
    requested_network = ip_network(normalize_ip_network(normalized_requested), strict=True)
    if isinstance(requested_network, IPv4Network) and isinstance(authorized_network, IPv4Network):
        return requested_network.subnet_of(authorized_network)
    if isinstance(requested_network, IPv6Network) and isinstance(authorized_network, IPv6Network):
        return requested_network.subnet_of(authorized_network)
    return False
