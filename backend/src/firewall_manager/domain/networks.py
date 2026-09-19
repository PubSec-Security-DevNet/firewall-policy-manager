"""Canonical IP-network parsing and complete-containment rules."""

from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

IpNetwork = IPv4Network | IPv6Network


def normalize_ip_network(value: str) -> str:
    """Return a canonical host or network value, rejecting ranges and invalid text."""
    stripped = value.strip()
    if "/" in stripped:
        return str(ip_network(stripped, strict=False))
    address = ip_address(stripped)
    return str(ip_network(f"{address}/{address.max_prefixlen}"))


def network_is_contained(requested: str, authorized: str) -> bool:
    """Return true only when the complete requested host/network fits in the grant."""
    requested_network = ip_network(normalize_ip_network(requested), strict=True)
    authorized_network = ip_network(normalize_ip_network(authorized), strict=True)
    if isinstance(requested_network, IPv4Network) and isinstance(authorized_network, IPv4Network):
        return requested_network.subnet_of(authorized_network)
    if isinstance(requested_network, IPv6Network) and isinstance(authorized_network, IPv6Network):
        return requested_network.subnet_of(authorized_network)
    return False
