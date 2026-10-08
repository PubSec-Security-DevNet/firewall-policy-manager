# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Provider-neutral delegated-management domain behavior."""

import pytest

from firewall_manager.domain.models import DiscoveredObject, FirewallObjectType
from firewall_manager.domain.networks import network_is_contained, normalize_ip_value


def test_network_object_values_are_canonicalized_with_ip_arithmetic() -> None:
    network = DiscoveredObject(
        native_id="provider-network",
        name="Finance subnet",
        native_version="1",
        fingerprint="network-fingerprint",
        object_type=FirewallObjectType.NETWORK,
        normalized_value="10.20.1.5/16",
    )
    host = DiscoveredObject(
        native_id="provider-host",
        name="Finance host",
        native_version="1",
        fingerprint="host-fingerprint",
        object_type=FirewallObjectType.NETWORK,
        normalized_value="2001:0db8::1",
    )
    assert network.normalized_value == "10.20.0.0/16"
    assert host.normalized_value == "2001:db8::1"


def test_network_range_object_values_are_canonicalized() -> None:
    address_range = DiscoveredObject(
        native_id="provider-range",
        name="Application range",
        native_version="1",
        fingerprint="range-fingerprint",
        object_type=FirewallObjectType.NETWORK,
        normalized_value="192.168.95.100 - 192.168.95.110",
    )

    assert address_range.normalized_value == "192.168.95.100-192.168.95.110"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2001:0db8::1", "2001:db8::1"),
        ("2001:db8:1::/48", "2001:db8:1::/48"),
        ("2001:db8::1 - 2001:db8::ff", "2001:db8::1-2001:db8::ff"),
    ],
)
def test_ipv6_hosts_subnets_and_ranges_are_canonicalized(value: str, expected: str) -> None:
    assert normalize_ip_value(value) == expected


def test_authorized_ranges_support_ipv4_and_ipv6_containment() -> None:
    assert network_is_contained("10.10.10.20-10.10.10.30", "10.10.10.1-10.10.10.40")
    assert network_is_contained("2001:db8::20", "2001:db8::1-2001:db8::ff")
    assert not network_is_contained("2001:db9::1", "2001:db8::1-2001:db8::ff")


@pytest.mark.parametrize(
    "value",
    ["192.168.95.110-192.168.95.100", "192.168.95.100-2001:db8::1"],
)
def test_invalid_network_range_object_value_is_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="range endpoints"):
        DiscoveredObject(
            native_id="provider-range",
            name="Invalid range",
            native_version="1",
            fingerprint="range-fingerprint",
            object_type=FirewallObjectType.NETWORK,
            normalized_value=value,
        )


def test_invalid_network_object_value_is_rejected() -> None:
    with pytest.raises(ValueError, match="does not appear"):
        DiscoveredObject(
            native_id="provider-network",
            name="Invalid network",
            native_version="1",
            fingerprint="network-fingerprint",
            object_type=FirewallObjectType.NETWORK,
            normalized_value="10.20.not-an-address",
        )


@pytest.mark.parametrize(
    ("requested", "grant", "allowed"),
    [
        ("10.0.0.0", "10.0.0.0/24", True),
        ("10.0.0.255", "10.0.0.0/24", True),
        ("10.0.1.0", "10.0.0.0/24", False),
        ("10.0.0.0/25", "10.0.0.0/24", True),
        ("10.0.0.0/23", "10.0.0.0/24", False),
        ("10.0.0.254-10.0.1.1", "10.0.0.0/24", False),
        ("010.0.0.1", "10.0.0.0/8", False),
        ("0x0a000001", "10.0.0.0/8", False),
        ("167772161", "10.0.0.0/8", False),
        ("10.0.0.129/25", "10.0.0.0/24", True),
        ("::ffff:10.0.0.1", "10.0.0.0/8", False),
        ("2001:0db8:0000::1", "2001:db8::/64", True),
        ("2001:db8::/63", "2001:db8::/64", False),
        ("10.0.0.2-10.0.0.1", "10.0.0.0/24", False),
    ],
)
def test_adversarial_ip_boundaries(requested: str, grant: str, allowed: bool) -> None:
    assert network_is_contained(requested, grant) is allowed
