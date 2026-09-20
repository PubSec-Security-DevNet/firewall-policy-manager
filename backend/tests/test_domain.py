"""Provider-neutral delegated-management domain behavior."""

import pytest

from firewall_manager.domain.models import DiscoveredObject, FirewallObjectType


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
