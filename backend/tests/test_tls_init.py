# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Self-signed ingress certificate initialization behavior."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from firewall_manager.tls_init import ensure_certificate


def test_generates_matching_hostname_certificate_and_key(tmp_path: Path) -> None:
    assert ensure_certificate("firewall.example.test", tmp_path)

    certificate = x509.load_pem_x509_certificate((tmp_path / "fullchain.pem").read_bytes())
    private_key = serialization.load_pem_private_key(
        (tmp_path / "privkey.pem").read_bytes(), password=None
    )

    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["firewall.example.test"]
    assert certificate.public_key().public_numbers() == private_key.public_key().public_numbers()
    assert (tmp_path / "privkey.pem").stat().st_mode & 0o777 == 0o600


def test_preserves_existing_certificate_pair(tmp_path: Path) -> None:
    certificate = tmp_path / "fullchain.pem"
    private_key = tmp_path / "privkey.pem"
    certificate.write_text("administrator certificate", encoding="utf-8")
    private_key.write_text("administrator key", encoding="utf-8")

    assert not ensure_certificate("firewall.example.test", tmp_path)
    assert certificate.read_text(encoding="utf-8") == "administrator certificate"
    assert private_key.read_text(encoding="utf-8") == "administrator key"


def test_renews_matching_self_signed_certificate_pair(tmp_path: Path) -> None:
    assert ensure_certificate("firewall.example.test", tmp_path)
    original_certificate = (tmp_path / "fullchain.pem").read_bytes()
    original_private_key = (tmp_path / "privkey.pem").read_bytes()

    assert ensure_certificate("firewall.example.test", tmp_path, renew_self_signed=True)

    assert (tmp_path / "fullchain.pem").read_bytes() != original_certificate
    assert (tmp_path / "privkey.pem").read_bytes() != original_private_key


def test_refuses_to_renew_unparseable_existing_pair(tmp_path: Path) -> None:
    (tmp_path / "fullchain.pem").write_text("administrator certificate", encoding="utf-8")
    (tmp_path / "privkey.pem").write_text("administrator key", encoding="utf-8")

    with pytest.raises(RuntimeError, match="could not be validated"):
        ensure_certificate("firewall.example.test", tmp_path, renew_self_signed=True)


def test_refuses_to_renew_ca_issued_certificate(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "firewall.example.test")])
    leaf_certificate = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_certificate.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(ca_key, hashes.SHA256())
    )
    (tmp_path / "fullchain.pem").write_bytes(
        leaf_certificate.public_bytes(serialization.Encoding.PEM)
    )
    (tmp_path / "privkey.pem").write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    with pytest.raises(RuntimeError, match="CA-issued"):
        ensure_certificate("firewall.example.test", tmp_path, renew_self_signed=True)


def test_refuses_partial_certificate_pair(tmp_path: Path) -> None:
    (tmp_path / "fullchain.pem").write_text("certificate only", encoding="utf-8")

    with pytest.raises(RuntimeError, match="must both exist or both be absent"):
        ensure_certificate("firewall.example.test", tmp_path)
