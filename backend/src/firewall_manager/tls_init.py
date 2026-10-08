# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Create or explicitly renew a local self-signed ingress certificate."""

import argparse
import ipaddress
import os
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def ensure_certificate(
    hostname: str, tls_directory: Path, *, renew_self_signed: bool = False
) -> bool:
    """Create the PEM pair atomically and return whether files were generated."""
    certificate_path = tls_directory / "fullchain.pem"
    private_key_path = tls_directory / "privkey.pem"
    certificate_exists = certificate_path.is_file()
    private_key_exists = private_key_path.is_file()
    if certificate_exists and private_key_exists:
        if not renew_self_signed:
            return False
        try:
            existing_certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
            existing_private_key = serialization.load_pem_private_key(
                private_key_path.read_bytes(), password=None
            )
        except (OSError, ValueError, TypeError) as exc:
            raise RuntimeError(
                "TLS renewal refused: the existing PEM pair could not be validated"
            ) from exc
        certificate_public_key = existing_certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_public_key = existing_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if existing_certificate.issuer != existing_certificate.subject:
            raise RuntimeError(
                "TLS renewal refused: the existing certificate is CA-issued; install the "
                "renewed PEM pair and use cert-reload"
            )
        if certificate_public_key != private_public_key:
            raise RuntimeError(
                "TLS renewal refused: the existing certificate and private key do not match"
            )
    if certificate_exists != private_key_exists:
        raise RuntimeError(
            "TLS initialization refused: fullchain.pem and privkey.pem must both exist or "
            "both be absent"
        )

    hostname = hostname.strip()
    if not hostname or "/" in hostname or "\x00" in hostname:
        raise ValueError("APP_PUBLIC_HOST is not a valid certificate hostname")
    try:
        san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(hostname))
    except ValueError:
        san = x509.DNSName(hostname)

    tls_directory.mkdir(parents=True, exist_ok=True)
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

    temporary_paths: list[Path] = []
    try:
        for destination, contents, mode in (
            (private_key_path, key_bytes, 0o600),
            (certificate_path, certificate_bytes, 0o644),
        ):
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{destination.name}.", dir=tls_directory
            )
            temporary_path = Path(temporary_name)
            temporary_paths.append(temporary_path)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.chmod(mode)
            temporary_path.replace(destination)
            temporary_paths.remove(temporary_path)
    finally:
        for temporary_path in temporary_paths:
            temporary_path.unlink(missing_ok=True)
    return True


def main() -> None:
    """Container entry point."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--renew-self-signed",
        action="store_true",
        help="replace an existing matching self-signed pair; refuse CA-issued certificates",
    )
    arguments = parser.parse_args()
    hostname = os.environ.get("APP_PUBLIC_HOST", "")
    tls_directory = Path(os.environ.get("TLS_DIRECTORY", "/tls"))
    try:
        generated = ensure_certificate(
            hostname,
            tls_directory,
            renew_self_signed=arguments.renew_self_signed,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        sys.stderr.write(f"{exc}\n")
        raise SystemExit(1) from exc
    if generated and arguments.renew_self_signed:
        sys.stdout.write("Renewed the self-signed ingress certificate.\n")
    elif generated:
        sys.stdout.write(
            "Generated a self-signed ingress certificate. Install a trusted certificate "
            "before exposing this deployment to users.\n"
        )
    else:
        sys.stdout.write("Using the existing ingress certificate and private key.\n")


if __name__ == "__main__":
    main()
