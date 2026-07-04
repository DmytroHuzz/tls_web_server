from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from cryptography.x509 import DNSName, Extension
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import PolicyBuilder, Store


@dataclass(frozen=True)
class CertificateName:
    country_name: str
    state_or_province_name: str
    locality_name: str
    organization_name: str
    common_name: str

    @property
    def certificate_name(self) -> x509.Name:
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.country_name),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state_or_province_name),
                x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization_name),
                x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
            ]
        )


@dataclass(frozen=True)
class ServerIdentity:
    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate
    intermediate_certificates: List[x509.Certificate]


def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def create_certificate_builder(
    public_key: CertificatePublicKeyTypes,
    subject: CertificateName,
    issuer: CertificateName,
    extensions: Iterable[Extension],
    validity_to: datetime,
    validity_from: Optional[datetime] = None,
) -> x509.CertificateBuilder:
    valid_from = validity_from or datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject.certificate_name)
        .issuer_name(issuer.certificate_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(validity_to)
    )
    for extension in extensions:
        builder = builder.add_extension(extension.value, critical=extension.critical)
    return builder


def issue_certificate(
    public_key: CertificatePublicKeyTypes,
    subject: CertificateName,
    issuer: CertificateName,
    issuer_private_key: CertificateIssuerPrivateKeyTypes,
    extensions: Iterable[Extension],
    validity_to: datetime,
    validity_from: Optional[datetime] = None,
) -> x509.Certificate:
    return create_certificate_builder(
        public_key=public_key,
        subject=subject,
        issuer=issuer,
        extensions=extensions,
        validity_to=validity_to,
        validity_from=validity_from,
    ).sign(private_key=issuer_private_key, algorithm=hashes.SHA256())


def ca_extensions(
    public_key: CertificatePublicKeyTypes,
    issuer_certificate: Optional[x509.Certificate] = None,
    path_length: Optional[int] = None,
) -> List[Extension]:
    extensions: List[Extension] = [
        Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=True, path_length=path_length),
        ),
        Extension(
            oid=x509.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
        ),
        Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier.from_public_key(public_key),
        ),
    ]
    if issuer_certificate is not None:
        extensions.append(
            Extension(
                oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                critical=False,
                value=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    issuer_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
                ),
            )
        )
    return extensions


def server_extensions(
    public_key: CertificatePublicKeyTypes,
    dns_names: Sequence[str],
    issuer_certificate: x509.Certificate,
) -> List[Extension]:
    return [
        Extension(
            oid=x509.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=x509.BasicConstraints(ca=False, path_length=None),
        ),
        Extension(
            oid=x509.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
        ),
        Extension(
            oid=x509.ExtensionOID.EXTENDED_KEY_USAGE,
            critical=False,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        ),
        Extension(
            oid=x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=False,
            value=x509.SubjectAlternativeName([DNSName(name) for name in dns_names]),
        ),
        Extension(
            oid=x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            critical=False,
            value=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                issuer_certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
            ),
        ),
        Extension(
            oid=x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=x509.SubjectKeyIdentifier.from_public_key(public_key),
        ),
    ]


def verify_server_certificate(
    root_certificate: x509.Certificate,
    intermediate_certificates: Sequence[x509.Certificate],
    server_certificate: x509.Certificate,
    dns_name: str,
    validation_time: Optional[datetime] = None,
):
    store = Store([root_certificate])
    builder = PolicyBuilder().store(store)
    if validation_time is not None:
        builder = builder.time(validation_time)
    verifier = builder.build_server_verifier(DNSName(dns_name))
    return verifier.verify(server_certificate, list(intermediate_certificates))


def generate_certificate_chain(certs_dir: Path, dns_name: str = "localhost") -> None:
    certs_dir = Path(certs_dir)
    certs_dir.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)

    root_name = CertificateName("AT", "Vorarlberg", "Dornbirn", "Rebuilt TLS", "Root CA")
    intermediate_name = CertificateName("AT", "Vorarlberg", "Dornbirn", "Rebuilt TLS", "Intermediate CA")
    server_name = CertificateName("AT", "Vorarlberg", "Dornbirn", "Rebuilt TLS", dns_name)

    root_key = generate_rsa_key()
    root_cert = issue_certificate(
        public_key=root_key.public_key(),
        subject=root_name,
        issuer=root_name,
        issuer_private_key=root_key,
        extensions=ca_extensions(root_key.public_key(), path_length=1),
        validity_from=now,
        validity_to=now + timedelta(days=3650),
    )

    intermediate_key = generate_rsa_key()
    intermediate_cert = issue_certificate(
        public_key=intermediate_key.public_key(),
        subject=intermediate_name,
        issuer=root_name,
        issuer_private_key=root_key,
        extensions=ca_extensions(intermediate_key.public_key(), issuer_certificate=root_cert, path_length=0),
        validity_from=now,
        validity_to=now + timedelta(days=1825),
    )

    server_key = generate_rsa_key()
    server_cert = issue_certificate(
        public_key=server_key.public_key(),
        subject=server_name,
        issuer=intermediate_name,
        issuer_private_key=intermediate_key,
        extensions=server_extensions(server_key.public_key(), [dns_name], intermediate_cert),
        validity_from=now,
        validity_to=now + timedelta(days=730),
    )

    verify_server_certificate(root_cert, [intermediate_cert], server_cert, dns_name, validation_time=now)

    (certs_dir / "root_cert.pem").write_bytes(root_cert.public_bytes(Encoding.PEM))
    (certs_dir / "intermediate_cert.pem").write_bytes(intermediate_cert.public_bytes(Encoding.PEM))
    (certs_dir / "server_cert.pem").write_bytes(server_cert.public_bytes(Encoding.PEM))
    (certs_dir / "server_key.pem").write_bytes(
        server_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )


def load_trusted_root(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def load_server_identity(private_key_path: Path, certificate_path: Path, chain_paths: Sequence[Path]) -> ServerIdentity:
    private_key = load_pem_private_key(Path(private_key_path).read_bytes(), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Server identity key must be an RSA private key")
    certificate = x509.load_pem_x509_certificate(Path(certificate_path).read_bytes())
    chain = [x509.load_pem_x509_certificate(Path(path).read_bytes()) for path in chain_paths]
    return ServerIdentity(private_key=private_key, certificate=certificate, intermediate_certificates=chain)
