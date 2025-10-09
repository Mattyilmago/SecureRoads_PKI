"""
Certificate Builder and Maker for X.509 certificates.

Provides fluent interface for building certificates and factory methods
for common PKI certificate types.
"""

from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from typing import Optional


class CertificateBuilder:
    """
    Fluent builder for X.509 certificates.
    """

    def __init__(self):
        self._subject_attrs = []
        self._issuer = None
        self._public_key = None
        self._serial_number = None
        self._not_before = None
        self._not_after = None
        self._extensions = []

    def with_subject_country(self, country: str) -> "CertificateBuilder":
        """Aggiunge il paese al subject"""
        self._subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        return self

    def with_subject_organization(self, org: str) -> "CertificateBuilder":
        """Aggiunge l'organizzazione al subject"""
        self._subject_attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
        return self

    def with_subject_common_name(self, cn: str) -> "CertificateBuilder":
        """Aggiunge il common name al subject"""
        self._subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, cn))
        return self

    def with_issuer(self, issuer: x509.Name) -> "CertificateBuilder":
        """Imposta l'issuer del certificato"""
        self._issuer = issuer
        return self

    def with_public_key(self, public_key) -> "CertificateBuilder":
        """Imposta la chiave pubblica"""
        self._public_key = public_key
        return self

    def with_serial_number(self, serial: Optional[int] = None) -> "CertificateBuilder":
        """Imposta il serial number (o genera uno casuale)"""
        self._serial_number = serial if serial else x509.random_serial_number()
        return self

    def with_validity_period(
        self,
        days: Optional[int] = None,
        weeks: Optional[int] = None,
        not_before: Optional[datetime] = None,
        not_after: Optional[datetime] = None,
    ) -> "CertificateBuilder":
        """
        Imposta il periodo di validità.

        Args:
            days: Numero di giorni di validità
            weeks: Numero di settimane di validità
            not_before: Data di inizio validità (default: ora)
            not_after: Data di fine validità
        """
        self._not_before = not_before or datetime.now(timezone.utc)

        if not_after:
            self._not_after = not_after
        elif days:
            self._not_after = self._not_before + timedelta(days=days)
        elif weeks:
            self._not_after = self._not_before + timedelta(weeks=weeks)
        else:
            # Default: 1 anno
            self._not_after = self._not_before + timedelta(days=365)

        return self

    def with_basic_constraints(
        self, ca: bool, path_length: Optional[int] = None
    ) -> "CertificateBuilder":
        """Aggiunge Basic Constraints extension"""
        self._extensions.append((x509.BasicConstraints(ca=ca, path_length=path_length), True))
        return self

    def with_key_usage(
        self, digital_signature: bool = False, key_cert_sign: bool = False, crl_sign: bool = False
    ) -> "CertificateBuilder":
        """Aggiunge Key Usage extension"""
        self._extensions.append(
            (
                x509.KeyUsage(
                    digital_signature=digital_signature,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=key_cert_sign,
                    crl_sign=crl_sign,
                    encipher_only=False,
                    decipher_only=False,
                ),
                True,
            )
        )
        return self

    def build_and_sign(self, private_key) -> x509.Certificate:
        """
        Costruisce e firma il certificato.

        Args:
            private_key: Chiave privata per firmare

        Returns:
            Certificato X.509 firmato
        """
        # Costruisci subject
        subject = x509.Name(self._subject_attrs)

        # Crea builder cryptography
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(self._issuer or subject)
        cert_builder = cert_builder.public_key(self._public_key)
        cert_builder = cert_builder.serial_number(
            self._serial_number or x509.random_serial_number()
        )
        cert_builder = cert_builder.not_valid_before(self._not_before or datetime.now(timezone.utc))
        cert_builder = cert_builder.not_valid_after(
            self._not_after or datetime.now(timezone.utc) + timedelta(days=365)
        )

        # Aggiungi extensions
        for extension, critical in self._extensions:
            cert_builder = cert_builder.add_extension(extension, critical=critical)

        # Firma
        return cert_builder.sign(private_key, hashes.SHA256())


class CertificateMaker:
    """
    Factory for creating different types of PKI certificates.
    """

    @staticmethod
    def create_root_ca_certificate(
        subject_name: str, public_key, private_key, validity_years: int = 10
    ) -> x509.Certificate:
        """
        Crea un certificato Root CA self-signed.

        Args:
            subject_name: Nome del subject (es. "RootCA")
            public_key: Chiave pubblica
            private_key: Chiave privata per firma
            validity_years: Anni di validità

        Returns:
            Certificato Root CA
        """
        builder = CertificateBuilder()
        return (
            builder.with_subject_country("IT")
            .with_subject_organization(subject_name)
            .with_subject_common_name(subject_name)
            .with_public_key(public_key)
            .with_serial_number()
            .with_validity_period(days=validity_years * 365)
            .with_basic_constraints(ca=True, path_length=None)
            .with_key_usage(key_cert_sign=True, crl_sign=True)
            .build_and_sign(private_key)
        )

    @staticmethod
    def create_subordinate_ca_certificate(
        subject_name: str,
        public_key,
        issuer_name: x509.Name,
        issuer_private_key,
        is_ca: bool = True,
        validity_days: int = 365,
    ) -> x509.Certificate:
        """
        Crea un certificato per CA subordinata (EA/AA).

        Args:
            subject_name: Nome del subject
            public_key: Chiave pubblica
            issuer_name: Nome dell'issuer (RootCA)
            issuer_private_key: Chiave privata dell'issuer per firma
            is_ca: Se True, il certificato è di tipo CA
            validity_days: Giorni di validità

        Returns:
            Certificato subordinato firmato
        """
        builder = CertificateBuilder()
        return (
            builder.with_subject_country("IT")
            .with_subject_organization(subject_name)
            .with_subject_common_name(subject_name)
            .with_issuer(issuer_name)
            .with_public_key(public_key)
            .with_serial_number()
            .with_validity_period(days=validity_days)
            .with_basic_constraints(ca=is_ca, path_length=0 if is_ca else None)
            .with_key_usage(digital_signature=True, key_cert_sign=is_ca, crl_sign=is_ca)
            .build_and_sign(issuer_private_key)
        )

    @staticmethod
    def create_enrollment_certificate(
        its_id: str,
        public_key,
        issuer_name: x509.Name,
        issuer_private_key,
        validity_days: int = 365,
    ) -> x509.Certificate:
        """
        Crea un Enrollment Certificate per ITS-S.

        Args:
            its_id: ID del veicolo ITS-S
            public_key: Chiave pubblica del veicolo
            issuer_name: Nome dell'EA
            issuer_private_key: Chiave privata EA per firma
            validity_days: Giorni di validità

        Returns:
            Enrollment Certificate firmato
        """
        builder = CertificateBuilder()
        return (
            builder.with_subject_country("IT")
            .with_subject_organization("ITS-S")
            .with_subject_common_name(its_id)
            .with_issuer(issuer_name)
            .with_public_key(public_key)
            .with_serial_number()
            .with_validity_period(days=validity_days)
            .with_basic_constraints(ca=False, path_length=None)
            .with_key_usage(digital_signature=True)
            .build_and_sign(issuer_private_key)
        )

    @staticmethod
    def create_authorization_ticket(
        its_id: str, public_key, issuer_name: x509.Name, issuer_private_key, validity_weeks: int = 1
    ) -> x509.Certificate:
        """
        Crea un Authorization Ticket per ITS-S.

        Args:
            its_id: ID del veicolo ITS-S
            public_key: Chiave pubblica per questo AT
            issuer_name: Nome dell'AA
            issuer_private_key: Chiave privata AA per firma
            validity_weeks: Settimane di validità (default: 1)

        Returns:
            Authorization Ticket firmato
        """
        builder = CertificateBuilder()
        return (
            builder.with_subject_country("IT")
            .with_subject_organization("ITS-S")
            .with_subject_common_name(its_id)
            .with_issuer(issuer_name)
            .with_public_key(public_key)
            .with_serial_number()
            .with_validity_period(weeks=validity_weeks)
            .with_basic_constraints(ca=False, path_length=None)
            .with_key_usage(digital_signature=True)
            .build_and_sign(issuer_private_key)
        )


# === FUNZIONI DI CONVENIENZA ===


def create_standard_subject(country: str, organization: str, common_name: str) -> x509.Name:
    """
    Crea un subject name standard per PKI.

    Args:
        country: Codice paese (es. "IT")
        organization: Nome organizzazione
        common_name: Common name

    Returns:
        x509.Name object
    """
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
