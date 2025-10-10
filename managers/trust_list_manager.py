import json
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from utils.cert_utils import (
    format_certificate_info,
    get_certificate_expiry_time,
    get_certificate_identifier,
    get_certificate_ski,
    get_short_identifier,
)
from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler


class TrustListManager:
    """
    Manages Certificate Trust Lists (CTL) creation and publication.
    Handles Full CTL, Delta CTL, Link Certificates, and Trust Anchors.
    """

    def __init__(self, root_ca, base_dir="./data/tlm/"):
        """Initializes Trust List Manager."""
        self.root_ca = root_ca
        self.base_dir = base_dir

        # Percorsi file
        self.ctl_dir = os.path.join(base_dir, "ctl/")
        self.full_ctl_path = os.path.join(self.ctl_dir, "full_ctl.pem")
        self.delta_ctl_path = os.path.join(self.ctl_dir, "delta_ctl.pem")
        self.link_certs_dir = os.path.join(base_dir, "link_certificates/")
        self.link_certs_json_dir = os.path.join(self.link_certs_dir, "json/")
        self.link_certs_asn1_dir = os.path.join(self.link_certs_dir, "asn1/")
        self.metadata_path = os.path.join(self.ctl_dir, "ctl_metadata.json")
        self.log_dir = os.path.join(base_dir, "logs/")
        self.backup_dir = os.path.join(base_dir, "backup/")
        
        # Inizializza logger
        self.logger = PKILogger.get_logger(
            name="TrustListManager",
            log_dir=self.log_dir,
            console_output=True
        )

        # Crea directory
        PKIFileHandler.ensure_directories(
            self.ctl_dir,
            self.link_certs_dir,
            self.link_certs_json_dir,
            self.link_certs_asn1_dir,
            self.log_dir,
            self.backup_dir,
        )

        # Lista completa dei trust anchors (per Full CTL)
        # Ogni entry contiene: certificate, authority_type (EA/AA), added_date
        self.trust_anchors = []

        # Link certificates generati
        # Collegano RootCA -> EA, RootCA -> AA, EA -> AA
        self.link_certificates = []

        # Metadata per tracking (simile a CRLManager)
        self.ctl_number = 0  # Numero sequenziale CTL
        self.base_ctl_number = 0  # Numero della Full CTL di riferimento per Delta
        self.last_full_ctl_time = None  # Timestamp ultima Full CTL

        # Modifiche per il prossimo Delta CTL
        self.delta_additions = []  # Trust anchors da aggiungere
        self.delta_removals = []  # Trust anchors da rimuovere

        # Carica metadata se esistono
        self.load_metadata()
        
        # Salva metadata iniziali se non esistono (primo avvio)
        if not os.path.exists(self.metadata_path):
            self.logger.info(f"Primo avvio: creazione metadata iniziali")
            self.save_metadata()

        self.logger.info(f"TrustListManager inizializzato")
        self.logger.info(f"CTL Number attuale: {self.ctl_number}")
        self.logger.info(f"Base CTL Number: {self.base_ctl_number}")
        self.logger.info(f"Trust anchors caricati: {len(self.trust_anchors)}")

    def add_trust_anchor(self, certificate, authority_type="UNKNOWN"):
        """Adds a trusted CA to the Certificate Trust List."""
        # Usa Subject + SKI invece del serial number
        cert_id = get_certificate_identifier(certificate)
        ski = get_certificate_ski(certificate)
        subject_name = certificate.subject.rfc4514_string()
        added_date = datetime.now(timezone.utc)
        expiry_date = get_certificate_expiry_time(certificate)

        self.logger.info(f"Aggiungendo trust anchor: {subject_name}")
        self.logger.info(f"  Identificatore: {cert_id}")
        self.logger.info(f"  SKI: {ski[:16]}...")
        self.logger.info(f"  Tipo: {authority_type}")
        self.logger.info(f"  Scadenza: {expiry_date}")

        # Controlla se già presente (usa SKI per confronto)
        if any(anchor["ski"] == ski for anchor in self.trust_anchors):
            self.logger.info(f"Trust anchor già presente nella lista")
            return

        trust_anchor_entry = {
            "certificate": certificate,
            "cert_id": cert_id,  # Identificatore human-readable (Subject + SKI)
            "ski": ski,  # Subject Key Identifier per confronti univoci
            "subject_name": subject_name,
            "authority_type": authority_type,
            "added_date": added_date,
            "expiry_date": expiry_date,
            # Mantieni serial_number per backward compatibility (solo logging)
            "serial_number": certificate.serial_number,
        }

        # Aggiunge a entrambe le liste
        self.trust_anchors.append(trust_anchor_entry)
        self.delta_additions.append(trust_anchor_entry)

        self.logger.info(f"Trust anchor aggiunto. Totale: {len(self.trust_anchors)}")
        self.logger.info(f"Aggiunte delta pending: {len(self.delta_additions)}")

        # Genera automaticamente link certificate per questa CA
        self._generate_link_certificate_for_authority(certificate, authority_type)

    def remove_trust_anchor(self, certificate, reason="unspecified"):
        """
        Rimuove una CA dalla Certificate Trust List.

        Questo accade quando:
        - La CA è stata compromessa
        - La CA è stata dismessa
        - Il certificato della CA è scaduto

        Args:
            certificate: Il certificato X.509 da rimuovere
            reason: Motivo della rimozione
        """
        ski = get_certificate_ski(certificate)
        cert_id = get_certificate_identifier(certificate)
        subject_name = certificate.subject.rfc4514_string()

        self.logger.info(f"Rimozione trust anchor: {subject_name}")
        self.logger.info(f"  Identificatore: {cert_id}")
        self.logger.info(f"  SKI: {ski[:16]}...")
        self.logger.info(f"  Motivo: {reason}")

        # Trova e rimuovi dalla lista completa (usa SKI per confronto)
        found = None
        for anchor in self.trust_anchors:
            if anchor["ski"] == ski:
                found = anchor
                break

        if not found:
            self.logger.info(f"Trust anchor non trovato nella lista")
            return

        self.trust_anchors.remove(found)

        # Aggiungi alla lista rimozioni delta
        removal_entry = {
            "cert_id": cert_id,
            "ski": ski,
            "subject_name": subject_name,
            "removal_date": datetime.now(timezone.utc),
            "reason": reason,
            # Mantieni serial_number per backward compatibility
            "serial_number": certificate.serial_number,
        }
        self.delta_removals.append(removal_entry)

        self.logger.info(f"Trust anchor rimosso. Totale: {len(self.trust_anchors)}")
        self.logger.info(f"Rimozioni delta pending: {len(self.delta_removals)}")

        # Rimuovi anche i link certificates associati
        self._remove_link_certificates_for_ski(ski)

    def is_trusted(self, certificate):
        """
        Verifica se un certificato è firmato da una CA fidata.

        Questo è il metodo principale usato dagli ITS-S per validare
        certificati ricevuti (EC, AT, ecc.)

        Args:
            certificate: Il certificato da verificare

        Returns:
            tuple (bool, str): (is_trusted, issuer_info)
        """
        # Controlla se il certificato stesso è un trust anchor (usa SKI per confronto)
        cert_ski = get_certificate_ski(certificate)
        for anchor in self.trust_anchors:
            if anchor["ski"] == cert_ski:
                return True, f"Direct trust anchor: {anchor['subject_name']}"

        # Controlla se l'issuer è un trust anchor
        issuer_name = certificate.issuer.rfc4514_string()
        for anchor in self.trust_anchors:
            anchor_subject = anchor["certificate"].subject.rfc4514_string()
            if issuer_name == anchor_subject:
                # Verifica firma del certificato usando la chiave pubblica del trust anchor
                try:
                    from cryptography.exceptions import InvalidSignature
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives.asymmetric import ec

                    # Ottieni chiave pubblica del trust anchor (issuer)
                    public_key = anchor["certificate"].public_key()

                    # Verifica firma del certificato
                    public_key.verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        ec.ECDSA(certificate.signature_hash_algorithm),
                    )
                    return True, f"Signed by trusted CA: {anchor_subject}"
                except (InvalidSignature, Exception) as e:
                    # Firma non valida o errore nella verifica
                    self.logger.info(f"[WARNING] Firma non valida per {certificate.subject}: {e}")
                    pass

        return False, "No trusted issuer found"

    def publish_full_ctl(self, validity_days=30):
        """
        Genera e pubblica una Full CTL contenente TUTTI i trust anchors.

        La Full CTL:
        - Contiene tutti i certificati fidati (EA, AA)
        - Viene pubblicata periodicamente (es. mensilmente)
        - Serve come base di riferimento per i Delta CTL
        - Include metadata e link certificates

        Nota: In un'implementazione completa, questo dovrebbe usare
        ASN.1 OER secondo ETSI TS 102941. Per ora usiamo un formato
        semplificato basato su X.509.

        Args:
            validity_days: Giorni di validità della CTL
        """
        self.logger.info(f"=== GENERAZIONE FULL CTL ===")

        # Incrementa CTL number
        self.ctl_number += 1
        self.base_ctl_number = self.ctl_number
        self.last_full_ctl_time = datetime.now(timezone.utc)

        # Pulisce trust anchors scaduti
        self._cleanup_expired_trust_anchors()

        self.logger.info(f"CTL Number: {self.ctl_number}")
        self.logger.info(f"Trust anchors attivi: {len(self.trust_anchors)}")

        # Crea struttura CTL
        ctl_data = {
            "version": "1.0",
            "ctl_number": self.ctl_number,
            "issuer": self.root_ca.certificate.subject.rfc4514_string(),
            "issue_date": datetime.now(timezone.utc).isoformat(),
            "next_update": (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat(),
            "trust_anchors": [],
        }

        # Salva tutti i certificati fidati in formato PEM concatenato
        ctl_content = []
        ctl_content.append(f"# Certificate Trust List (CTL)\n")
        ctl_content.append(f"# CTL Number: {self.ctl_number}\n")
        ctl_content.append(f"# Issuer: {ctl_data['issuer']}\n")
        ctl_content.append(f"# Issue Date: {ctl_data['issue_date']}\n")
        ctl_content.append(f"# Next Update: {ctl_data['next_update']}\n")
        ctl_content.append(f"# Trust Anchors: {len(self.trust_anchors)}\n")
        ctl_content.append(f"#\n")

        for anchor in self.trust_anchors:
            cert = anchor["certificate"]
            self.logger.info(f"  {anchor['authority_type']}: {anchor['subject_name']}")

            # Aggiungi a metadata (usa cert_id e SKI invece di solo serial)
            ctl_data["trust_anchors"].append(
                {
                    "cert_id": anchor["cert_id"],
                    "ski": anchor["ski"],
                    "subject": anchor["subject_name"],
                    "type": anchor["authority_type"],
                    "added_date": anchor["added_date"].isoformat(),
                    "expiry_date": anchor["expiry_date"].isoformat(),
                    # Mantieni serial_number per backward compatibility
                    "serial_number": anchor["serial_number"],
                }
            )

            # Aggiungi certificato in formato PEM (usa cert_id nell'header)
            ctl_content.append(
                f"\n# Trust Anchor: {anchor['cert_id']} ({anchor['authority_type']})\n"
            )
            ctl_content.append(f"# Subject: {anchor['subject_name']}\n")
            ctl_content.append(f"# SKI: {anchor['ski']}\n")
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            ctl_content.append(cert_pem)

        # Salva Full CTL
        with open(self.full_ctl_path, "w") as f:
            f.writelines(ctl_content)

        self.logger.info(f"Full CTL salvata: {self.full_ctl_path}")

        # Salva anche metadata JSON
        metadata_ctl_path = self.full_ctl_path.replace(".pem", "_metadata.json")
        with open(metadata_ctl_path, "w") as f:
            json.dump(ctl_data, f, indent=2)

        self.logger.info(f"Metadata CTL salvati: {metadata_ctl_path}")

        # Reset delta changes (tutto è ora nella Full CTL)
        self.delta_additions = []
        self.delta_removals = []

        # Salva metadata manager
        self.save_metadata()

        self.logger.info(f"=== FULL CTL PUBBLICATA ===")
        return ctl_data

    def publish_delta_ctl(self, validity_days=7):
        """
        Genera e pubblica una Delta CTL contenente SOLO le modifiche.

        La Delta CTL:
        - Contiene solo trust anchors aggiunti/rimossi dall'ultima Full CTL
        - È molto più piccola e veloce da distribuire
        - Include riferimento alla Full CTL base (Base CTL Number)
        - Viene pubblicata frequentemente (es. settimanalmente)

        Struttura Delta CTL:
        - ToBeAdded: Lista certificati da aggiungere ai trust anchors
        - ToBeRemoved: Lista certificati da rimuovere dai trust anchors

        Args:
            validity_days: Giorni di validità della Delta CTL
        """
        self.logger.info(f"=== GENERAZIONE DELTA CTL ===")

        # Controlla se ci sono modifiche
        if not self.delta_additions and not self.delta_removals:
            self.logger.info(f"Nessuna modifica, Delta CTL non necessaria")
            return None

        # Incrementa CTL number
        self.ctl_number += 1

        self.logger.info(f"CTL Number: {self.ctl_number}")
        self.logger.info(f"Base CTL Number: {self.base_ctl_number}")
        self.logger.info(f"Aggiunte: {len(self.delta_additions)}")
        self.logger.info(f"Rimozioni: {len(self.delta_removals)}")

        # Crea struttura Delta CTL
        delta_ctl_data = {
            "version": "1.0",
            "ctl_number": self.ctl_number,
            "base_ctl_number": self.base_ctl_number,
            "issuer": self.root_ca.certificate.subject.rfc4514_string(),
            "issue_date": datetime.now(timezone.utc).isoformat(),
            "next_update": (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat(),
            "to_be_added": [],
            "to_be_removed": [],
        }

        # Prepara contenuto
        delta_content = []
        delta_content.append(f"# Delta Certificate Trust List (Delta CTL)\n")
        delta_content.append(f"# CTL Number: {self.ctl_number}\n")
        delta_content.append(f"# Base CTL Number: {self.base_ctl_number}\n")
        delta_content.append(f"# Issuer: {delta_ctl_data['issuer']}\n")
        delta_content.append(f"# Issue Date: {delta_ctl_data['issue_date']}\n")
        delta_content.append(f"# Additions: {len(self.delta_additions)}\n")
        delta_content.append(f"# Removals: {len(self.delta_removals)}\n")
        delta_content.append(f"#\n")

        # Sezione ToBeAdded
        if self.delta_additions:
            delta_content.append(f"\n### TO BE ADDED ###\n")
            for anchor in self.delta_additions:
                cert = anchor["certificate"]
                self.logger.info(f"  + {anchor['authority_type']}: {anchor['subject_name']}")

                delta_ctl_data["to_be_added"].append(
                    {
                        "cert_id": anchor["cert_id"],
                        "ski": anchor["ski"],
                        "subject": anchor["subject_name"],
                        "type": anchor["authority_type"],
                        "added_date": anchor["added_date"].isoformat(),
                        # Mantieni serial_number per backward compatibility
                        "serial_number": anchor["serial_number"],
                    }
                )

                delta_content.append(f"\n# ADD: {anchor['cert_id']} ({anchor['authority_type']})\n")
                delta_content.append(f"# Subject: {anchor['subject_name']}\n")
                delta_content.append(f"# SKI: {anchor['ski']}\n")
                cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
                delta_content.append(cert_pem)

        # Sezione ToBeRemoved
        if self.delta_removals:
            delta_content.append(f"\n### TO BE REMOVED ###\n")
            for removal in self.delta_removals:
                self.logger.info(f"  - {removal['cert_id']} ({removal['reason']})")

                delta_ctl_data["to_be_removed"].append(
                    {
                        "cert_id": removal["cert_id"],
                        "ski": removal["ski"],
                        "subject": removal["subject_name"],
                        "removal_date": removal["removal_date"].isoformat(),
                        "reason": removal["reason"],
                        # Mantieni serial_number per backward compatibility
                        "serial_number": removal["serial_number"],
                    }
                )

                delta_content.append(f"\n# REMOVE: {removal['cert_id']}\n")
                delta_content.append(f"# Subject: {removal['subject_name']}\n")
                delta_content.append(f"# SKI: {removal['ski']}\n")
                delta_content.append(f"# Reason: {removal['reason']}\n")

        # Salva Delta CTL
        with open(self.delta_ctl_path, "w") as f:
            f.writelines(delta_content)

        self.logger.info(f"Delta CTL salvata: {self.delta_ctl_path}")

        # Salva metadata JSON
        metadata_delta_path = self.delta_ctl_path.replace(".pem", "_metadata.json")
        with open(metadata_delta_path, "w") as f:
            json.dump(delta_ctl_data, f, indent=2)

        self.logger.info(f"Metadata Delta CTL salvati: {metadata_delta_path}")

        # Salva metadata manager
        self.save_metadata()

        self.logger.info(f"=== DELTA CTL PUBBLICATA ===")
        return delta_ctl_data

    def _generate_link_certificate_for_authority(self, authority_cert, authority_type):
        """
        Genera un Link Certificate ETSI-compliant che collega RootCA a questa autorità.

        ETSI TS 102941 Section 6.4 - ToBeSignedLinkCertificate:
        - certificateHash: HashedId8 del certificato subordinato (SHA-256)
        - issuerCertificate: Riferimento al certificato issuer (RootCA)
        - expiryTime: Timestamp di scadenza del link
        - signature: Firma digitale ECDSA della RootCA

        I Link Certificates permettono di:
        - Navigare la gerarchia di fiducia
        - Validare catene di certificati ETSI TS 103097
        - Verificare relazioni tra CA in modo crittograficamente sicuro

        Args:
            authority_cert: Certificato dell'autorità (EA/AA)
            authority_type: Tipo di autorità ("EA", "AA")
        """
        import hashlib
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self.logger.info(f"Generando Link Certificate ETSI-compliant: RootCA -> {authority_type}")

        # Usa SKI invece di serial number per identificatori più robusti
        root_ca_ski = get_certificate_ski(self.root_ca.certificate)
        authority_ski = get_certificate_ski(authority_cert)
        authority_id = get_short_identifier(authority_cert)

        # ETSI TS 102941: Calcola HashedId8 del certificato subordinato
        # HashedId8 = primi 8 byte di SHA-256(DER-encoded certificate)
        cert_der = authority_cert.public_bytes(serialization.Encoding.DER)
        cert_hash_full = hashlib.sha256(cert_der).digest()
        cert_hash_id8 = cert_hash_full[:8].hex()  # HashedId8 (16 caratteri hex)

        # ETSI TS 102941: Calcola scadenza del link certificate
        # Usa la scadenza del certificato subordinato o 1 anno, quello che è minore
        authority_expiry = get_certificate_expiry_time(authority_cert)
        one_year_from_now = datetime.now(timezone.utc) + timedelta(days=365)

        link_expiry = min(authority_expiry, one_year_from_now)

        # Prepara dati da firmare secondo ETSI TS 102941
        # ToBeSignedLinkCertificate = {from_ski, to_ski, cert_hash, expiry}
        data_to_sign = json.dumps(
            {
                "from_ski": root_ca_ski,
                "to_ski": authority_ski,
                "cert_hash_id8": cert_hash_id8,
                "expiry_time": link_expiry.isoformat(),
                "link_version": "1.0",
            },
            sort_keys=True,
        ).encode("utf-8")

        # ETSI TS 102941: Firma con chiave privata RootCA usando ECDSA-SHA256
        signature = self.root_ca.private_key.sign(data_to_sign, ec.ECDSA(hashes.SHA256()))

        # Costruisci Link Certificate ETSI-compliant
        link_cert_info = {
            # Identificatori
            "link_id": f"LINK_{root_ca_ski[:8]}_to_{authority_ski[:8]}",
            "version": "1.0",
            "link_certificate_format": "ETSI_TS_102941",
            # Issuer (RootCA)
            "from_ca": "RootCA",
            "from_ski": root_ca_ski,
            "from_cert_id": get_short_identifier(self.root_ca.certificate),
            "from_serial": self.root_ca.certificate.serial_number,
            # Subject (EA/AA)
            "to_ca": authority_type,
            "to_ski": authority_ski,
            "to_cert_id": authority_id,
            "to_subject": authority_cert.subject.rfc4514_string(),
            "to_serial": authority_cert.serial_number,
            # ETSI TS 102941 mandatory fields
            "cert_hash_id8": cert_hash_id8,  # HashedId8 del subordinato
            "expiry_time": link_expiry.isoformat(),  # Scadenza link
            "created_at": datetime.now(timezone.utc).isoformat(),
            # Firma digitale ECDSA
            "signature": signature.hex(),
            "signature_algorithm": "ECDSA-SHA256",
            # Metadata
            "purpose": f"Certifies trust relationship RootCA -> {authority_type}",
            "etsi_compliant": True,
        }

        self.link_certificates.append(link_cert_info)

        self.logger.info(f"  HashedId8: {cert_hash_id8}")
        self.logger.info(f"  Expiry: {link_expiry.strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info(f"  Signature: {signature.hex()[:32]}...")

        # Salva link certificate in due formati:
        # 1. JSON (per debugging e compatibilità)
        # 2. ASN.1 OER binario (ETSI-compliant)

        short_id = authority_id.replace("EnrollmentAuthority_", "").replace(
            "AuthorizationAuthority_", ""
        )

        # Formato JSON (leggibile) - salvato in sottocartella json/
        link_filename_json = f"link_RootCA_to_{short_id}.json"
        link_path_json = os.path.join(self.link_certs_json_dir, link_filename_json)

        with open(link_path_json, "w") as f:
            json.dump(link_cert_info, f, indent=2)

        self.logger.info(f"Link Certificate JSON salvato: {link_path_json}")

        # Formato ASN.1 OER (ETSI-compliant)
        try:
            from protocols.etsi_link_certificate import ETSILinkCertificateEncoder

            encoder = ETSILinkCertificateEncoder()

            # Codifica in ASN.1 OER
            asn1_bytes = encoder.encode_full_link_certificate(
                issuer_cert_der=self.root_ca.certificate.public_bytes(serialization.Encoding.DER),
                subject_cert_der=authority_cert.public_bytes(serialization.Encoding.DER),
                expiry_time=link_expiry,
                private_key=self.root_ca.private_key,
            )

            # Salva formato binario ASN.1 - salvato in sottocartella asn1/
            link_filename_asn1 = f"link_RootCA_to_{short_id}.asn1"
            link_path_asn1 = os.path.join(self.link_certs_asn1_dir, link_filename_asn1)

            with open(link_path_asn1, "wb") as f:
                f.write(asn1_bytes)

            self.logger.info(f"Link Certificate ASN.1 OER salvato: {link_path_asn1}")
            self.logger.info(f"  Dimensione: {len(asn1_bytes)} bytes")

        except Exception as e:
            self.logger.info(f"[WARNING] Errore codifica ASN.1: {e}")
            self.logger.info(f"Continuando con solo formato JSON...")

    def verify_link_certificate(self, link_cert_data):
        """
        Verifica la firma di un Link Certificate secondo ETSI TS 102941.

        Questo metodo è usato da ITS-S per validare catene di fiducia
        prima di accettare certificati EC/AT.

        Args:
            link_cert_data: Dictionary contenente i dati del link certificate

        Returns:
            tuple (bool, str): (is_valid, message)

        ETSI TS 102941 Section 6.4 - Link Certificate Verification
        """
        from cryptography.hazmat.primitives.asymmetric import ec

        try:
            # Verifica presenza campi obbligatori ETSI
            required_fields = [
                "from_ski",
                "to_ski",
                "cert_hash_id8",
                "expiry_time",
                "signature",
            ]
            for field in required_fields:
                if field not in link_cert_data:
                    return False, f"Missing required field: {field}"

            # Verifica scadenza
            expiry = datetime.fromisoformat(link_cert_data["expiry_time"])
            if expiry < datetime.now(timezone.utc):
                return False, f"Link certificate expired at {expiry}"

            # Ricostruisci dati originali da firmare
            data_to_verify = json.dumps(
                {
                    "from_ski": link_cert_data["from_ski"],
                    "to_ski": link_cert_data["to_ski"],
                    "cert_hash_id8": link_cert_data["cert_hash_id8"],
                    "expiry_time": link_cert_data["expiry_time"],
                    "link_version": link_cert_data.get("version", "1.0"),
                },
                sort_keys=True,
            ).encode("utf-8")

            # Verifica firma con chiave pubblica RootCA
            signature = bytes.fromhex(link_cert_data["signature"])
            self.root_ca.certificate.public_key().verify(
                signature, data_to_verify, ec.ECDSA(hashes.SHA256())
            )

            return True, "Link certificate signature valid"

        except Exception as e:
            return False, f"Verification failed: {str(e)}"

    def _remove_link_certificates_for_ski(self, ski):
        """
        Rimuove tutti i link certificates associati a un SKI.

        Args:
            ski: Subject Key Identifier del certificato
        """
        self.logger.info(f"Rimozione link certificates per SKI: {ski[:16]}...")

        # Rimuovi dalla lista in memoria (usa SKI per confronto)
        self.link_certificates = [link for link in self.link_certificates if link["to_ski"] != ski]

        # Rimuovi file (cerca per SKI nei metadati del file)
        for filename in os.listdir(self.link_certs_dir):
            file_path = os.path.join(self.link_certs_dir, filename)
            try:
                with open(file_path, "r") as f:
                    link_data = json.load(f)
                    if link_data.get("to_ski") == ski:
                        os.remove(file_path)
                        self.logger.info(f"Link certificate rimosso: {filename}")
            except (json.JSONDecodeError, FileNotFoundError):
                pass

    def publish_link_certificates(self):
        """
        Pubblica tutti i link certificates in un bundle.

        Questo bundle viene distribuito agli ITS-S insieme alla CTL
        per permettere la validazione completa delle catene.

        Genera due formati:
        1. JSON bundle (leggibile, per debugging)
        2. ASN.1 OER bundle (ETSI-compliant, per produzione)
        """
        self.logger.info(f"=== PUBBLICAZIONE LINK CERTIFICATES ===")
        self.logger.info(f"Link certificates totali: {len(self.link_certificates)}")

        # 1. Bundle JSON (formato leggibile) - salvato in json/
        bundle_path_json = os.path.join(self.link_certs_json_dir, "link_certificates_bundle.json")

        bundle_data = {
            "version": "1.0",
            "format": "JSON",
            "issue_date": datetime.now(timezone.utc).isoformat(),
            "total_links": len(self.link_certificates),
            "link_certificates": self.link_certificates,
        }

        with open(bundle_path_json, "w") as f:
            json.dump(bundle_data, f, indent=2)

        self.logger.info(f"Bundle JSON salvato: {bundle_path_json}")

        # 2. Bundle ASN.1 OER (formato ETSI-compliant) - salvato in asn1/
        try:
            from protocols.etsi_link_certificate import ETSILinkCertificateEncoder

            bundle_path_asn1 = os.path.join(
                self.link_certs_asn1_dir, "link_certificates_bundle.asn1"
            )

            # Genera bundle ASN.1: [count(2) | link1_len(2) | link1 | link2_len(2) | link2 | ...]
            encoder = ETSILinkCertificateEncoder()
            bundle_asn1 = bytearray()

            # Header: numero di link certificates (2 bytes, big-endian)
            import struct

            bundle_asn1.extend(struct.pack(">H", len(self.link_certificates)))

            # Aggiungi tutti i link certificates
            links_encoded = 0
            for link_cert in self.link_certificates:
                try:
                    # Trova il certificato subordinato per questo link
                    to_ski = link_cert["to_ski"]

                    # Cerca il certificato nella lista trust anchors
                    subject_cert = None
                    for anchor in self.trust_anchors:
                        if anchor["ski"] == to_ski:
                            subject_cert = anchor["certificate"]
                            break

                    if subject_cert is None:
                        self.logger.info(f"[WARNING] Certificato non trovato per SKI: {to_ski[:16]}...")
                        continue

                    # Estrai expiry time
                    expiry_time = datetime.fromisoformat(link_cert["expiry_time"])

                    # Codifica link certificate completo in ASN.1 OER
                    link_asn1 = encoder.encode_full_link_certificate(
                        issuer_cert_der=self.root_ca.certificate.public_bytes(
                            serialization.Encoding.DER
                        ),
                        subject_cert_der=subject_cert.public_bytes(serialization.Encoding.DER),
                        expiry_time=expiry_time,
                        private_key=self.root_ca.private_key,
                    )

                    # Aggiungi lunghezza + dati
                    bundle_asn1.extend(struct.pack(">H", len(link_asn1)))
                    bundle_asn1.extend(link_asn1)
                    links_encoded += 1

                except Exception as e:
                    self.logger.info(f"[ERROR] Errore codifica link: {e}")
                    continue

            # Salva bundle ASN.1
            with open(bundle_path_asn1, "wb") as f:
                f.write(bytes(bundle_asn1))

            self.logger.info(f"Bundle ASN.1 OER salvato: {bundle_path_asn1}")
            self.logger.info(
                f"  Link certificates codificati: {links_encoded}/{len(self.link_certificates)}"
            )
            self.logger.info(f"  Dimensione bundle: {len(bundle_asn1)} bytes")

        except Exception as e:
            self.logger.info(f"[WARNING] Errore creazione bundle ASN.1: {e}")
            self.logger.info(f"Continuando con solo bundle JSON...")

        self.logger.info(f"=== PUBBLICAZIONE COMPLETATA ===")

        return bundle_data

    def distribute_to_itss(self, itss_list):
        """
        Distribuisce CTL e link certificates a una lista di ITS-S.

        Questo metodo simula la distribuzione attiva delle trust lists
        agli ITS-S. In un sistema reale, questo potrebbe essere:
        - Push via API REST
        - Download su richiesta
        - Distribuzione via broadcast V2X

        Args:
            itss_list: Lista di oggetti ITSStation
        """
        self.logger.info(f"=== DISTRIBUZIONE CTL A ITS-S ===")
        self.logger.info(f"ITS-S destinatari: {len(itss_list)}")

        # Carica Full CTL
        ctl_data = self.get_ctl_for_download()

        distributed = 0
        for itss in itss_list:
            try:
                # Copia CTL nella directory dell'ITS-S
                itss_ctl_path = os.path.join(itss.ctl_path)

                # Copia file CTL
                import shutil

                shutil.copy2(self.full_ctl_path, itss_ctl_path)

                self.logger.info(f"CTL distribuita a: {itss.its_id}")
                distributed += 1
            except Exception as e:
                self.logger.info(f"Errore distribuzione a {itss.its_id}: {e}")

        self.logger.info(f"Distribuzione completata: {distributed}/{len(itss_list)} ITS-S")
        self.logger.info(f"=== DISTRIBUZIONE TERMINATA ===")

    def get_ctl_for_download(self):
        """
        Restituisce la Full CTL in formato scaricabile.

        Questo metodo viene chiamato dagli ITS-S quando richiedono
        la CTL via API o download diretto.

        Returns:
            dict con metadata e percorso file CTL
        """
        if not os.path.exists(self.full_ctl_path):
            self.logger.info(f"Full CTL non disponibile")
            return None

        metadata_path = self.full_ctl_path.replace(".pem", "_metadata.json")

        ctl_info = {
            "ctl_number": self.ctl_number,
            "file_path": self.full_ctl_path,
            "metadata_path": metadata_path if os.path.exists(metadata_path) else None,
            "trust_anchors_count": len(self.trust_anchors),
            "last_update": self.last_full_ctl_time.isoformat() if self.last_full_ctl_time else None,
        }

        self.logger.info(f"CTL disponibile per download:")
        self.logger.info(f"  CTL Number: {ctl_info['ctl_number']}")
        self.logger.info(f"  Trust Anchors: {ctl_info['trust_anchors_count']}")

        return ctl_info

    def _cleanup_expired_trust_anchors(self):
        """
        Rimuove trust anchors scaduti dalla lista.

        Simile a cleanup nel CRLManager, ma per certificati fidati.
        Un certificato scaduto non può più essere usato per firmare,
        quindi non serve mantenerlo nei trust anchors.
        """
        now = datetime.now(timezone.utc)
        old_count = len(self.trust_anchors)

        # Filtra solo trust anchors non ancora scaduti
        filtered = []
        for anchor in self.trust_anchors:
            expiry_date = anchor.get("expiry_date")
            if expiry_date:
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                if expiry_date > now:
                    filtered.append(anchor)
                else:
                    self.logger.info(f"Rimozione trust anchor scaduto: {anchor['subject_name']}")

        self.trust_anchors = filtered

        removed = old_count - len(self.trust_anchors)
        if removed > 0:
            self.logger.info(f"Pulizia: rimossi {removed} trust anchors scaduti")
            self.logger.info(f"Trust anchors attivi rimasti: {len(self.trust_anchors)}")

    def load_full_ctl(self):
        """
        Carica la Full CTL dal file.

        Returns:
            dict con metadata CTL o None se non esiste
        """
        metadata_path = self.full_ctl_path.replace(".pem", "_metadata.json")

        if not os.path.exists(metadata_path):
            self.logger.info(f"Full CTL metadata non trovati")
            return None

        with open(metadata_path, "r") as f:
            ctl_data = json.load(f)

        self.logger.info(f"Full CTL caricata:")
        self.logger.info(f"  CTL Number: {ctl_data['ctl_number']}")
        self.logger.info(f"  Trust Anchors: {len(ctl_data['trust_anchors'])}")
        self.logger.info(f"  Issue Date: {ctl_data['issue_date']}")

        return ctl_data

    def load_delta_ctl(self):
        """
        Carica la Delta CTL dal file.

        Returns:
            dict con metadata Delta CTL o None se non esiste
        """
        metadata_path = self.delta_ctl_path.replace(".pem", "_metadata.json")

        if not os.path.exists(metadata_path):
            self.logger.info(f"Delta CTL metadata non trovati")
            return None

        with open(metadata_path, "r") as f:
            delta_data = json.load(f)

        self.logger.info(f"Delta CTL caricata:")
        self.logger.info(f"  CTL Number: {delta_data['ctl_number']}")
        self.logger.info(f"  Base CTL Number: {delta_data['base_ctl_number']}")
        self.logger.info(f"  Aggiunte: {len(delta_data['to_be_added'])}")
        self.logger.info(f"  Rimozioni: {len(delta_data['to_be_removed'])}")

        return delta_data

    def save_metadata(self):
        """
        Salva metadata TLM su file JSON per persistenza.

        Simile a CRLManager, mantiene stato tra restart.
        Salva anche i trust anchors in formato serializzabile.
        """
        # Serializza trust anchors (solo i campi necessari, non il certificato completo)
        serialized_anchors = []
        for anchor in self.trust_anchors:
            cert = anchor["certificate"]
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
            
            serialized_anchors.append({
                "certificate_pem": cert_pem,
                "cert_id": anchor["cert_id"],
                "ski": anchor["ski"],
                "subject_name": anchor["subject_name"],
                "authority_type": anchor["authority_type"],
                "added_date": anchor["added_date"].isoformat(),
                "expiry_date": anchor["expiry_date"].isoformat(),
                "serial_number": anchor["serial_number"],
            })
        
        metadata = {
            "ctl_number": self.ctl_number,
            "base_ctl_number": self.base_ctl_number,
            "last_full_ctl_time": (
                self.last_full_ctl_time.isoformat() if self.last_full_ctl_time else None
            ),
            "trust_anchors_count": len(self.trust_anchors),
            "trust_anchors": serialized_anchors,  # NUOVO: salva trust anchors
            "delta_additions_pending": len(self.delta_additions),
            "delta_removals_pending": len(self.delta_removals),
            "link_certificates_count": len(self.link_certificates),
        }

        with open(self.metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        self.logger.info(f"Metadata salvati: {self.metadata_path}")
        self.logger.info(f"  Trust anchors salvati: {len(serialized_anchors)}")

    def load_metadata(self):
        """
        Carica metadata TLM da file JSON.
        Ricarica anche i trust anchors salvati.
        """
        if not os.path.exists(self.metadata_path):
            self.logger.info(f"Nessun metadata esistente, inizializzo nuovo")
            return

        try:
            with open(self.metadata_path, "r") as f:
                metadata = json.load(f)

            self.ctl_number = metadata.get("ctl_number", 0)
            self.base_ctl_number = metadata.get("base_ctl_number", 0)

            last_full = metadata.get("last_full_ctl_time")
            if last_full:
                self.last_full_ctl_time = datetime.fromisoformat(last_full)

            # NUOVO: Ricarica trust anchors
            serialized_anchors = metadata.get("trust_anchors", [])
            if serialized_anchors:
                self.logger.info(f"Ricaricando {len(serialized_anchors)} trust anchors...")
                for ser_anchor in serialized_anchors:
                    try:
                        # Deserializza certificato da PEM
                        cert_pem = ser_anchor["certificate_pem"].encode("utf-8")
                        certificate = x509.load_pem_x509_certificate(cert_pem)
                        
                        # Ricostruisci anchor entry
                        anchor_entry = {
                            "certificate": certificate,
                            "cert_id": ser_anchor["cert_id"],
                            "ski": ser_anchor["ski"],
                            "subject_name": ser_anchor["subject_name"],
                            "authority_type": ser_anchor["authority_type"],
                            "added_date": datetime.fromisoformat(ser_anchor["added_date"]),
                            "expiry_date": datetime.fromisoformat(ser_anchor["expiry_date"]),
                            "serial_number": ser_anchor["serial_number"],
                        }
                        self.trust_anchors.append(anchor_entry)
                        
                    except Exception as e:
                        self.logger.error(f"Errore ricaricamento trust anchor: {e}")

            self.logger.info(f"Metadata caricati con successo")
            self.logger.info(f"  CTL Number: {self.ctl_number}")
            self.logger.info(f"  Base CTL Number: {self.base_ctl_number}")
            self.logger.info(f"  Trust anchors ricaricati: {len(self.trust_anchors)}")

        except Exception as e:
            self.logger.info(f"Errore caricamento metadata: {e}")

    def get_statistics(self):
        """
        Restituisce statistiche sullo stato del Trust List Manager.

        Returns:
            dict con statistiche
        """
        stats = {
            "ctl_number": self.ctl_number,
            "base_ctl_number": self.base_ctl_number,
            "total_trust_anchors": len(self.trust_anchors),
            "delta_additions_pending": len(self.delta_additions),
            "delta_removals_pending": len(self.delta_removals),
            "link_certificates": len(self.link_certificates),
            "last_full_ctl": (
                self.last_full_ctl_time.isoformat() if self.last_full_ctl_time else None
            ),
            "trust_anchors_by_type": self._get_anchors_by_type(),
        }

        return stats

    def _get_anchors_by_type(self):
        """
        Conta trust anchors per tipo di autorità.

        Returns:
            dict con conteggi per tipo
        """
        counts = {}
        for anchor in self.trust_anchors:
            auth_type = anchor["authority_type"]
            counts[auth_type] = counts.get(auth_type, 0) + 1
        return counts
