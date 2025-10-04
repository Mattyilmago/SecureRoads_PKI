from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import os
import json
from utils.cert_utils import (
    get_certificate_ski,
    get_certificate_identifier,
    get_short_identifier,
    format_certificate_info,
)


class TrustListManager:
    """
    Gestisce la creazione e pubblicazione di Certificate Trust Lists (CTL).

    Concetti chiave:
    - Full CTL: Lista completa di tutte le CA fidate (whitelist)
    - Delta CTL: Lista incrementale di modifiche (aggiunte/rimozioni)
    - Link Certificates: Certificati che collegano CA diverse nella gerarchia
    - Trust Anchors: Punti di fiducia root per validazione catene

    Differenze con CRLManager:
    - CTL gestisce certificati FIDATI (whitelist) vs CRL gestisce REVOCATI (blacklist)
    - CTL usa formato ETSI TS 102941 vs CRL usa X.509 standard
    - CTL include Link Certificates per navigazione gerarchie
    """

    def __init__(self, root_ca, base_dir="./data/tlm/"):
        """
        Inizializza il Trust List Manager.

        Args:
            root_ca: Riferimento alla Root CA che firma le CTL
            base_dir: Directory base per salvare CTL e link certificates
        """
        self.root_ca = root_ca
        self.base_dir = base_dir

        # Percorsi file
        self.ctl_dir = os.path.join(base_dir, "ctl/")
        self.full_ctl_path = os.path.join(self.ctl_dir, "full_ctl.pem")
        self.delta_ctl_path = os.path.join(self.ctl_dir, "delta_ctl.pem")
        self.link_certs_dir = os.path.join(base_dir, "link_certificates/")
        self.metadata_path = os.path.join(self.ctl_dir, "ctl_metadata.json")

        # Crea directory
        for d in [self.ctl_dir, self.link_certs_dir]:
            os.makedirs(d, exist_ok=True)

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

        print(f"[TLM] TrustListManager inizializzato")
        print(f"[TLM] CTL Number attuale: {self.ctl_number}")
        print(f"[TLM] Base CTL Number: {self.base_ctl_number}")
        print(f"[TLM] Trust anchors caricati: {len(self.trust_anchors)}")

    def add_trust_anchor(self, certificate, authority_type="UNKNOWN"):
        """
        Aggiunge una CA fidata alla Certificate Trust List.

        Questo è l'equivalente "positivo" di add_revoked_certificate del CRLManager.
        Qui aggiungiamo certificati FIDATI invece che revocati.

        Args:
            certificate: Il certificato X.509 della CA da fidarsi (EA/AA)
            authority_type: Tipo di autorità ("EA", "AA", "RootCA")
        """
        # Usa Subject + SKI invece del serial number
        cert_id = get_certificate_identifier(certificate)
        ski = get_certificate_ski(certificate)
        subject_name = certificate.subject.rfc4514_string()
        added_date = datetime.now(timezone.utc)
        expiry_date = certificate.not_valid_after_utc

        print(f"[TLM] Aggiungendo trust anchor: {subject_name}")
        print(f"[TLM]   Identificatore: {cert_id}")
        print(f"[TLM]   SKI: {ski[:16]}...")
        print(f"[TLM]   Tipo: {authority_type}")
        print(f"[TLM]   Scadenza: {expiry_date}")

        # Controlla se già presente (usa SKI per confronto)
        if any(anchor["ski"] == ski for anchor in self.trust_anchors):
            print(f"[TLM] Trust anchor già presente nella lista")
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

        print(f"[TLM] Trust anchor aggiunto. Totale: {len(self.trust_anchors)}")
        print(f"[TLM] Aggiunte delta pending: {len(self.delta_additions)}")

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

        print(f"[TLM] Rimozione trust anchor: {subject_name}")
        print(f"[TLM]   Identificatore: {cert_id}")
        print(f"[TLM]   SKI: {ski[:16]}...")
        print(f"[TLM]   Motivo: {reason}")

        # Trova e rimuovi dalla lista completa (usa SKI per confronto)
        found = None
        for anchor in self.trust_anchors:
            if anchor["ski"] == ski:
                found = anchor
                break

        if not found:
            print(f"[TLM] Trust anchor non trovato nella lista")
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

        print(f"[TLM] Trust anchor rimosso. Totale: {len(self.trust_anchors)}")
        print(f"[TLM] Rimozioni delta pending: {len(self.delta_removals)}")

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
                    from cryptography.hazmat.primitives.asymmetric import ec
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.exceptions import InvalidSignature

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
                    print(f"[TLM] [WARNING] Firma non valida per {certificate.subject}: {e}")
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
        print(f"[TLM] === GENERAZIONE FULL CTL ===")

        # Incrementa CTL number
        self.ctl_number += 1
        self.base_ctl_number = self.ctl_number
        self.last_full_ctl_time = datetime.now(timezone.utc)

        # Pulisce trust anchors scaduti
        self._cleanup_expired_trust_anchors()

        print(f"[TLM] CTL Number: {self.ctl_number}")
        print(f"[TLM] Trust anchors attivi: {len(self.trust_anchors)}")

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
            print(f"[TLM]   {anchor['authority_type']}: {anchor['subject_name']}")

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

        print(f"[TLM] Full CTL salvata: {self.full_ctl_path}")

        # Salva anche metadata JSON
        metadata_ctl_path = self.full_ctl_path.replace(".pem", "_metadata.json")
        with open(metadata_ctl_path, "w") as f:
            json.dump(ctl_data, f, indent=2)

        print(f"[TLM] Metadata CTL salvati: {metadata_ctl_path}")

        # Reset delta changes (tutto è ora nella Full CTL)
        self.delta_additions = []
        self.delta_removals = []

        # Salva metadata manager
        self.save_metadata()

        print(f"[TLM] === FULL CTL PUBBLICATA ===")
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
        print(f"[TLM] === GENERAZIONE DELTA CTL ===")

        # Controlla se ci sono modifiche
        if not self.delta_additions and not self.delta_removals:
            print(f"[TLM] Nessuna modifica, Delta CTL non necessaria")
            return None

        # Incrementa CTL number
        self.ctl_number += 1

        print(f"[TLM] CTL Number: {self.ctl_number}")
        print(f"[TLM] Base CTL Number: {self.base_ctl_number}")
        print(f"[TLM] Aggiunte: {len(self.delta_additions)}")
        print(f"[TLM] Rimozioni: {len(self.delta_removals)}")

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
                print(f"[TLM]   + {anchor['authority_type']}: {anchor['subject_name']}")

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
                print(f"[TLM]   - {removal['cert_id']} ({removal['reason']})")

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

        print(f"[TLM] Delta CTL salvata: {self.delta_ctl_path}")

        # Salva metadata JSON
        metadata_delta_path = self.delta_ctl_path.replace(".pem", "_metadata.json")
        with open(metadata_delta_path, "w") as f:
            json.dump(delta_ctl_data, f, indent=2)

        print(f"[TLM] Metadata Delta CTL salvati: {metadata_delta_path}")

        # Salva metadata manager
        self.save_metadata()

        print(f"[TLM] === DELTA CTL PUBBLICATA ===")
        return delta_ctl_data

    def _generate_link_certificate_for_authority(self, authority_cert, authority_type):
        """
        Genera un Link Certificate che collega RootCA a questa autorità.

        I Link Certificates permettono di:
        - Navigare la gerarchia di fiducia
        - Validare catene di certificati
        - Verificare relazioni tra CA

        Args:
            authority_cert: Certificato dell'autorità (EA/AA)
            authority_type: Tipo di autorità ("EA", "AA")
        """
        print(f"[TLM] Generando Link Certificate: RootCA -> {authority_type}")

        # Il Link Certificate è essenzialmente una attestazione firmata
        # che dice "RootCA certifica che questa EA/AA è fidata"

        # In un'implementazione ETSI completa, questo sarebbe un certificato
        # con extension specifiche. Per ora usiamo un approccio semplificato.

        # Usa SKI invece di serial number per identificatori più robusti
        root_ca_ski = get_certificate_ski(self.root_ca.certificate)
        authority_ski = get_certificate_ski(authority_cert)
        authority_id = get_short_identifier(authority_cert)

        link_cert_info = {
            "link_id": f"LINK_{root_ca_ski[:8]}_to_{authority_ski[:8]}",
            "from_ca": "RootCA",
            "from_ski": root_ca_ski,
            "from_cert_id": get_short_identifier(self.root_ca.certificate),
            "to_ca": authority_type,
            "to_ski": authority_ski,
            "to_cert_id": authority_id,
            "to_subject": authority_cert.subject.rfc4514_string(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "purpose": f"Certifies trust relationship RootCA -> {authority_type}",
            # Mantieni serial numbers per backward compatibility
            "from_serial": self.root_ca.certificate.serial_number,
            "to_serial": authority_cert.serial_number,
        }

        self.link_certificates.append(link_cert_info)

        # Salva link certificate su file (usa identificatori leggibili nel nome)
        link_filename = f"link_RootCA_to_{authority_id}.json"
        link_path = os.path.join(self.link_certs_dir, link_filename)

        with open(link_path, "w") as f:
            json.dump(link_cert_info, f, indent=2)

        print(f"[TLM] Link Certificate salvato: {link_path}")

    def _remove_link_certificates_for_ski(self, ski):
        """
        Rimuove tutti i link certificates associati a un SKI.

        Args:
            ski: Subject Key Identifier del certificato
        """
        print(f"[TLM] Rimozione link certificates per SKI: {ski[:16]}...")

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
                        print(f"[TLM] Link certificate rimosso: {filename}")
            except (json.JSONDecodeError, FileNotFoundError):
                pass

    def publish_link_certificates(self):
        """
        Pubblica tutti i link certificates in un bundle.

        Questo bundle viene distribuito agli ITS-S insieme alla CTL
        per permettere la validazione completa delle catene.
        """
        print(f"[TLM] === PUBBLICAZIONE LINK CERTIFICATES ===")
        print(f"[TLM] Link certificates totali: {len(self.link_certificates)}")

        bundle_path = os.path.join(self.link_certs_dir, "link_certificates_bundle.json")

        bundle_data = {
            "version": "1.0",
            "issue_date": datetime.now(timezone.utc).isoformat(),
            "link_certificates": self.link_certificates,
        }

        with open(bundle_path, "w") as f:
            json.dump(bundle_data, f, indent=2)

        print(f"[TLM] Link certificates bundle salvato: {bundle_path}")
        print(f"[TLM] === PUBBLICAZIONE COMPLETATA ===")

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
        print(f"[TLM] === DISTRIBUZIONE CTL A ITS-S ===")
        print(f"[TLM] ITS-S destinatari: {len(itss_list)}")

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

                print(f"[TLM] CTL distribuita a: {itss.its_id}")
                distributed += 1
            except Exception as e:
                print(f"[TLM] Errore distribuzione a {itss.its_id}: {e}")

        print(f"[TLM] Distribuzione completata: {distributed}/{len(itss_list)} ITS-S")
        print(f"[TLM] === DISTRIBUZIONE TERMINATA ===")

    def get_ctl_for_download(self):
        """
        Restituisce la Full CTL in formato scaricabile.

        Questo metodo viene chiamato dagli ITS-S quando richiedono
        la CTL via API o download diretto.

        Returns:
            dict con metadata e percorso file CTL
        """
        if not os.path.exists(self.full_ctl_path):
            print(f"[TLM] Full CTL non disponibile")
            return None

        metadata_path = self.full_ctl_path.replace(".pem", "_metadata.json")

        ctl_info = {
            "ctl_number": self.ctl_number,
            "file_path": self.full_ctl_path,
            "metadata_path": metadata_path if os.path.exists(metadata_path) else None,
            "trust_anchors_count": len(self.trust_anchors),
            "last_update": self.last_full_ctl_time.isoformat() if self.last_full_ctl_time else None,
        }

        print(f"[TLM] CTL disponibile per download:")
        print(f"[TLM]   CTL Number: {ctl_info['ctl_number']}")
        print(f"[TLM]   Trust Anchors: {ctl_info['trust_anchors_count']}")

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
                    print(f"[TLM] Rimozione trust anchor scaduto: {anchor['subject_name']}")

        self.trust_anchors = filtered

        removed = old_count - len(self.trust_anchors)
        if removed > 0:
            print(f"[TLM] Pulizia: rimossi {removed} trust anchors scaduti")
            print(f"[TLM] Trust anchors attivi rimasti: {len(self.trust_anchors)}")

    def load_full_ctl(self):
        """
        Carica la Full CTL dal file.

        Returns:
            dict con metadata CTL o None se non esiste
        """
        metadata_path = self.full_ctl_path.replace(".pem", "_metadata.json")

        if not os.path.exists(metadata_path):
            print(f"[TLM] Full CTL metadata non trovati")
            return None

        with open(metadata_path, "r") as f:
            ctl_data = json.load(f)

        print(f"[TLM] Full CTL caricata:")
        print(f"[TLM]   CTL Number: {ctl_data['ctl_number']}")
        print(f"[TLM]   Trust Anchors: {len(ctl_data['trust_anchors'])}")
        print(f"[TLM]   Issue Date: {ctl_data['issue_date']}")

        return ctl_data

    def load_delta_ctl(self):
        """
        Carica la Delta CTL dal file.

        Returns:
            dict con metadata Delta CTL o None se non esiste
        """
        metadata_path = self.delta_ctl_path.replace(".pem", "_metadata.json")

        if not os.path.exists(metadata_path):
            print(f"[TLM] Delta CTL metadata non trovati")
            return None

        with open(metadata_path, "r") as f:
            delta_data = json.load(f)

        print(f"[TLM] Delta CTL caricata:")
        print(f"[TLM]   CTL Number: {delta_data['ctl_number']}")
        print(f"[TLM]   Base CTL Number: {delta_data['base_ctl_number']}")
        print(f"[TLM]   Aggiunte: {len(delta_data['to_be_added'])}")
        print(f"[TLM]   Rimozioni: {len(delta_data['to_be_removed'])}")

        return delta_data

    def save_metadata(self):
        """
        Salva metadata TLM su file JSON per persistenza.

        Simile a CRLManager, mantiene stato tra restart.
        """
        metadata = {
            "ctl_number": self.ctl_number,
            "base_ctl_number": self.base_ctl_number,
            "last_full_ctl_time": (
                self.last_full_ctl_time.isoformat() if self.last_full_ctl_time else None
            ),
            "trust_anchors_count": len(self.trust_anchors),
            "delta_additions_pending": len(self.delta_additions),
            "delta_removals_pending": len(self.delta_removals),
            "link_certificates_count": len(self.link_certificates),
        }

        with open(self.metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"[TLM] Metadata salvati: {self.metadata_path}")

    def load_metadata(self):
        """
        Carica metadata TLM da file JSON.
        """
        if not os.path.exists(self.metadata_path):
            print(f"[TLM] Nessun metadata esistente, inizializzo nuovo")
            return

        try:
            with open(self.metadata_path, "r") as f:
                metadata = json.load(f)

            self.ctl_number = metadata.get("ctl_number", 0)
            self.base_ctl_number = metadata.get("base_ctl_number", 0)

            last_full = metadata.get("last_full_ctl_time")
            if last_full:
                self.last_full_ctl_time = datetime.fromisoformat(last_full)

            print(f"[TLM] Metadata caricati con successo")
            print(f"[TLM]   CTL Number: {self.ctl_number}")
            print(f"[TLM]   Base CTL Number: {self.base_ctl_number}")

        except Exception as e:
            print(f"[TLM] Errore caricamento metadata: {e}")

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
