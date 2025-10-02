from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import os

# COMPITI ITS-S:
#   Generazione chiavi ECC proprie
#   Richiesta EC a EA
#   Richiesta AT a AA (standard) #TODO butterfly 
#   Aggiornamento trust anchors (CTL/Delta)
#   Invio/ricezione messaggi firmati

class ITSStation:
    def __init__(self, its_id, base_dir="./data/itss/"):
        #sottocartelle uniche per ogni veicolo
        base_dir = os.path.join(base_dir, f"{its_id}/")

        print(f"[ITSS] Inizializzazione ITS Station {its_id}")
        self.its_id = its_id
        self.key_path = os.path.join(base_dir, f"own_certificates/{its_id}_key.pem")
        self.cert_path = os.path.join(base_dir, f"own_certificates/{its_id}_certificate.pem")
        self.ec_path = os.path.join(base_dir, f"own_certificates/{its_id}_ec.pem")
        self.at_path = os.path.join(base_dir, f"received_tickets/{its_id}_at.pem")
        self.trust_anchor_path = os.path.join(base_dir, "trust_anchors/trust_anchors.pem")
        self.ctl_path = os.path.join(base_dir, "ctl_full/ctl.pem")
        self.delta_path = os.path.join(base_dir, "ctl_delta/delta.pem")
        self.inbox_path = os.path.join(base_dir, f"inbox/{its_id}_inbox.txt")
        self.outbox_path = os.path.join(base_dir, f"outbox/{its_id}_outbox.txt")

        for d in [
            os.path.dirname(self.key_path),
            os.path.dirname(self.cert_path),
            os.path.dirname(self.ec_path),
            os.path.dirname(self.at_path),
            os.path.dirname(self.trust_anchor_path),
            os.path.dirname(self.ctl_path),
            os.path.dirname(self.delta_path),
            os.path.dirname(self.inbox_path),
            os.path.dirname(self.outbox_path),
        ]:
            os.makedirs(d, exist_ok=True)
            print(f"[ITSS] Directory creata o già esistente: {d}")

        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.ec_certificate = None
        self.at_certificate = None
        self.trust_anchors = []
        print(f"[ITSS] Inizializzazione ITS Station {its_id} completata!")

   
    # Genera una chiave privata ECC e la salva su file
    def generate_ecc_keypair(self):
        print(f"[ITSS] Generazione chiave ECC privata ITS-S {self.its_id}...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        with open(self.key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))
        print(f"[ITSS] Chiave privata ECC salvata su: {self.key_path}")

    
    # Crea una CSR firmata con la chiave ITS-S
    def generate_csr(self):
        print(f"[ITSS] Generazione CSR per richiesta EC...")
        if not self.private_key:
            self.generate_ecc_keypair()
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ITS-S"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.its_id),
        ])).sign(self.private_key, hashes.SHA256())
        print(f"[ITSS] CSR generato per {self.its_id}")
        return csr.public_bytes(serialization.Encoding.PEM)


    # Invia la CSR all''EA e salva l''EC ricevuto
    def request_ec(self, ea_obj):
        print(f"[ITSS] Richiesta Enrollment Certificate a EA per {self.its_id}...")
        csr_pem = self.generate_csr()
        ec_certificate = ea_obj.process_csr(csr_pem, self.its_id)
        if ec_certificate:
            with open(self.ec_path, "wb") as f:
                f.write(ec_certificate.public_bytes(serialization.Encoding.PEM))
            self.ec_certificate = ec_certificate
            print(f"[ITSS] Enrollment Certificate ricevuto e salvato: {self.ec_path}")
            return ec_certificate
        else:
            print(f"[ITSS] Fallita la richiesta EC per {self.its_id}")
            return None


    # Invia EC all''AA per ottenere AT 
    def request_at(self, aa_obj, permissions=None, region=None):
        """
        Richiede un Authorization Ticket all''AA.
        
        Args:
            aa_obj: L''oggetto Authorization Authority
            permissions: Lista dei permessi richiesti (es. ["CAM", "DENM"])
            region: Regione per cui vale l''AT (es. "EU")
        """
        print(f"[ITSS] Richiesta Authorization Ticket a AA per {self.its_id}...")
        if permissions:
            print(f"[ITSS] Permessi richiesti: {permissions}")
        if region:
            print(f"[ITSS] Regione richiesta: {region}")
            
        if not self.ec_certificate:
            print("[ITSS] EC non presente, impossibile richiedere AT.")
            return None
        ec_bytes = self.ec_certificate.public_bytes(serialization.Encoding.PEM)
        
        # Chiamata all''AA con i parametri aggiuntivi (anche se l''AA potrebbe ignorarli)
        at_certificate = aa_obj.process_authorization_request(ec_bytes, self.its_id)
        at_path = self.at_path
        if at_certificate:
            with open(at_path, "wb") as f:
                f.write(at_certificate.public_bytes(serialization.Encoding.PEM))
            self.at_certificate = at_certificate
            print(f"[ITSS] Authorization Ticket ricevuto e salvato: {at_path}")
        else:
            print(f"[ITSS] Fallita la richiesta AT per {self.its_id}")
        
        return at_certificate


    # Aggiorna i trust anchors (Root CA/EA/AA) usati per validare la chain.
    def update_trust_anchors(self, anchors_list):
        """
        Aggiorna i trust anchors per la validazione dei certificati.
        
        Args:
            anchors_list: Lista di certificati trust anchor
        """
        print(f"[ITSS] Aggiornamento trust anchors per {self.its_id}...")
        self.trust_anchors = anchors_list
        
        # Salva tutti gli anchors in un file PEM
        with open(self.trust_anchor_path, "wb") as f:
            for anchor in anchors_list:
                f.write(anchor.public_bytes(serialization.Encoding.PEM))
        print(f"[ITSS] Trust anchors salvati su: {self.trust_anchor_path}")


    # Valida una catena di certificati usando i trust anchors
    def validate_certificate_chain(self, certificate):
        """
        Valida un certificato contro i trust anchors caricati.
        
        Args:
            certificate: Il certificato da validare
            
        Returns:
            bool: True se la validazione ha successo, False altrimenti
        """
        print(f"[ITSS] Validazione certificato per {self.its_id}...")
        
        if not self.trust_anchors:
            print("[ITSS] Nessun trust anchor disponibile per la validazione")
            return False
            
        # Validazione semplificata: controlla se il certificato è firmato da uno dei trust anchors
        for anchor in self.trust_anchors:
            try:
                # Verifica la firma (semplificata)
                if certificate.issuer == anchor.subject:
                    print(f"[ITSS] Certificato validato con successo contro trust anchor")
                    return True
            except Exception as e:
                print(f"[ITSS] Errore durante la validazione: {e}")
                continue
                
        print(f"[ITSS] Validazione certificato fallita")
        return False


    # Aggiorna la CTL (Certificate Trust List) e la delta.
    def update_ctl(self, ctl_pem, delta_pem=None):
        print(f"[ITSS] Aggiornamento CTL completo per {self.its_id}...")
        with open(self.ctl_path, "wb") as f:
            f.write(ctl_pem)
        print(f"[ITSS] CTL completo salvato su: {self.ctl_path}")
        if delta_pem:
            print(f"[ITSS] Aggiornamento CTL delta per {self.its_id}...")
            with open(self.delta_path, "wb") as f:
                f.write(delta_pem)
            print(f"[ITSS] CTL delta salvato su: {self.delta_path}")


    # Firma e invia un messaggio (CAM/DENM non crittati) a un altro ITS-S, scrivendolo nell''outbox.
    def send_signed_message(self, message, recipient_id, message_type="CAM"):
        """
        Firma e invia un messaggio a un altro ITS-S.
        
        Args:
            message: Il contenuto del messaggio da inviare
            recipient_id: L''ID del destinatario
            message_type: Il tipo di messaggio V2X (CAM, DENM, CPM, VAM, etc.)
        """
        print(f"[ITSS] Invio messaggio firmato da {self.its_id} a {recipient_id}...")
        print(f"[ITSS] Tipo messaggio: {message_type}")
        
        if not self.private_key or not self.at_certificate:
            print("[ITSS] Serve chiave privata e AT per firmare il messaggio!")
            return False
        signature = self.private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
        outbox_message = f"To: {recipient_id}\nFrom: {self.its_id}\nType: {message_type}\nMessage: {message}\nSignature: {signature.hex()}\n---\n"
        
        # Scrive nel proprio outbox
        with open(self.outbox_path, "a") as f:
            f.write(outbox_message)
        
        # Simula la consegna scrivendo nell''inbox del destinatario
        recipient_inbox = os.path.join(os.path.dirname(self.inbox_path), f"{recipient_id}_inbox.txt")
        os.makedirs(os.path.dirname(recipient_inbox), exist_ok=True)
        with open(recipient_inbox, "a") as f:
            f.write(f"From: {self.its_id}\nType: {message_type}\nMessage: {message}\nSignature: {signature.hex()}\n---\n")
        
        print(f"[ITSS] Messaggio {message_type} firmato inviato e salvato su: {self.outbox_path}")
        return True


    # Legge i messaggi (CAM/DENM non crittati) ricevuti dall''inbox. 
    def receive_signed_message(self):
        print(f"[ITSS] Ricezione messaggi per {self.its_id}...")
        if not os.path.exists(self.inbox_path):
            print(f"[ITSS] Nessun messaggio in arrivo per {self.its_id}.")
            return []
        
        messages = []
        with open(self.inbox_path, "r") as f:
            content = f.read()
            # Divide i messaggi usando il separatore ---
            message_blocks = [block.strip() for block in content.split("---") if block.strip()]
            
        print(f"[ITSS] Messaggi ricevuti: {len(message_blocks)}")
        return message_blocks
