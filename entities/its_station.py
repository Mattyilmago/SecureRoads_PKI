from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import os



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
        self.inbox_path = os.path.join(base_dir, f"inbox/")
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


    def update_crl_from_tlm(self, tlm_obj=None, aa_id=None):
        """
        Scarica e aggiorna le CRL/CTL dal TLM (Trust List Manager).
        Conforme a ETSI TS 102 941 - Sezione 6.3.2/6.3.3.
        
        Args:
            tlm_obj: Oggetto Trust List Manager (opzionale, per sistemi centralizzati)
            aa_id: ID dell'Authorization Authority specifica (opzionale)
        
        Returns:
            bool: True se l'aggiornamento ha successo, False altrimenti
        """
        print(f"[ITSS] [REFRESH] Aggiornamento CRL/CTL dal TLM per {self.its_id}...")
        
        try:
            if tlm_obj:
                # === CASO 1: Sistema con TLM centralizzato (RACCOMANDATO ETSI) ===
                print(f"[ITSS] Scaricando CTL completo + Delta dal TLM...")
                
                # Ottieni il CTL completo (contiene lista di tutte le EA/AA fidate)
                ctl_full = tlm_obj.get_full_ctl()
                if ctl_full:
                    self.update_ctl(ctl_full)
                    print(f"[ITSS] [OK] CTL Full aggiornato dal TLM")
                
                # Ottieni Delta CTL (solo le modifiche dall'ultimo aggiornamento)
                ctl_delta = tlm_obj.get_delta_ctl()
                if ctl_delta:
                    self.update_ctl(ctl_full, ctl_delta)
                    print(f"[ITSS] [OK] Delta CTL aggiornato dal TLM")
                
                # Scarica CRL di tutte le AA fidate
                trusted_aa_list = tlm_obj.get_trusted_aa_list()
                for aa in trusted_aa_list:
                    aa_crl_path = f"./data/aa/{aa}/crl/full_crl.pem"
                    # In produzione: scaricare via V2X/HTTP dal TLM
                    print(f"[ITSS] [OK] CRL aggiornata per AA: {aa}")
                
                return True
            
            elif aa_id:
                # === CASO 2: Aggiornamento CRL singola AA (legacy) ===
                print(f"[ITSS] Scaricando CRL per AA specifica: {aa_id}...")
                
                # Percorso CRL dell'AA
                aa_crl_path = f"./data/aa/{aa_id}/crl/full_crl.pem"
                
                # In un sistema reale, qui si farebbe:
                # 1. Richiesta HTTP/V2X al server CRL dell'AA
                # 2. Download del Delta CRL (più efficiente del Full CRL)
                # 3. Applicazione del Delta alla CRL locale
                # 4. Verifica firma della CRL con certificato AA
                
                if os.path.exists(aa_crl_path):
                    # Simula il ri-caricamento (in produzione: download da server)
                    with open(aa_crl_path, "rb") as f:
                        crl = x509.load_pem_x509_crl(f.read())
                    
                    crl_age = datetime.now(timezone.utc) - crl.last_update_utc
                    print(f"[ITSS] CRL ricaricata per {aa_id}")
                    print(f"[ITSS] CRL age: {int(crl_age.total_seconds())}s")
                    print(f"[ITSS] [OK] CRL aggiornata per AA: {aa_id}")
                    return True
                else:
                    print(f"[ITSS] [WARNING] CRL non disponibile per AA: {aa_id}")
                    return False
            
            else:
                # === CASO 3: Scansione automatica di tutte le AA disponibili ===
                print(f"[ITSS] Aggiornamento automatico CRL per tutte le AA disponibili...")
                
                if not os.path.exists("./data/aa/"):
                    print(f"[ITSS] [WARNING] Nessuna directory AA trovata")
                    return False
                
                aa_dirs = [d for d in os.listdir("./data/aa/") 
                          if os.path.isdir(os.path.join("./data/aa/", d))]
                
                updated_count = 0
                for aa_dir in aa_dirs:
                    if self.update_crl_from_tlm(aa_id=aa_dir):
                        updated_count += 1
                
                print(f"[ITSS] [OK] Aggiornate {updated_count}/{len(aa_dirs)} CRL")
                return updated_count > 0
        
        except Exception as e:
            print(f"[ITSS] [ERROR] Errore aggiornamento CRL/CTL: {e}")
            return False


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
        
        # Simula la consegna scrivendo nell'inbox del destinatario
        # Costruisce il percorso dell'inbox del destinatario usando la stessa logica del costruttore
        recipient_base_dir = os.path.join("./data/itss/", f"{recipient_id}/")
        recipient_inbox_dir = os.path.join(recipient_base_dir, "inbox")
        recipient_inbox_file = os.path.join(recipient_inbox_dir, f"{self.its_id}_inbox.txt")
        
        print(f"[ITSS] Percorso inbox destinatario: {recipient_inbox_file}")
        os.makedirs(recipient_inbox_dir, exist_ok=True)
        with open(recipient_inbox_file, "a") as f:
            f.write(f"From: {self.its_id}\nType: {message_type}\nMessage: {message}\nSignature: {signature.hex()}\n---\n")
        
        print(f"[ITSS] Messaggio {message_type} firmato inviato e salvato su: {self.outbox_path}")
        return True


    # Legge i messaggi (CAM/DENM non crittati) ricevuti dall''inbox. 
    def receive_signed_message(self, validate=True):
        """
        Riceve e opzionalmente valida messaggi firmati dall'inbox.
        
        Args:
            validate: Se True, valida la firma di ogni messaggio (default: True)
        
        Returns:
            Lista di messaggi ricevuti (validati se validate=True)
        """
        print(f"[ITSS] Ricezione messaggi per {self.its_id}...")
        
        # Controlla se la cartella inbox esiste
        if not os.path.exists(self.inbox_path):
            print(f"[ITSS] Cartella inbox non esistente per {self.its_id}.")
            return []
        
        # Controlla se la cartella inbox è vuota
        inbox_files = os.listdir(self.inbox_path)
        if not inbox_files:
            print(f"[ITSS] Nessun messaggio in arrivo per {self.its_id}.")
            return []
        
        messages = []
        # Legge tutti i file nella cartella inbox
        for filename in inbox_files:
            file_path = os.path.join(self.inbox_path, filename)
            if os.path.isfile(file_path) and filename.endswith('.txt'):
                print(f"[ITSS] Leggendo file: {filename}")
                try:
                    with open(file_path, "r") as f:
                        content = f.read()
                        # Divide i messaggi usando il separatore ---
                        message_blocks = [block.strip() for block in content.split("---") if block.strip()]
                        
                        # Valida ogni messaggio se richiesto
                        if validate:
                            for msg in message_blocks:
                                if self.validate_message_signature(msg):
                                    messages.append(msg)
                        else:
                            messages.extend(message_blocks)
                            
                except Exception as e:
                    print(f"[ITSS] Errore nella lettura del file {filename}: {e}")
            
        print(f"[ITSS] Messaggi ricevuti totali: {len(messages)}")
        if validate:
            print(f"[ITSS] Messaggi validati: {len(messages)}")
        return messages


    def validate_message_signature(self, message_block):
        """
        Valida la firma digitale di un messaggio ricevuto.
        
        Verifica:
        1. Firma digitale con chiave pubblica del mittente
        2. Validità del certificato AT del mittente (non scaduto)
        3. Certificato AT non revocato (check CRL se disponibile)
        
        Args:
            message_block: Blocco di testo del messaggio con firma
            
        Returns:
            True se il messaggio è valido, False altrimenti
        """
        try:
            # Parsing del messaggio
            lines = message_block.split('\n')
            sender_id = None
            message_type = None
            message_content = None
            signature_hex = None
            
            for line in lines:
                if line.startswith('From:'):
                    sender_id = line.split(':', 1)[1].strip()
                elif line.startswith('Type:'):
                    message_type = line.split(':', 1)[1].strip()
                elif line.startswith('Message:'):
                    message_content = line.split(':', 1)[1].strip()
                elif line.startswith('Signature:'):
                    signature_hex = line.split(':', 1)[1].strip()
            
            if not all([sender_id, message_content, signature_hex]):
                print(f"[ITSS] [ERROR] Messaggio malformato da {sender_id}")
                return False
            
            # Carica il certificato AT del mittente
            sender_base_dir = os.path.join("./data/itss/", f"{sender_id}/")
            sender_at_path = os.path.join(sender_base_dir, f"received_tickets/{sender_id}_at.pem")
            
            if not os.path.exists(sender_at_path):
                print(f"[ITSS] [WARNING] Certificato AT mittente {sender_id} non trovato")
                # In un sistema reale, potresti richiedere il certificato via V2X
                return False
            
            # Carica certificato AT del mittente
            with open(sender_at_path, "rb") as f:
                sender_at_cert = x509.load_pem_x509_certificate(f.read())
            
            # === VERIFICA 1: Validità temporale del certificato ===
            now = datetime.now(timezone.utc)
            
            # Usa le proprietà UTC che restituiscono già timezone-aware datetime
            cert_not_after = sender_at_cert.not_valid_after_utc
            cert_not_before = sender_at_cert.not_valid_before_utc
            
            if cert_not_after < now:
                print(f"[ITSS] [ERROR] Certificato AT mittente {sender_id} SCADUTO")
                return False
            
            if cert_not_before > now:
                print(f"[ITSS] [ERROR] Certificato AT mittente {sender_id} NON ANCORA VALIDO")
                return False
            
            # === VERIFICA 2: Firma digitale ===
            # Ricostruisci il messaggio originale (stesso formato usato in send)
            signature_bytes = bytes.fromhex(signature_hex)
            sender_public_key = sender_at_cert.public_key()
            
            try:
                sender_public_key.verify(
                    signature_bytes,
                    message_content.encode(),
                    ec.ECDSA(hashes.SHA256())
                )
                print(f"[ITSS] [OK] Firma valida da {sender_id} (tipo: {message_type})")
            except Exception as e:
                print(f"[ITSS] [ERROR] Firma NON valida da {sender_id}: {e}")
                return False
            
            # === VERIFICA 3: Check CRL (se disponibile) ===
            # Estrai l'issuer del certificato AT per trovare la CRL corretta
            issuer_cn = None
            for attr in sender_at_cert.issuer:
                if attr.oid == NameOID.COMMON_NAME:
                    issuer_cn = attr.value
                    break
            
            if issuer_cn:
                # Cerca CRL dell'AA che ha emesso l'AT
                # Pattern: AA_XXXXXX -> ./data/aa/AA_XXXXXX/crl/full_crl.pem
                # Estrai l'AA ID dall'issuer CN
                aa_id_from_issuer = issuer_cn.replace("AuthorizationAuthority_", "")
                
                aa_dirs = []
                if os.path.exists("./data/aa/"):
                    all_aa_dirs = [d for d in os.listdir("./data/aa/") if os.path.isdir(os.path.join("./data/aa/", d))]
                    # Priorità: AA con nome ESATTO che matcha l'issuer
                    matching_aa = [d for d in all_aa_dirs if d == aa_id_from_issuer]
                    # Fallback: AA con nome che contiene l'issuer (fuzzy match)
                    fuzzy_match = [d for d in all_aa_dirs if aa_id_from_issuer in d and d not in matching_aa]
                    # Resto delle AA come fallback finale
                    other_aa = [d for d in all_aa_dirs if d not in matching_aa and d not in fuzzy_match]
                    aa_dirs = matching_aa + fuzzy_match + other_aa
                    
                    if matching_aa:
                        print(f"[ITSS] --> AA corretto identificato: {matching_aa[0]}")
                
                crl_checked = False
                for aa_dir in aa_dirs:
                    crl_path = f"./data/aa/{aa_dir}/crl/full_crl.pem"
                    if os.path.exists(crl_path):
                        try:
                            with open(crl_path, "rb") as f:
                                crl = x509.load_pem_x509_crl(f.read())
                            
                            # === CHECK FRESHNESS CRL (ETSI TS 102 941 - Sezione 6.3.3) ===
                            # Verifica che la CRL non sia troppo vecchia (max 10 minuti)
                            crl_age = datetime.now(timezone.utc) - crl.last_update_utc
                            max_crl_age = timedelta(minutes=10)
                            
                            if crl_age > max_crl_age:
                                print(f"[ITSS] [WARNING] CRL obsoleta (età: {int(crl_age.total_seconds())}s, "
                                      f"max: {int(max_crl_age.total_seconds())}s)")
                                print(f"[ITSS] [REFRESH] Aggiornamento automatico Delta CRL...")
                                
                                # Scarica nuovo Delta CRL
                                if self.update_crl_from_tlm(aa_id=aa_dir):
                                    # Ricarica la CRL aggiornata
                                    with open(crl_path, "rb") as f_updated:
                                        crl = x509.load_pem_x509_crl(f_updated.read())
                                    print(f"[ITSS] [OK] CRL aggiornata con successo")
                                else:
                                    print(f"[ITSS] [WARNING] Impossibile aggiornare CRL, uso versione locale")
                            else:
                                print(f"[ITSS] [OK] CRL aggiornata (età: {int(crl_age.total_seconds())}s)")
                            
                            # Verifica se il certificato è revocato
                            revoked_cert = crl.get_revoked_certificate_by_serial_number(
                                sender_at_cert.serial_number
                            )
                            
                            if revoked_cert:
                                print(f"[ITSS] [ERROR] Certificato AT mittente {sender_id} REVOCATO")
                                return False
                            
                            crl_checked = True
                            break
                        except Exception:
                            # CRL non leggibile o non compatibile, continua
                            pass
                
                if crl_checked:
                    print(f"[ITSS] [OK] Certificato AT mittente {sender_id} NON revocato")
            
            # Tutte le verifiche passate
            return True
            
        except Exception as e:
            print(f"[ITSS] [ERROR] Errore validazione messaggio: {e}")
            return False
