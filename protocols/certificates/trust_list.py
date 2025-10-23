"""
ETSI TS 102941 Trust List (CTL) Encoding (ASN.1 OER)

Implementa la codifica ASN.1 OER per Certificate Trust Lists (CTL) 
secondo lo standard ETSI TS 102941 V2.1.1 Section 6.5.

Standard Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- IEEE 1609.2 - Wireless Access in Vehicular Environments (WAVE)

ASN.1 Schema (ETSI TS 102941 Section 6.5):
    ToBeSignedTlmCtl ::= SEQUENCE {
        version Version,
        thisUpdate Time32,
        nextUpdate Time32,
        isFullCtl BOOLEAN,
        ctlSequence INTEGER (0..255),
        ctlCommands SEQUENCE (SIZE(1..MAX)) OF CtlCommand,
        ...
    }
    
    CtlCommand ::= CHOICE {
        add CtlEntry,
        delete CtlEntry
    }
    
    CtlEntry ::= SEQUENCE {
        rca HashedId8,
        ea HashedId8 OPTIONAL,
        aa HashedId8 OPTIONAL,
        its HashedId8 OPTIONAL,
        ...
    }

Author: SecureRoad PKI Project
Date: October 2025
"""

import struct
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Import centralized ETSI utilities from core modules
from protocols.core.primitives import compute_hashed_id8, time32_decode, time32_encode


class TrustListEncoder:
    """
    Codifica e decodifica Certificate Trust Lists (CTL) in formato ASN.1 OER ETSI-compliant.
    
    Supporta:
    - Full CTL: Lista completa di tutti i trust anchors
    - Delta CTL: Solo modifiche (add/delete) dall'ultima Full CTL
    - ToBeSignedTlmCtl encoding secondo ETSI TS 102941
    - Time32 encoding (Unix timestamp relativo a ETSI epoch 2004-01-01)
    - HashedId8 identificatori per certificati
    
    Uses centralized ETSI utilities from core modules (DRY compliance).
    """
    
    # ETSI TS 102941 constants
    CTL_VERSION = 1
    SIGNATURE_ALGORITHM_ECDSA_SHA256 = 0
    
    # CTL Command types
    CTL_COMMAND_ADD = 0x00
    CTL_COMMAND_DELETE = 0x01
    
    # Delegate to centralized utilities from core modules (DRY compliance)
    time32_encode = staticmethod(time32_encode)
    time32_decode = staticmethod(time32_decode)
    
    def encode_ctl_entry(
        self,
        cert_der: bytes,
        authority_type: str
    ) -> bytes:
        """
        Codifica singolo CtlEntry in ASN.1 OER.
        
        ETSI TS 102941 Section 6.5:
        CtlEntry ::= SEQUENCE {
            rca HashedId8,           -- RootCA hash (sempre presente)
            ea HashedId8 OPTIONAL,   -- EA hash (se authority_type = EA)
            aa HashedId8 OPTIONAL,   -- AA hash (se authority_type = AA)
            its HashedId8 OPTIONAL,  -- ITS-S hash (se authority_type = ITS)
        }
        
        Args:
            cert_der: Certificato in DER
            authority_type: Tipo autorità ("RCA", "EA", "AA", "ITS")
            
        Returns:
            bytes: CtlEntry codificato
        """
        hashed_id8 = compute_hashed_id8(cert_der)
        
        # Formato semplificato ASN.1 OER:
        # [type(1) | hashed_id8(8)]
        encoded = bytearray()
        
        # Authority type tag
        type_map = {
            "RCA": 0x00,
            "EA": 0x01,
            "AA": 0x02,
            "ITS": 0x03,
        }
        
        if authority_type not in type_map:
            raise ValueError(f"Invalid authority_type: {authority_type}")
        
        encoded.append(type_map[authority_type])
        
        # HashedId8 (8 bytes)
        encoded.extend(hashed_id8)
        
        return bytes(encoded)
    
    def encode_ctl_command(
        self,
        command_type: str,
        cert_der: bytes,
        authority_type: str
    ) -> bytes:
        """
        Codifica singolo CtlCommand (add o delete).
        
        ETSI TS 102941 Section 6.5:
        CtlCommand ::= CHOICE {
            add CtlEntry,
            delete CtlEntry
        }
        
        Args:
            command_type: "add" o "delete"
            cert_der: Certificato DER
            authority_type: Tipo autorità
            
        Returns:
            bytes: CtlCommand codificato
        """
        # Command type (1 byte)
        if command_type == "add":
            cmd_byte = self.CTL_COMMAND_ADD
        elif command_type == "delete":
            cmd_byte = self.CTL_COMMAND_DELETE
        else:
            raise ValueError(f"Invalid command_type: {command_type}")
        
        # Encode entry
        entry = self.encode_ctl_entry(cert_der, authority_type)
        
        # Formato: [cmd_type(1) | entry_len(2) | entry]
        encoded = bytearray()
        encoded.append(cmd_byte)
        encoded.extend(struct.pack(">H", len(entry)))
        encoded.extend(entry)
        
        return bytes(encoded)
    
    def encode_to_be_signed_ctl(
        self,
        ctl_number: int,
        this_update: datetime,
        next_update: datetime,
        is_full_ctl: bool,
        commands: List[Tuple[str, bytes, str]]  # (cmd_type, cert_der, authority_type)
    ) -> bytes:
        """
        Codifica ToBeSignedTlmCtl in ASN.1 OER.
        
        ETSI TS 102941 Section 6.5:
        ToBeSignedTlmCtl ::= SEQUENCE {
            version Version,           -- 1 byte
            thisUpdate Time32,         -- 4 bytes
            nextUpdate Time32,         -- 4 bytes
            isFullCtl BOOLEAN,         -- 1 byte
            ctlSequence INTEGER,       -- 1 byte (0..255)
            ctlCommands SEQUENCE OF,   -- variable
        }
        
        Args:
            ctl_number: Numero sequenziale CTL
            this_update: Data emissione CTL
            next_update: Data prossimo aggiornamento
            is_full_ctl: True se Full CTL, False se Delta CTL
            commands: Lista di comandi [(type, cert_der, auth_type), ...]
            
        Returns:
            bytes: ToBeSignedTlmCtl codificato
        """
        encoded = bytearray()
        
        # Version (1 byte)
        encoded.append(self.CTL_VERSION)
        
        # thisUpdate (Time32, 4 bytes)
        this_time32 = self.time32_encode(this_update)
        encoded.extend(struct.pack(">I", this_time32))
        
        # nextUpdate (Time32, 4 bytes)
        next_time32 = self.time32_encode(next_update)
        encoded.extend(struct.pack(">I", next_time32))
        
        # isFullCtl (1 byte: 0x01 = True, 0x00 = False)
        encoded.append(0x01 if is_full_ctl else 0x00)
        
        # ctlSequence (1 byte, solo i primi 8 bit di ctl_number)
        encoded.append(ctl_number & 0xFF)
        
        # ctlCommands count (2 bytes)
        encoded.extend(struct.pack(">H", len(commands)))
        
        # ctlCommands (variable)
        for cmd_type, cert_der, auth_type in commands:
            cmd_encoded = self.encode_ctl_command(cmd_type, cert_der, auth_type)
            encoded.extend(cmd_encoded)
        
        return bytes(encoded)
    
    def sign_ctl(
        self,
        to_be_signed: bytes,
        private_key,
        algorithm: str = "ECDSA-SHA256"
    ) -> bytes:
        """
        Firma ToBeSignedTlmCtl con ECDSA.
        
        ETSI TS 103097: Signature using ECDSA-SHA256 on curve NIST P-256
        
        Args:
            to_be_signed: Bytes da firmare
            private_key: Chiave privata ECC
            algorithm: Algoritmo firma (default: ECDSA-SHA256)
            
        Returns:
            bytes: Firma ECDSA (64 bytes: r + s, 32 bytes each)
        """
        if algorithm != "ECDSA-SHA256":
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")
        
        # Firma con ECDSA-SHA256
        signature_der = private_key.sign(to_be_signed, ec.ECDSA(hashes.SHA256()))
        
        # ETSI richiede formato raw (r || s) non DER
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        
        r, s = decode_dss_signature(signature_der)
        
        # 32 bytes per r, 32 bytes per s (NIST P-256)
        signature_raw = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
        
        return signature_raw
    
    def encode_full_ctl(
        self,
        ctl_number: int,
        this_update: datetime,
        next_update: datetime,
        trust_anchors: List[Tuple[bytes, str]],  # (cert_der, authority_type)
        private_key
    ) -> bytes:
        """
        Codifica Full CTL completa con firma.
        
        Full CTL = ToBeSignedTlmCtl + Signature
        
        Args:
            ctl_number: Numero sequenziale CTL
            this_update: Data emissione
            next_update: Data prossimo aggiornamento
            trust_anchors: Lista di trust anchors [(cert_der, auth_type), ...]
            private_key: Chiave privata per firma
            
        Returns:
            bytes: Full CTL codificata e firmata
        """
        # Costruisci comandi: tutti "add" per Full CTL
        commands = [("add", cert_der, auth_type) for cert_der, auth_type in trust_anchors]
        
        # Codifica ToBeSignedTlmCtl
        to_be_signed = self.encode_to_be_signed_ctl(
            ctl_number=ctl_number,
            this_update=this_update,
            next_update=next_update,
            is_full_ctl=True,
            commands=commands
        )
        
        # Firma
        signature = self.sign_ctl(to_be_signed, private_key)
        
        # Full CTL = [tbs_len(4) | to_be_signed | signature(64)]
        encoded = bytearray()
        encoded.extend(struct.pack(">I", len(to_be_signed)))
        encoded.extend(to_be_signed)
        encoded.extend(signature)
        
        return bytes(encoded)
    
    def encode_delta_ctl(
        self,
        ctl_number: int,
        this_update: datetime,
        next_update: datetime,
        additions: List[Tuple[bytes, str]],  # (cert_der, authority_type)
        removals: List[Tuple[bytes, str]],   # (cert_der, authority_type)
        private_key
    ) -> bytes:
        """
        Codifica Delta CTL con firma.
        
        Delta CTL = ToBeSignedTlmCtl + Signature
        Contiene solo modifiche (add + delete)
        
        Args:
            ctl_number: Numero sequenziale CTL
            this_update: Data emissione
            next_update: Data prossimo aggiornamento
            additions: Lista trust anchors da aggiungere
            removals: Lista trust anchors da rimuovere
            private_key: Chiave privata per firma
            
        Returns:
            bytes: Delta CTL codificata e firmata
        """
        # Costruisci comandi: prima add, poi delete
        commands = []
        commands.extend([("add", cert_der, auth_type) for cert_der, auth_type in additions])
        commands.extend([("delete", cert_der, auth_type) for cert_der, auth_type in removals])
        
        # Codifica ToBeSignedTlmCtl
        to_be_signed = self.encode_to_be_signed_ctl(
            ctl_number=ctl_number,
            this_update=this_update,
            next_update=next_update,
            is_full_ctl=False,
            commands=commands
        )
        
        # Firma
        signature = self.sign_ctl(to_be_signed, private_key)
        
        # Delta CTL = [tbs_len(4) | to_be_signed | signature(64)]
        encoded = bytearray()
        encoded.extend(struct.pack(">I", len(to_be_signed)))
        encoded.extend(to_be_signed)
        encoded.extend(signature)
        
        return bytes(encoded)
    
    def decode_ctl(self, encoded: bytes) -> Dict:
        """
        Decodifica CTL (Full o Delta) da ASN.1 OER.
        
        Args:
            encoded: CTL codificata
            
        Returns:
            Dict con campi decodificati
        """
        offset = 0
        
        # TBS length (4 bytes)
        tbs_len = struct.unpack(">I", encoded[offset:offset+4])[0]
        offset += 4
        
        # ToBeSignedTlmCtl
        to_be_signed = encoded[offset:offset+tbs_len]
        offset += tbs_len
        
        # Signature (64 bytes)
        signature = encoded[offset:offset+64]
        offset += 64
        
        # Decodifica ToBeSignedTlmCtl
        tbs_offset = 0
        
        # Version (1 byte)
        version = to_be_signed[tbs_offset]
        tbs_offset += 1
        
        # thisUpdate (4 bytes)
        this_time32 = struct.unpack(">I", to_be_signed[tbs_offset:tbs_offset+4])[0]
        this_update = self.time32_decode(this_time32)
        tbs_offset += 4
        
        # nextUpdate (4 bytes)
        next_time32 = struct.unpack(">I", to_be_signed[tbs_offset:tbs_offset+4])[0]
        next_update = self.time32_decode(next_time32)
        tbs_offset += 4
        
        # isFullCtl (1 byte)
        is_full_ctl = to_be_signed[tbs_offset] == 0x01
        tbs_offset += 1
        
        # ctlSequence (1 byte)
        ctl_sequence = to_be_signed[tbs_offset]
        tbs_offset += 1
        
        # ctlCommands count (2 bytes)
        cmd_count = struct.unpack(">H", to_be_signed[tbs_offset:tbs_offset+2])[0]
        tbs_offset += 2
        
        # Parse commands
        commands = []
        for _ in range(cmd_count):
            # Command type (1 byte)
            cmd_type = to_be_signed[tbs_offset]
            tbs_offset += 1
            
            # Entry length (2 bytes)
            entry_len = struct.unpack(">H", to_be_signed[tbs_offset:tbs_offset+2])[0]
            tbs_offset += 2
            
            # Entry (variable)
            entry = to_be_signed[tbs_offset:tbs_offset+entry_len]
            tbs_offset += entry_len
            
            # Decode entry
            auth_type_byte = entry[0]
            hashed_id8 = entry[1:9].hex()
            
            type_map = {0x00: "RCA", 0x01: "EA", 0x02: "AA", 0x03: "ITS"}
            auth_type = type_map.get(auth_type_byte, "UNKNOWN")
            
            commands.append({
                "type": "add" if cmd_type == self.CTL_COMMAND_ADD else "delete",
                "authority_type": auth_type,
                "hashed_id8": hashed_id8
            })
        
        return {
            "version": version,
            "this_update": this_update,
            "next_update": next_update,
            "is_full_ctl": is_full_ctl,
            "ctl_sequence": ctl_sequence,
            "commands": commands,
            "signature": signature.hex()
        }
    
    def verify_ctl_signature(
        self,
        encoded: bytes,
        public_key
    ) -> bool:
        """
        Verifica firma ECDSA di una CTL.
        
        Args:
            encoded: CTL codificata completa
            public_key: Chiave pubblica ECC dell'issuer
            
        Returns:
            bool: True se firma valida
        """
        try:
            # Estrai TBS e signature
            tbs_len = struct.unpack(">I", encoded[0:4])[0]
            to_be_signed = encoded[4:4+tbs_len]
            signature_raw = encoded[4+tbs_len:4+tbs_len+64]
            
            # Converti signature raw a DER
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            
            r = int.from_bytes(signature_raw[:32], byteorder="big")
            s = int.from_bytes(signature_raw[32:64], byteorder="big")
            signature_der = encode_dss_signature(r, s)
            
            # Verifica
            public_key.verify(signature_der, to_be_signed, ec.ECDSA(hashes.SHA256()))
            
            return True
            
        except Exception as e:
            return False
