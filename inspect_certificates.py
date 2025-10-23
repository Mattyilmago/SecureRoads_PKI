"""
Script per ispezionare i certificati OER generati dalle entità PKI

Mostra il contenuto dettagliato dei certificati Root CA, EA e AA
codificati in formato ASN.1 OER secondo ETSI TS 103097.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone
from protocols.messages.encoder import asn1_compiler
from protocols.core.primitives import compute_hashed_id8, time32_decode


def format_bytes(data: bytes, max_length: int = 32) -> str:
    """Formatta bytes per visualizzazione"""
    hex_str = data.hex()
    if len(hex_str) > max_length * 2:
        return f"{hex_str[:max_length*2]}... ({len(data)} bytes)"
    return f"{hex_str} ({len(data)} bytes)"


def decode_public_key(verify_key_indicator):
    """Decodifica la chiave pubblica dal certificato"""
    try:
        choice_name, choice_value = verify_key_indicator
        if choice_name == 'verificationKey':
            pk_choice_name, pk_choice_value = choice_value
            if pk_choice_name == 'ecdsaNistP256':
                coord_type, coord_value = pk_choice_value
                return {
                    'algorithm': 'ECDSA NIST P-256',
                    'format': coord_type,
                    'value': format_bytes(coord_value, 16)
                }
        return {'raw': str(verify_key_indicator)}
    except Exception as e:
        return {'error': str(e)}


def decode_certificate_id(cert_id):
    """Decodifica l'ID del certificato"""
    try:
        choice_name, choice_value = cert_id
        return {
            'type': choice_name,
            'value': choice_value if isinstance(choice_value, str) else format_bytes(choice_value, 8)
        }
    except Exception as e:
        return {'error': str(e)}


def decode_issuer_identifier(issuer):
    """Decodifica l'issuer identifier"""
    try:
        choice_name, choice_value = issuer
        if choice_name == 'self':
            return {
                'type': 'Self-Signed',
                'hash_algorithm': choice_value
            }
        elif choice_name == 'sha256AndDigest':
            return {
                'type': 'SHA-256 Digest',
                'hashedId8': format_bytes(choice_value, 8)
            }
        return {'raw': str(issuer)}
    except Exception as e:
        return {'error': str(e)}


def decode_validity_period(validity):
    """Decodifica il periodo di validità"""
    try:
        from datetime import timedelta
        
        start_time32 = validity['start']
        duration_choice_name, duration_value = validity['duration']
        
        # Converti Time32 in datetime
        start_dt = time32_decode(start_time32)
        
        # Calcola end date in base al tipo di durata
        if duration_choice_name == 'hours':
            hours = duration_value
            end_dt = start_dt + timedelta(hours=hours)
            duration_str = f"{hours} hours ({hours/24:.1f} days, {hours/(24*365):.2f} years)"
        elif duration_choice_name == 'microseconds':
            microseconds = duration_value
            end_dt = start_dt + timedelta(microseconds=microseconds)
            duration_str = f"{microseconds} microseconds"
        elif duration_choice_name == 'milliseconds':
            milliseconds = duration_value
            end_dt = start_dt + timedelta(milliseconds=milliseconds)
            duration_str = f"{milliseconds} milliseconds"
        elif duration_choice_name == 'seconds':
            seconds = duration_value
            end_dt = start_dt + timedelta(seconds=seconds)
            duration_str = f"{seconds} seconds"
        elif duration_choice_name == 'minutes':
            minutes = duration_value
            end_dt = start_dt + timedelta(minutes=minutes)
            duration_str = f"{minutes} minutes"
        else:
            duration_str = f"{duration_choice_name}: {duration_value}"
            end_dt = None
        
        return {
            'start': start_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'start_time32': start_time32,
            'duration': duration_str,
            'end': end_dt.strftime('%Y-%m-%d %H:%M:%S UTC') if end_dt else 'N/A',
            'is_valid': datetime.now(timezone.utc) < end_dt if end_dt else False
        }
    except Exception as e:
        return {'error': str(e)}


def decode_app_permissions(app_perms):
    """Decodifica le app permissions"""
    if not app_perms:
        return None
    
    result = []
    for perm in app_perms:
        try:
            psid = perm.get('psid')
            ssp_choice = perm.get('ssp')
            
            perm_info = {
                'psid': psid if isinstance(psid, int) else format_bytes(psid, 8) if isinstance(psid, bytes) else str(psid)
            }
            
            if ssp_choice:
                choice_name, choice_value = ssp_choice
                perm_info['ssp'] = {
                    'type': choice_name,
                    'value': format_bytes(choice_value) if isinstance(choice_value, bytes) else str(choice_value)
                }
            
            result.append(perm_info)
        except Exception as e:
            result.append({'error': str(e)})
    
    return result


def decode_cert_issue_permissions(cert_issue_perms):
    """Decodifica le cert issue permissions"""
    if not cert_issue_perms:
        return None
    
    result = []
    for perm in cert_issue_perms:
        try:
            perm_info = {
                'minChainLength': perm.get('minChainLength'),
                'chainLengthRange': perm.get('chainLengthRange'),
            }
            
            # Subject permissions
            subj_perms_choice = perm.get('subjectPermissions')
            if subj_perms_choice:
                choice_name, choice_value = subj_perms_choice
                perm_info['subjectPermissions'] = {
                    'type': choice_name,
                    'value': choice_value
                }
            
            # EE Type (BIT STRING)
            ee_type = perm.get('eeType')
            if ee_type:
                ee_bytes, num_bits = ee_type
                perm_info['eeType'] = {
                    'bits': format_bytes(ee_bytes, 2),
                    'num_bits': num_bits,
                    'app': bool(ee_bytes[0] & 0x80) if len(ee_bytes) > 0 else False,
                    'enrol': bool(ee_bytes[0] & 0x40) if len(ee_bytes) > 0 else False
                }
            
            result.append(perm_info)
        except Exception as e:
            result.append({'error': str(e)})
    
    return result


def inspect_certificate(cert_path: Path, cert_name: str):
    """Ispeziona un certificato OER"""
    print(f"\n{'='*80}")
    print(f"  {cert_name}")
    print(f"{'='*80}")
    
    if not cert_path.exists():
        print(f"❌ Certificato non trovato: {cert_path}")
        return
    
    try:
        # Leggi il file binario OER
        with open(cert_path, 'rb') as f:
            cert_oer = f.read()
        
        print(f"\n📄 File: {cert_path}")
        print(f"📊 Dimensione: {len(cert_oer)} bytes")
        print(f"🔢 Hex (primi 64 bytes): {cert_oer[:64].hex()}")
        
        # Calcola HashedId8
        hashed_id8 = compute_hashed_id8(cert_oer)
        print(f"🔑 HashedId8: {hashed_id8.hex()}")
        
        # Decodifica con ASN.1 compiler
        print(f"\n🔍 Decodifica ASN.1 (ETSI TS 103097)...")
        cert_decoded = asn1_compiler.decode('Certificate', cert_oer)
        
        # Version
        version = cert_decoded.get('version')
        print(f"\n📌 Version: {version}")
        
        # Type
        cert_type = cert_decoded.get('type')
        print(f"📌 Type: {cert_type}")
        
        # Issuer
        issuer = cert_decoded.get('issuer')
        issuer_info = decode_issuer_identifier(issuer)
        print(f"\n👤 Issuer:")
        for key, value in issuer_info.items():
            print(f"   - {key}: {value}")
        
        # ToBeSigned
        tbs = cert_decoded.get('toBeSigned')
        if tbs:
            print(f"\n📝 To Be Signed:")
            
            # Certificate ID
            cert_id = tbs.get('id')
            id_info = decode_certificate_id(cert_id)
            print(f"   🆔 ID:")
            for key, value in id_info.items():
                print(f"      - {key}: {value}")
            
            # CRL Series
            crl_series = tbs.get('crlSeries')
            print(f"   📋 CRL Series: {crl_series}")
            
            # CRACA ID
            craca_id = tbs.get('cracaId')
            print(f"   🔐 CRACA ID: {format_bytes(craca_id, 3)}")
            
            # Validity Period
            validity = tbs.get('validityPeriod')
            if validity:
                validity_info = decode_validity_period(validity)
                print(f"   ⏰ Validity Period:")
                for key, value in validity_info.items():
                    print(f"      - {key}: {value}")
            
            # Verification Key
            verify_key = tbs.get('verifyKeyIndicator')
            if verify_key:
                key_info = decode_public_key(verify_key)
                print(f"   🔑 Public Key:")
                for key, value in key_info.items():
                    print(f"      - {key}: {value}")
            
            # App Permissions
            app_perms = tbs.get('appPermissions')
            if app_perms:
                app_perms_info = decode_app_permissions(app_perms)
                print(f"   📱 App Permissions:")
                for i, perm in enumerate(app_perms_info, 1):
                    print(f"      Permission {i}:")
                    for key, value in perm.items():
                        print(f"         - {key}: {value}")
            
            # Cert Issue Permissions
            cert_issue_perms = tbs.get('certIssuePermissions')
            if cert_issue_perms:
                cert_issue_info = decode_cert_issue_permissions(cert_issue_perms)
                print(f"   🎫 Certificate Issue Permissions:")
                for i, perm in enumerate(cert_issue_info, 1):
                    print(f"      Permission {i}:")
                    for key, value in perm.items():
                        if isinstance(value, dict):
                            print(f"         - {key}:")
                            for k2, v2 in value.items():
                                print(f"            * {k2}: {v2}")
                        else:
                            print(f"         - {key}: {value}")
        
        # Signature
        signature = cert_decoded.get('signature')
        if signature:
            sig_choice_name, sig_choice_value = signature
            print(f"\n✍️  Signature:")
            print(f"   - Type: {sig_choice_name}")
            if sig_choice_name == 'ecdsaNistP256Signature':
                r_choice = sig_choice_value.get('rSig')
                s_value = sig_choice_value.get('sSig')
                print(f"   - R: {format_bytes(r_choice[1] if isinstance(r_choice, tuple) else r_choice, 16)}")
                print(f"   - S: {format_bytes(s_value, 16)}")
        
        print(f"\n✅ Certificato decodificato con successo!")
        
    except Exception as e:
        print(f"❌ Errore durante l'ispezione: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main function"""
    print("\n" + "="*80)
    print("  🔍 ISPETTORE CERTIFICATI PKI - ETSI TS 103097")
    print("="*80)
    
    pki_data_dir = Path("pki_data")
    
    # Root CA Certificate
    root_ca_cert = pki_data_dir / "root_ca" / "certificates" / "root_ca_certificate.oer"
    inspect_certificate(root_ca_cert, "ROOT CA CERTIFICATE")
    
    # EA Certificate
    ea_cert = pki_data_dir / "ea" / "EA_001" / "certificates" / "ea_certificate.oer"
    inspect_certificate(ea_cert, "ENROLLMENT AUTHORITY (EA_001) CERTIFICATE")
    
    # AA Certificate
    aa_cert = pki_data_dir / "aa" / "AA_001" / "certificates" / "aa_certificate.oer"
    inspect_certificate(aa_cert, "AUTHORIZATION AUTHORITY (AA_001) CERTIFICATE")
    
    print(f"\n{'='*80}")
    print("  ✅ Ispezione completata!")
    print("="*80 + "\n")


if __name__ == "__main__":
    main()
