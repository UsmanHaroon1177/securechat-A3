#!/usr/bin/env python3
"""
Verify transcript and session receipt for non-repudiation
Offline verification tool
"""

import sys
import json
import base64
from crypto_utils import crypto
import os


def verify_transcript_entry(line, cert):
    """
    Verify a single transcript entry
    Format: seqno|timestamp|ct|sig|peer-cert-fingerprint
    """
    parts = line.strip().split('|')

    if len(parts) != 5:
        return False, "Invalid transcript format"

    seqno, timestamp, ct_b64, sig_b64, fingerprint = parts

    try:
        # Decode
        ct_with_iv = base64.b64decode(ct_b64)
        signature = base64.b64decode(sig_b64)

        # Recompute digest
        digest_data = f"{seqno}{timestamp}".encode('utf-8') + ct_with_iv
        digest = crypto.sha256_hash(digest_data)

        # Verify signature
        is_valid = crypto.rsa_verify(digest, signature, cert)

        if is_valid:
            return True, f"Seqno {seqno}: Signature valid"
        else:
            return False, f"Seqno {seqno}: Signature INVALID"

    except Exception as e:
        return False, f"Verification error: {e}"


def verify_transcript_file(transcript_file, cert_file):
    """Verify all entries in a transcript file"""
    print(f"\n=== Verifying Transcript: {transcript_file} ===")

    # Load certificate
    cert = crypto.load_certificate(cert_file)
    print(f"[+] Loaded certificate: {cert_file}")

    # Read transcript
    try:
        with open(transcript_file, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[!] Transcript file not found: {transcript_file}")
        return False

    print(f"[+] Transcript contains {len(lines)} entries")

    # Verify each entry
    all_valid = True
    for i, line in enumerate(lines, 1):
        valid, msg = verify_transcript_entry(line, cert)
        if valid:
            print(f"  Entry {i}: ✓ {msg}")
        else:
            print(f"  Entry {i}: ✗ {msg}")
            all_valid = False

    return all_valid


def verify_receipt(receipt_file, cert_file, transcript_file):
    """Verify session receipt"""
    print(f"\n=== Verifying Session Receipt: {receipt_file} ===")

    # Load certificate
    cert = crypto.load_certificate(cert_file)
    print(f"[+] Loaded certificate: {cert_file}")

    # Load receipt
    try:
        with open(receipt_file, 'r') as f:
            receipt = json.load(f)
    except FileNotFoundError:
        print(f"[!] Receipt file not found: {receipt_file}")
        return False

    print(f"[+] Receipt loaded")
    print(f"    Peer: {receipt['peer']}")
    print(f"    First seq: {receipt['first_seq']}, Last seq: {receipt['last_seq']}")
    print(f"    Transcript hash: {receipt['transcript_sha256']}")

    # Recompute transcript hash
    print(f"\n[+] Recomputing transcript hash...")
    try:
        with open(transcript_file, 'r') as f:
            transcript_data = f.read()
    except FileNotFoundError:
        print(f"[!] Transcript file not found: {transcript_file}")
        return False

    computed_hash = crypto.sha256_hash_hex(transcript_data.strip())
    print(f"    Computed hash:  {computed_hash}")
    print(f"    Receipt hash:   {receipt['transcript_sha256']}")

    if computed_hash != receipt['transcript_sha256']:
        print("✗ HASH MISMATCH - Transcript has been modified!")
        return False

    print("✓ Transcript hash matches")

    # Verify signature
    print(f"\n[+] Verifying receipt signature...")
    signature = base64.b64decode(receipt['signature'])
    is_valid = crypto.rsa_verify(receipt['transcript_sha256'], signature, cert)

    if is_valid:
        print("✓ Receipt signature is VALID")
        return True
    else:
        print("✗ Receipt signature is INVALID")
        return False


def test_tampered_transcript(transcript_file, cert_file, receipt_file):
    """Test that tampering is detected"""
    print(f"\n\n=== Test: Tampered Transcript Detection ===")

    # Read original transcript
    with open(transcript_file, 'r') as f:
        original_lines = f.readlines()

    # Create tampered version
    tampered_file = transcript_file.replace('.txt', '_TAMPERED.txt')
    with open(tampered_file, 'w') as f:
        for i, line in enumerate(original_lines):
            if i == 0:  # Tamper with first line
                parts = line.strip().split('|')
                parts[0] = str(int(parts[0]) + 100)  # Change seqno
                f.write('|'.join(parts) + '\n')
            else:
                f.write(line)

    print(f"[+] Created tampered transcript: {tampered_file}")
    print(f"    Modified: First line seqno changed")

    # Try to verify with receipt
    print(f"\n[+] Attempting to verify tampered transcript...")
    valid = verify_receipt(receipt_file, cert_file, tampered_file)

    if not valid:
        print("\n✓ Test PASSED - Tampering detected!")
        print("  The hash mismatch proves the transcript was modified")
    else:
        print("\n✗ Test FAILED - Tampering should be detected")

    # Clean up
    os.remove(tampered_file)


def main():
    """Main verification entry point"""
    print("=" * 60)
    print("     Transcript & Receipt Verification Tool")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  Verify transcript:")
        print("    python3 verify_transcript.py <transcript_file> <cert_file>")
        print("\n  Verify receipt:")
        print("    python3 verify_transcript.py <receipt_file> <cert_file> <transcript_file>")
        return

    # Check if it's a receipt or transcript
    if sys.argv[1].endswith('_receipt.json'):
        # Verify receipt
        if len(sys.argv) < 4:
            print("[!] Error: Receipt verification requires 3 arguments")
            print("    Usage: python3 verify_transcript.py <receipt_file> <cert_file> <transcript_file>")
            return

        receipt_file = sys.argv[1]
        cert_file = sys.argv[2]
        transcript_file = sys.argv[3]

        # Verify receipt
        receipt_valid = verify_receipt(receipt_file, cert_file, transcript_file)

        # Also verify individual transcript entries
        transcript_valid = verify_transcript_file(transcript_file, cert_file)

        # Test tampering detection
        if receipt_valid and transcript_valid:
            test_tampered_transcript(transcript_file, cert_file, receipt_file)

        # Summary
        print("\n" + "=" * 60)
        print("Verification Summary")
        print("=" * 60)
        if receipt_valid and transcript_valid:
            print("✓ All verifications PASSED")
            print("  - All transcript entries have valid signatures")
            print("  - Receipt signature is valid")
            print("  - Transcript hash matches receipt")
            print("  - Tampering detection works correctly")
        else:
            print("✗ Verification FAILED")
            if not transcript_valid:
                print("  - Some transcript entries have invalid signatures")
            if not receipt_valid:
                print("  - Receipt verification failed")
    else:
        # Verify transcript only
        if len(sys.argv) < 3:
            print("[!] Error: Transcript verification requires 2 arguments")
            print("    Usage: python3 verify_transcript.py <transcript_file> <cert_file>")
            return

        transcript_file = sys.argv[1]
        cert_file = sys.argv[2]

        transcript_valid = verify_transcript_file(transcript_file, cert_file)

        print("\n" + "=" * 60)
        if transcript_valid:
            print("✓ All transcript entries verified successfully")
        else:
            print("✗ Some transcript entries failed verification")
        print("=" * 60)


if __name__ == "__main__":
    main()
