#!/usr/bin/env python3
"""
Test message integrity protection
Tests tampering detection via signature verification
"""

import base64
from crypto_utils import crypto
from protocol import Protocol

def test_message_tampering():
    """Test that tampered messages are detected"""
    print("=" * 60)
    print("     Message Tampering Test")
    print("=" * 60)
    
    # Load certificates and keys
    client_cert = crypto.load_certificate("certs/client_cert.pem")
    client_key = crypto.load_private_key("certs/client_key.pem")
    server_cert = crypto.load_certificate("certs/server_cert.pem")
    
    # Simulate session key (for testing)
    session_key = crypto.generate_nonce(16)
    
    # Original message
    plaintext = "This is a secret message"
    seqno = 1
    timestamp = Protocol.get_current_timestamp()
    
    print(f"\n[+] Original message: {plaintext}")
    print(f"    Seqno: {seqno}, Timestamp: {timestamp}")
    
    # Encrypt message
    iv, ciphertext = crypto.aes_encrypt(plaintext, session_key)
    ct_with_iv = iv + ciphertext
    
    # Compute digest and sign
    digest_data = f"{seqno}{timestamp}".encode('utf-8') + ct_with_iv
    digest = crypto.sha256_hash(digest_data)
    signature = crypto.rsa_sign(digest, client_key)
    
    print(f"[+] Message encrypted and signed")
    
    # Test 1: Verify original message
    print("\n=== Test 1: Original Message Verification ===")
    is_valid = crypto.rsa_verify(digest, signature, client_cert)
    print(f"Signature valid: {is_valid}")
    
    if is_valid:
        print("✓ Test PASSED - Original message signature valid")
    else:
        print("✗ Test FAILED - Original signature should be valid")
    
    # Test 2: Tamper with ciphertext (flip one bit)
    print("\n=== Test 2: Tampered Ciphertext ===")
    tampered_ct = bytearray(ct_with_iv)
    tampered_ct[20] ^= 0x01  # Flip one bit
    tampered_ct = bytes(tampered_ct)
    
    # Recompute digest with tampered ciphertext
    tampered_digest_data = f"{seqno}{timestamp}".encode('utf-8') + tampered_ct
    tampered_digest = crypto.sha256_hash(tampered_digest_data)
    
    # Try to verify with original signature
    is_valid_tampered = crypto.rsa_verify(tampered_digest, signature, client_cert)
    print(f"Tampered message signature valid: {is_valid_tampered}")
    
    if not is_valid_tampered:
        print("✓ Test PASSED - Tampered message detected (SIG_FAIL)")
    else:
        print("✗ Test FAILED - Tampering should be detected")
    
    # Test 3: Tamper with sequence number
    print("\n=== Test 3: Tampered Sequence Number ===")
    tampered_seqno = seqno + 1
    tampered_seqno_digest_data = f"{tampered_seqno}{timestamp}".encode('utf-8') + ct_with_iv
    tampered_seqno_digest = crypto.sha256_hash(tampered_seqno_digest_data)
    
    is_valid_seqno = crypto.rsa_verify(tampered_seqno_digest, signature, client_cert)
    print(f"Tampered seqno signature valid: {is_valid_seqno}")
    
    if not is_valid_seqno:
        print("✓ Test PASSED - Seqno tampering detected (SIG_FAIL)")
    else:
        print("✗ Test FAILED - Seqno tampering should be detected")
    
    # Test 4: Tamper with timestamp
    print("\n=== Test 4: Tampered Timestamp ===")
    tampered_timestamp = timestamp + 1000
    tampered_ts_digest_data = f"{seqno}{tampered_timestamp}".encode('utf-8') + ct_with_iv
    tampered_ts_digest = crypto.sha256_hash(tampered_ts_digest_data)
    
    is_valid_ts = crypto.rsa_verify(tampered_ts_digest, signature, client_cert)
    print(f"Tampered timestamp signature valid: {is_valid_ts}")
    
    if not is_valid_ts:
        print("✓ Test PASSED - Timestamp tampering detected (SIG_FAIL)")
    else:
        print("✗ Test FAILED - Timestamp tampering should be detected")
    
    # Test 5: Decrypt tampered ciphertext (should produce garbage)
    print("\n=== Test 5: Decrypt Tampered Ciphertext ===")
    try:
        tampered_iv = tampered_ct[:16]
        tampered_ciphertext = tampered_ct[16:]
        decrypted_garbage = crypto.aes_decrypt(tampered_iv, tampered_ciphertext, session_key)
        print(f"Decrypted tampered message: {repr(decrypted_garbage)}")
        
        if decrypted_garbage != plaintext:
            print("✓ Test PASSED - Tampered ciphertext produces different plaintext")
        else:
            print("✗ Test FAILED - Tampered ciphertext should not decrypt to original")
    except Exception as e:
        print(f"Decryption failed with error: {e}")
        print("✓ Test PASSED - Tampered ciphertext cannot be decrypted properly")
    
    print("\n" + "=" * 60)
    print("All tampering tests completed")
    print("=" * 60)

if __name__ == "__main__":
    test_message_tampering()
