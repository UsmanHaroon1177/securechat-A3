#!/usr/bin/env python3
"""
Test cryptographic utilities
"""

from crypto_utils import crypto
import json

def test_crypto():
    print("=== Testing Cryptographic Utilities ===\n")
    
    # Test 1: Diffie-Hellman Key Exchange
    print("Test 1: Diffie-Hellman Key Exchange")
    print("-" * 50)
    p, g = crypto.generate_dh_parameters()
    print(f"DH Parameters generated: p (length: {p.bit_length()} bits), g = {g}")
    
    # Alice's side
    alice_private = crypto.generate_dh_private_key(p)
    alice_public = crypto.compute_dh_public_key(g, alice_private, p)
    print(f"Alice: private key generated, public key computed")
    
    # Bob's side
    bob_private = crypto.generate_dh_private_key(p)
    bob_public = crypto.compute_dh_public_key(g, bob_private, p)
    print(f"Bob: private key generated, public key computed")
    
    # Compute shared secrets
    alice_shared = crypto.compute_dh_shared_secret(bob_public, alice_private, p)
    bob_shared = crypto.compute_dh_shared_secret(alice_public, bob_private, p)
    print(f"Shared secret match: {alice_shared == bob_shared}")
    
    # Derive AES keys
    alice_key = crypto.derive_aes_key_from_dh(alice_shared)
    bob_key = crypto.derive_aes_key_from_dh(bob_shared)
    print(f"AES keys match: {alice_key == bob_key}")
    print(f"AES Key (hex): {alice_key.hex()}\n")
    
    # Test 2: AES Encryption/Decryption
    print("Test 2: AES-128 Encryption/Decryption")
    print("-" * 50)
    plaintext = "Hello, this is a secret message!"
    print(f"Original plaintext: {plaintext}")
    
    iv, ciphertext = crypto.aes_encrypt(plaintext, alice_key)
    print(f"Encrypted (base64): {crypto.base64_encode(ciphertext)}")
    
    decrypted = crypto.aes_decrypt(iv, ciphertext, bob_key)
    print(f"Decrypted plaintext: {decrypted}")
    print(f"Decryption successful: {plaintext == decrypted}\n")
    
    # Test 3: RSA Signing/Verification
    print("Test 3: RSA Signing/Verification")
    print("-" * 50)
    
    # Load keys and certificates
    try:
        private_key = crypto.load_private_key("certs/client_key.pem")
        certificate = crypto.load_certificate("certs/client_cert.pem")
        print("Loaded client private key and certificate")
        
        # Sign a message
        message = "This is a test message for signing"
        signature = crypto.rsa_sign(message, private_key)
        print(f"Message signed, signature length: {len(signature)} bytes")
        
        # Verify signature
        is_valid = crypto.rsa_verify(message, signature, certificate)
        print(f"Signature valid: {is_valid}")
        
        # Test with tampered message
        tampered_message = "This is a TAMPERED message"
        is_valid_tampered = crypto.rsa_verify(tampered_message, signature, certificate)
        print(f"Tampered message signature valid: {is_valid_tampered}\n")
        
    except FileNotFoundError:
        print("Certificates not found. Please run gen_ca.py and gen_cert.py first.\n")
    
    # Test 4: Certificate Validation
    print("Test 4: Certificate Validation")
    print("-" * 50)
    try:
        ca_cert = crypto.load_certificate("certs/ca_cert.pem")
        client_cert = crypto.load_certificate("certs/client_cert.pem")
        
        valid, error = crypto.validate_certificate(client_cert, ca_cert)
        print(f"Certificate valid: {valid}")
        if error:
            print(f"Error: {error}")
        
        # Get fingerprint
        fingerprint = crypto.get_certificate_fingerprint(client_cert)
        print(f"Certificate fingerprint: {fingerprint}\n")
        
    except FileNotFoundError:
        print("Certificates not found. Please run gen_ca.py and gen_cert.py first.\n")
    
    # Test 5: SHA-256 Hashing
    print("Test 5: SHA-256 Hashing")
    print("-" * 50)
    data = "Test data for hashing"
    hash_hex = crypto.sha256_hash_hex(data)
    print(f"Data: {data}")
    print(f"SHA-256 hash: {hash_hex}\n")

if __name__ == "__main__":
    test_crypto()
