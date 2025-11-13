#!/usr/bin/env python3
"""
Cryptographic utilities for SecureChat
Implements: DH key exchange, AES-128 encryption, RSA signing/verification, SHA-256 hashing
"""

import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.primitives import padding as sym_padding

class CryptoUtils:
    """Cryptographic operations utility class"""
    
    def __init__(self):
        self.backend = default_backend()
    
    # ========== Diffie-Hellman Key Exchange ==========
    
    def generate_dh_parameters(self):
        """
        Generate DH parameters (p, g)
        Using a safe prime for p
        """
        # Using a 2048-bit safe prime (Sophie Germain prime)
        # This is a well-known safe prime for DH
        p = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
        )
        g = 2
        
        return p, g
    
    def generate_dh_private_key(self, p):
        """Generate a random private key for DH (between 2 and p-2)"""
        return int.from_bytes(os.urandom(256), byteorder='big') % (p - 2) + 2
    
    def compute_dh_public_key(self, g, private_key, p):
        """Compute public key: g^private_key mod p"""
        return pow(g, private_key, p)
    
    def compute_dh_shared_secret(self, peer_public_key, private_key, p):
        """Compute shared secret: peer_public^private_key mod p"""
        return pow(peer_public_key, private_key, p)
    
    def derive_aes_key_from_dh(self, shared_secret):
        """
        Derive AES-128 key from DH shared secret
        K = Trunc_16(SHA256(big-endian(Ks)))
        """
        # Convert shared secret to bytes (big-endian)
        shared_bytes = shared_secret.to_bytes(
            (shared_secret.bit_length() + 7) // 8, 
            byteorder='big'
        )
        
        # Compute SHA-256 hash
        hash_digest = hashlib.sha256(shared_bytes).digest()
        
        # Truncate to 16 bytes for AES-128
        aes_key = hash_digest[:16]
        
        return aes_key
    
    # ========== AES-128 Encryption/Decryption ==========
    
    def aes_encrypt(self, plaintext, key):
        """
        Encrypt plaintext using AES-128 in CBC mode with PKCS#7 padding
        Returns: (iv, ciphertext) both as bytes
        """
        # Generate random IV (16 bytes for AES)
        iv = os.urandom(16)
        
        # Apply PKCS#7 padding
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode('utf-8') if isinstance(plaintext, str) else plaintext)
        padded_data += padder.finalize()
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, ciphertext
    
    def aes_decrypt(self, iv, ciphertext, key):
        """
        Decrypt ciphertext using AES-128 in CBC mode
        Returns: plaintext as string
        """
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS#7 padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode('utf-8')
    
    # ========== RSA Signing/Verification ==========
    
    def load_private_key(self, key_path):
        """Load RSA private key from PEM file"""
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=self.backend
            )
        return private_key
    
    def load_certificate(self, cert_path):
        """Load X.509 certificate from PEM file"""
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), self.backend)
        return cert
    
    def rsa_sign(self, data, private_key):
        """
        Sign data using RSA private key
        Returns: signature as bytes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature
    
    def rsa_verify(self, data, signature, certificate):
        """
        Verify RSA signature using public key from certificate
        Returns: True if valid, False otherwise
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        try:
            public_key = certificate.public_key()
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"[!] Signature verification failed: {e}")
            return False
    
    # ========== Certificate Validation ==========
    
    def validate_certificate(self, cert, ca_cert, expected_cn=None):
        """
        Validate a certificate against CA certificate
        Checks:
        1. Signature verification
        2. Validity period (not expired, not yet valid)
        3. Common Name (if provided)
        
        Returns: (valid: bool, error_message: str or None)
        """
        import datetime
        
        try:
            # Check 1: Verify signature chain
            ca_public_key = ca_cert.public_key()
            try:
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
            except Exception as e:
                return False, f"BAD_CERT: Invalid signature - {e}"
            
            # Check 2: Verify validity period
            now = datetime.datetime.utcnow()
            if now < cert.not_valid_before:
                return False, f"BAD_CERT: Certificate not yet valid (valid from {cert.not_valid_before})"
            if now > cert.not_valid_after:
                return False, f"BAD_CERT: Certificate expired (expired on {cert.not_valid_after})"
            
            # Check 3: Verify Common Name (if expected)
            if expected_cn:
                cert_cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                if cert_cn != expected_cn:
                    return False, f"BAD_CERT: Common Name mismatch (expected {expected_cn}, got {cert_cn})"
            
            return True, None
            
        except Exception as e:
            return False, f"BAD_CERT: Validation error - {e}"
    
    def get_certificate_fingerprint(self, cert):
        """Get SHA-256 fingerprint of certificate"""
        fingerprint = cert.fingerprint(hashes.SHA256())
        return fingerprint.hex()
    
    # ========== SHA-256 Hashing ==========
    
    def sha256_hash(self, data):
        """
        Compute SHA-256 hash of data
        Returns: hash as bytes
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).digest()
    
    def sha256_hash_hex(self, data):
        """
        Compute SHA-256 hash of data
        Returns: hash as hex string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    # ========== Utility Functions ==========
    
    def generate_nonce(self, length=16):
        """Generate a random nonce"""
        return os.urandom(length)
    
    def base64_encode(self, data):
        """Base64 encode bytes"""
        return base64.b64encode(data).decode('utf-8')
    
    def base64_decode(self, data):
        """Base64 decode string to bytes"""
        return base64.b64decode(data)

# Create singleton instance
crypto = CryptoUtils()
