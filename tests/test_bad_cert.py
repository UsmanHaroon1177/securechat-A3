#!/usr/bin/env python3
"""
Test certificate validation with invalid certificates
Tests: self-signed, expired, and forged certificates
"""

import os
import sys
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from crypto_utils import crypto

def create_self_signed_cert():
    """Create a self-signed certificate (should be rejected)"""
    print("\n=== Test 1: Self-Signed Certificate ===")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Malicious Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "securechat.client"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(private_key, hashes.SHA256(), default_backend())
    
    # Save certificate
    os.makedirs("test_certs", exist_ok=True)
    with open("test_certs/self_signed.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Try to validate
    ca_cert = crypto.load_certificate("certs/ca_cert.pem")
    valid, error = crypto.validate_certificate(cert, ca_cert)
    
    print(f"Certificate: Self-Signed")
    print(f"Valid: {valid}")
    print(f"Error: {error}")
    
    if not valid and "BAD_CERT" in error:
        print("✓ Test PASSED - Self-signed certificate rejected")
        return True
    else:
        print("✗ Test FAILED - Self-signed certificate should be rejected")
        return False

def create_expired_cert():
    """Create an expired certificate (should be rejected)"""
    print("\n=== Test 2: Expired Certificate ===")
    
    # Load CA
    ca_cert = crypto.load_certificate("certs/ca_cert.pem")
    ca_key = crypto.load_private_key("certs/ca_key.pem")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create expired certificate (valid period in the past)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, "securechat.client"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=400)  # Started 400 days ago
    ).not_valid_after(
        datetime.utcnow() - timedelta(days=35)   # Expired 35 days ago
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save certificate
    with open("test_certs/expired.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Try to validate
    valid, error = crypto.validate_certificate(cert, ca_cert)
    
    print(f"Certificate: Expired")
    print(f"Valid: {valid}")
    print(f"Error: {error}")
    
    if not valid and "expired" in error.lower():
        print("✓ Test PASSED - Expired certificate rejected")
        return True
    else:
        print("✗ Test FAILED - Expired certificate should be rejected")
        return False

def create_wrong_cn_cert():
    """Create a certificate with wrong Common Name (should be rejected)"""
    print("\n=== Test 3: Wrong Common Name Certificate ===")
    
    # Load CA
    ca_cert = crypto.load_certificate("certs/ca_cert.pem")
    ca_key = crypto.load_private_key("certs/ca_key.pem")
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate with wrong CN
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, "wrong.hostname.com"),  # Wrong CN
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save certificate
    with open("test_certs/wrong_cn.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Try to validate with expected CN
    valid, error = crypto.validate_certificate(cert, ca_cert, expected_cn="securechat.client")
    
    print(f"Certificate: Wrong Common Name")
    print(f"Valid: {valid}")
    print(f"Error: {error}")
    
    if not valid and "Common Name mismatch" in error:
        print("✓ Test PASSED - Wrong CN certificate rejected")
        return True
    else:
        print("✗ Test FAILED - Wrong CN certificate should be rejected")
        return False

def test_valid_cert():
    """Test that valid certificates are accepted"""
    print("\n=== Test 4: Valid Certificate (Control) ===")
    
    # Load valid certificate
    ca_cert = crypto.load_certificate("certs/ca_cert.pem")
    client_cert = crypto.load_certificate("certs/client_cert.pem")
    
    # Validate
    valid, error = crypto.validate_certificate(
        client_cert, 
        ca_cert,
        expected_cn="securechat.client"
    )
    
    print(f"Certificate: Valid Client Certificate")
    print(f"Valid: {valid}")
    print(f"Error: {error}")
    
    if valid:
        print("✓ Test PASSED - Valid certificate accepted")
        return True
    else:
        print("✗ Test FAILED - Valid certificate should be accepted")
        return False

def main():
    """Run all certificate validation tests"""
    print("=" * 60)
    print("     Certificate Validation Tests")
    print("=" * 60)
    
    results = []
    
    # Test 1: Self-signed certificate
    results.append(create_self_signed_cert())
    
    # Test 2: Expired certificate
    results.append(create_expired_cert())
    
    # Test 3: Wrong Common Name
    results.append(create_wrong_cn_cert())
    
    # Test 4: Valid certificate (control)
    results.append(test_valid_cert())
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✓ All tests PASSED")
    else:
        print(f"✗ {total - passed} test(s) FAILED")
    
    print("\nTest certificates saved in: test_certs/")

if __name__ == "__main__":
    main()
