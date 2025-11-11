#!/usr/bin/env python3
"""
Generate Root Certificate Authority (CA)
This script creates a self-signed CA certificate and private key.
"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import os

def generate_ca():
    """Generate a self-signed root CA certificate"""
    
    # Generate private key for CA
    print("[+] Generating CA private key (2048-bit RSA)...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])
    
    # Build the CA certificate
    print("[+] Creating self-signed CA certificate...")
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Ensure certs directory exists
    os.makedirs("certs", exist_ok=True)
    
    # Write CA private key to file
    print("[+] Writing CA private key to certs/ca_key.pem...")
    with open("certs/ca_key.pem", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write CA certificate to file
    print("[+] Writing CA certificate to certs/ca_cert.pem...")
    with open("certs/ca_cert.pem", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    print("[✓] Root CA generated successfully!")
    print("    CA Private Key: certs/ca_key.pem")
    print("    CA Certificate: certs/ca_cert.pem")
    print("\n[!] Keep ca_key.pem secure and NEVER commit it to Git!")

if __name__ == "__main__":
    generate_ca()
