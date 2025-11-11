#!/usr/bin/env python3
"""
Generate and sign certificates for server and client
Certificates are signed by the Root CA created by gen_ca.py
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import sys
import os

def load_ca():
    """Load CA certificate and private key"""
    print("[+] Loading CA certificate and private key...")
    
    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open("certs/ca_key.pem", "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    return ca_cert, ca_key

def generate_cert(entity_name, common_name, ca_cert, ca_key):
    """Generate a certificate signed by the CA"""
    
    print(f"[+] Generating private key for {entity_name}...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    print(f"[+] Creating certificate for {entity_name}...")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)  # 1 year
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_file = f"certs/{entity_name}_key.pem"
    print(f"[+] Writing private key to {key_file}...")
    with open(key_file, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_file = f"certs/{entity_name}_cert.pem"
    print(f"[+] Writing certificate to {cert_file}...")
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"[✓] Certificate for {entity_name} generated successfully!")
    return cert_file, key_file

if __name__ == "__main__":
    import ipaddress
    
    if not os.path.exists("certs/ca_cert.pem") or not os.path.exists("certs/ca_key.pem"):
        print("[!] Error: CA certificate or key not found.")
        print("    Please run gen_ca.py first!")
        sys.exit(1)
    
    ca_cert, ca_key = load_ca()
    
    # Generate server certificate
    print("\n=== Generating Server Certificate ===")
    generate_cert("server", "securechat.server", ca_cert, ca_key)
    
    # Generate client certificate
    print("\n=== Generating Client Certificate ===")
    generate_cert("client", "securechat.client", ca_cert, ca_key)
    
    print("\n[✓] All certificates generated successfully!")
    print("\n[!] Remember: NEVER commit private keys to Git!")
