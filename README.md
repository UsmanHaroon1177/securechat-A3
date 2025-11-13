# Secure Chat System - Information Security Assignment 2

A console-based secure chat system implementing end-to-end cryptographic protocols including PKI, AES-128 encryption, RSA signatures, Diffie-Hellman key exchange, and non-repudiation mechanisms.

## 👨‍🎓 Student Information
- **Name**: Usman Haroon
- **Roll Number**: 22i-1177
- **University**: FAST-NUCES
- **Course**: Information Security
- **Semester**: Fall 2025
- **Assignment**: #2

## 🔗 Repository
- **GitHub**: https://github.com/UsmanHaroon1177/securechat-A3
- **Branch**: main

#
## ✨ Features

### Cryptographic Implementations
- ✅ **PKI (Public Key Infrastructure)**: Self-built CA with X.509 certificates
- ✅ **Mutual Authentication**: Certificate-based client-server verification
- ✅ **AES-128 Encryption**: CBC mode with PKCS#7 padding
- ✅ **RSA Digital Signatures**: 2048-bit keys for message signing
- ✅ **Diffie-Hellman Key Exchange**: 2048-bit DH for session key agreement
- ✅ **SHA-256 Hashing**: For integrity verification and password storage
- ✅ **Replay Attack Protection**: Strict sequence number enforcement
- ✅ **Non-Repudiation**: Signed session transcripts with receipts

### CIANR Properties Achieved
- **C (Confidentiality)**: All messages encrypted with AES-128
- **I (Integrity)**: SHA-256 digests detect any tampering
- **A (Authenticity)**: RSA signatures verify sender identity
- **N (Non-Repudiation)**: Signed transcripts prove communication occurred
- **R (Replay Prevention)**: Sequence numbers prevent message replay

## 🖥️ System Requirements

### Operating System
- Kali Linux (tested)
- Ubuntu 20.04+ / Debian-based systems
- Any Linux distribution with Python 3.8+

### Software Dependencies
- Python 3.8 or higher
- MySQL Server 8.0+
- OpenSSL (usually pre-installed)
- Wireshark (for packet analysis)
- tcpdump (for packet capture)

### Python Libraries
```
cryptography==41.0.7
mysql-connector-python==8.2.0
python-dotenv==1.0.0
```

## 📦 Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/UsmanHaroon1177/securechat-assignment.git
cd securechat-assignment
```

### Step 2: Setup Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Setup MySQL Database
```bash
# Start MySQL service
sudo systemctl start mysql

# Login to MySQL
sudo mysql -u root -p
```

**Execute these SQL commands:**
```sql
CREATE DATABASE securechat;
CREATE USER 'chatuser'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON securechat.* TO 'chatuser'@'localhost';
FLUSH PRIVILEGES;

USE securechat;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    salt VARBINARY(16) NOT NULL,
    pwd_hash CHAR(64) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

EXIT;
```

### Step 4: Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit with your database credentials
nano .env
```

**Update these values in .env:**
```
DB_HOST=localhost
DB_USER=chatuser
DB_PASSWORD=SecurePass123!
DB_NAME=securechat
SERVER_HOST=127.0.0.1
SERVER_PORT=5555
```

### Step 5: Generate Certificates
```bash
# Generate Certificate Authority
python3 scripts/gen_ca.py

# Generate Server and Client Certificates
python3 scripts/gen_cert.py

# Verify certificates
openssl verify -CAfile certs/ca_cert.pem certs/server_cert.pem
openssl verify -CAfile certs/ca_cert.pem certs/client_cert.pem
```

**Expected output:**
```
certs/server_cert.pem: OK
certs/client_cert.pem: OK
```

## 🚀 Usage

### Starting the Server
**Terminal 1:**
```bash
cd ~/Desktop/A3/securechat-assignment
source venv/bin/activate
python3 server.py
```

**Expected output:**
```
============================================================
          Secure Chat Server
============================================================
[+] Server certificates loaded
[+] Server started on 127.0.0.1:5555
[+] Waiting for clients...
```

### Starting the Client
**Terminal 2:**
```bash
cd ~/Desktop/A3/securechat-assignment
source venv/bin/activate
python3 client.py
```

### User Registration (First Time)
```
[Phase 1] Certificate Exchange
[+] Server certificate validated successfully

[Phase 2] Authentication
1. Register new account
2. Login to existing account
Choose option (1/2): 1

=== Registration ===
Email: alice@example.com
Username: alice
Password: [hidden]
[+] Registration successful
```

### User Login (Returning Users)
```
Choose option (1/2): 2

=== Login ===
Email: alice@example.com
Password: [hidden]
[+] Login successful
[+] Welcome back, alice!
```

### Sending Messages
```
[Phase 4] Encrypted Chat
============================================================
Chat session started as alice
Type your messages and press Enter to send
Type 'quit' to exit
============================================================

Hello Server!
[You] Hello Server!
[Server] Hi Alice! How are you?
I'm doing great, thanks!
[You] I'm doing great, thanks!
quit

[+] Generating session receipt...
[+] Receipt sent to server
[+] Disconnected from server
```

## 🔄 Protocol Phases

### Phase 1: Certificate Exchange (Control Plane)
```
Client → Server: HELLO {client_cert, nonce}
Server → Client: SERVER_HELLO {server_cert, nonce}
Both Sides:     Validate certificates against CA
                Check expiry, CN, signature chain
```

**Purpose**: Establish trust and mutual authentication

### Phase 2: Authentication
```
Client ↔ Server: Temporary DH exchange
Client → Server: Encrypted REGISTER/LOGIN message
                 {email, username, pwd_hash, salt}
Server:          Verify credentials against MySQL
Server → Client: AUTH_SUCCESS/AUTH_FAIL
```

**Purpose**: Authenticate user without plaintext credentials

### Phase 3: Session Key Agreement
```
Client → Server: DH_CLIENT {g, p, A = g^a mod p}
Server → Client: DH_SERVER {B = g^b mod p}
Both Compute:    Shared Secret Ks = g^(ab) mod p
Both Derive:     Session Key K = Trunc₁₆(SHA256(Ks))
```

**Purpose**: Establish unique encryption key for session

### Phase 4: Encrypted Message Exchange (Data Plane)
```
Sender Side:
1. Encrypt:  CT = AES-128-CBC(plaintext, K, IV)
2. Digest:   h = SHA256(seqno || timestamp || CT)
3. Sign:     sig = RSA_Sign(h, private_key)
4. Send:     MSG {seqno, ts, CT, sig}

Receiver Side:
1. Verify:   seqno > last_seqno (replay check)
2. Verify:   RSA_Verify(sig, h, sender_cert)
3. Decrypt:  plaintext = AES-128-CBC-Decrypt(CT, K, IV)
4. Display:  Show plaintext to user
```

**Purpose**: Secure, authenticated, tamper-proof messaging

### Phase 5: Non-Repudiation (Session Closure)
```
Both Sides:
1. Maintain:  Append-only transcript file
              Format: seqno|ts|ct|sig|peer_fingerprint
2. Compute:   transcript_hash = SHA256(transcript)
3. Sign:      receipt_sig = RSA_Sign(transcript_hash)
4. Create:    SessionReceipt {peer, first_seq, last_seq, 
                              transcript_hash, receipt_sig}
5. Exchange:  Send receipts to each other
```

**Purpose**: Cryptographic proof of communication

## 🧪 Testing

### Test 1: Cryptographic Utilities
```bash
python3 test_crypto.py
```

**What it tests:**
- Diffie-Hellman key exchange correctness
- AES-128 encryption/decryption
- RSA signing and verification
- Certificate validation
- SHA-256 hashing

**Expected output:**
```
=== Testing Cryptographic Utilities ===
Test 1: Diffie-Hellman Key Exchange
✓ Shared secret match: True
✓ AES keys match: True

Test 2: AES-128 Encryption/Decryption
✓ Decryption successful: True

Test 3: RSA Signing/Verification
✓ Signature valid: True
✓ Tampered message signature valid: False
```

### Test 2: Certificate Validation
```bash
python3 test_bad_cert.py
```

**What it tests:**
- Self-signed certificate rejection (BAD_CERT)
- Expired certificate rejection (BAD_CERT)
- Wrong Common Name rejection (BAD_CERT)
- Valid certificate acceptance

**Expected output:**
```
=== Test 1: Self-Signed Certificate ===
✓ Test PASSED - Self-signed certificate rejected

=== Test 2: Expired Certificate ===
✓ Test PASSED - Expired certificate rejected

=== Test 3: Wrong Common Name Certificate ===
✓ Test PASSED - Wrong CN certificate rejected

=== Test 4: Valid Certificate (Control) ===
✓ Test PASSED - Valid certificate accepted
```

### Test 3: Message Tampering Detection
```bash
python3 test_tampering.py
```

**What it tests:**
- Tampered ciphertext detection (SIG_FAIL)
- Tampered sequence number detection
- Tampered timestamp detection
- Signature verification integrity

**Expected output:**
```
=== Test 1: Original Message Verification ===
✓ Test PASSED - Original message signature valid

=== Test 2: Tampered Ciphertext ===
✓ Test PASSED - Tampered message detected (SIG_FAIL)

=== Test 3: Tampered Sequence Number ===
✓ Test PASSED - Seqno tampering detected (SIG_FAIL)
```

### Test 4: Replay Attack Protection
```bash
python3 test_replay.py
```

**What it tests:**
- Old sequence number rejection (REPLAY)
- Out-of-order message rejection
- Sequence number monotonicity enforcement

**Expected output:**
```
=== Test 1: Replay Attack ===
✓ Test PASSED - REPLAY DETECTED: seqno 2 <= current 3
Message REJECTED

=== Test 2: Out of Order (Skip) ===
✓ Valid seqno: 5 > 3
Message ACCEPTED
```

### Test 5: Wireshark Packet Capture
```bash
# Terminal 1: Start packet capture BEFORE server
sudo tcpdump -i lo port 5555 -w captures/demo_session.pcap

# Terminal 2: Start server
python3 server.py

# Terminal 3: Start client and chat
python3 client.py
# Register/login, send messages, quit

# Terminal 1: Stop capture (Ctrl+C)

# Analyze with Wireshark
wireshark captures/demo_session.pcap
```

**Wireshark Display Filters to Use:**
```
tcp.port == 5555
tcp.port == 5555 && tcp.len > 0
```

**What to verify in Wireshark:**
- ✅ No plaintext messages visible
- ✅ Certificate exchange (PEM format visible)
- ✅ Encrypted payloads (binary/base64 data)
- ✅ No passwords or credentials in plaintext
- ✅ All chat messages are encrypted

### Test 6: Non-Repudiation Verification
```bash
# After a chat session, list transcript files
ls transcripts/

# Verify individual transcript entries
python3 verify_transcript.py transcripts/client_alice_1234567890.txt certs/client_cert.pem

# Verify session receipt
python3 verify_transcript.py transcripts/client_alice_1234567890_receipt.json certs/client_cert.pem transcripts/client_alice_1234567890.txt
```

**Expected output:**
```
=== Verifying Transcript ===
Entry 1: ✓ Seqno 1: Signature valid
Entry 2: ✓ Seqno 2: Signature valid
Entry 3: ✓ Seqno 3: Signature valid

=== Verifying Session Receipt ===
✓ Transcript hash matches
✓ Receipt signature is VALID

=== Test: Tampered Transcript Detection ===
✓ Test PASSED - Tampering detected!
```

## 📁 Project Structure
```
securechat-assignment/
├── certs/                          # X.509 Certificates (NOT in Git)
│   ├── ca_cert.pem                 # Root CA certificate
│   ├── ca_key.pem                  # Root CA private key
│   ├── server_cert.pem             # Server certificate
│   ├── server_key.pem              # Server private key
│   ├── client_cert.pem             # Client certificate
│   └── client_key.pem              # Client private key
│
├── scripts/                        # Certificate generation scripts
│   ├── gen_ca.py                   # Generate root CA
│   └── gen_cert.py                 # Issue certificates
│
├── transcripts/                    # Session transcripts (NOT in Git)
│   ├── client_alice_1234567890.txt
│   ├── client_alice_1234567890_receipt.json
│   ├── server_1234567890.txt
│   └── server_1234567890_receipt.json
│
├── captures/                       # Wireshark packet captures
│   └── demo_session.pcap
│
├
│
├── test_certs/                     # Test certificates (generated)
│   ├── self_signed.pem
│   ├── expired.pem
│   └── wrong_cn.pem
│
├── server.py                       # Server implementation
├── client.py                       # Client implementation
├── crypto_utils.py                 # Cryptographic utilities
├── protocol.py                     # Protocol message definitions
├── user_manager.py                 # User authentication module
├── db_config.py                    # Database configuration
├── transcript_manager.py           # Transcript handling
│
├── test_crypto.py                  # Crypto utilities tests
├── test_bad_cert.py                # Certificate validation tests
├── test_tampering.py               # Message integrity tests
├── test_replay.py                  # Replay attack tests
├── verify_transcript.py            # Offline verification tool
│
├── schema.sql                      # MySQL database schema
├── requirements.txt                # Python dependencies
├── .env                            # Environment config (NOT in Git)
├── .env.example                    # Environment template
├── .gitignore                      # Git ignore rules
└── README.md                       # This file
```

## 🔒 Security Features

### Password Security
- ✅ Random 16-byte salt per user
- ✅ SHA-256 salted password hashing
- ✅ No plaintext passwords stored or transmitted
- ✅ Credentials encrypted during transit (via temporary DH)

### Message Security
- ✅ AES-128 encryption (CBC mode, PKCS#7 padding)
- ✅ Per-message RSA signatures (2048-bit keys)
- ✅ SHA-256 message digests
- ✅ Sequence numbers for replay protection
- ✅ Timestamps for freshness verification

### Certificate Security
- ✅ X.509 certificate validation
- ✅ Signature chain verification against CA
- ✅ Expiry date checking
- ✅ Common Name (CN) validation
- ✅ Certificate fingerprinting

### Non-Repudiation
- ✅ Append-only transcript logs
- ✅ Signed transcript hashes
- ✅ SessionReceipts for proof of communication
- ✅ Offline verification capability
- ✅ Tamper detection

#
## 🐛 Troubleshooting

### Issue: MySQL Connection Failed
```bash
# Check MySQL service
sudo systemctl status mysql

# Restart MySQL
sudo systemctl restart mysql

# Verify credentials in .env file
cat .env
```

### Issue: Certificate Not Found
```bash
# Regenerate certificates
python3 scripts/gen_ca.py
python3 scripts/gen_cert.py
```

### Issue: Module Not Found
```bash
# Reinstall dependencies
source venv/bin/activate
pip install --upgrade -r requirements.txt
```

### Issue: Permission Denied for tcpdump
```bash
# Run with sudo
sudo tcpdump -i lo port 5555 -w captures/test.pcap
```

### Issue: Port Already in Use
```bash
# Find process using port 5555
sudo lsof -i :5555

# Kill the process
kill -9 <PID>
```

## 📚 References

- Python Cryptography Library: https://cryptography.io/
- SEED Security Labs (PKI): https://seedsecuritylabs.org/
- RFC 5280 - X.509 Certificates
- NIST SP 800-38A - AES Modes
- RFC 2631 - Diffie-Hellman Key Agreement

## 📧 Contact

- **Student**: Usman Haroon
- **Email**: i221177@nu.edu.pk
- **GitHub**: [@UsmanHaroon1177](https://github.com/UsmanHaroon1177)

---

**⚠️ Important Notes:**
- Never commit private keys (.key files) to Git
- Never commit .env files with passwords
- Always use strong passwords for production
- This is an educational project for learning purposes


