#!/usr/bin/env python3
"""
Secure Chat Client
Connects to server, performs authentication, key exchange, and encrypted messaging
"""

import socket
import threading
import json
import os
import sys
import base64
import getpass
from datetime import datetime
from crypto_utils import crypto
from protocol import Protocol
from transcript_manager import TranscriptManager

class SecureChatClient:
    """Secure chat client implementation"""
    
    def __init__(self, server_host='127.0.0.1', server_port=5555):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        
        # Load client certificate and private key
        self.client_cert = crypto.load_certificate("certs/client_cert.pem")
        self.client_private_key = crypto.load_private_key("certs/client_key.pem")
        self.ca_cert = crypto.load_certificate("certs/ca_cert.pem")
        
        # Client certificate PEM string
        with open("certs/client_cert.pem", 'r') as f:
            self.client_cert_pem = f.read()
        
        print("[+] Client certificates loaded")
        
        # Connection state
        self.server_cert = None
        self.server_cert_pem = None
        self.authenticated = False
        self.username = None
        self.session_key = None
        self.seqno = 0
        self.peer_seqno = 0
        self.transcript = None
        self.running = False
    
    def connect(self):
        """Connect to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"[+] Connected to server {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        try:
            if self.socket:
                # Send disconnect message
                disconnect_msg = Protocol.create_disconnect()
                self.socket.send(disconnect_msg.encode('utf-8'))
                
                self.socket.close()
                print("[+] Disconnected from server")
        except Exception as e:
            print(f"[!] Disconnect error: {e}")
    
    def phase_certificate_exchange(self):
        """Phase 1: Certificate exchange and validation"""
        print("\n[Phase 1] Certificate Exchange")
        
        try:
            # Generate nonce
            client_nonce = crypto.generate_nonce(16)
            
            # Send hello message
            hello_msg = Protocol.create_hello(self.client_cert_pem, client_nonce)
            self.socket.send(hello_msg.encode('utf-8'))
            print("[+] Sent hello message to server")
            
            # Receive server hello
            data = self.socket.recv(8192).decode('utf-8')
            msg = Protocol.parse_message(data)
            
            if not msg:
                print("[!] Failed to parse server response")
                return False
            
            if msg['type'] == Protocol.MSG_ERROR:
                print(f"[!] Server error: {msg['message']}")
                return False
            
            if msg['type'] != Protocol.MSG_SERVER_HELLO:
                print(f"[!] Expected server_hello, got {msg['type']}")
                return False
            
            # Extract server certificate
            server_cert_pem = msg['server_cert']
            server_nonce = base64.b64decode(msg['nonce'])
            
            # Load and validate server certificate
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            server_cert = x509.load_pem_x509_certificate(
                server_cert_pem.encode('utf-8'),
                default_backend()
            )
            
            # Validate certificate
            valid, error = crypto.validate_certificate(
                server_cert,
                self.ca_cert,
                expected_cn="securechat.server"
            )
            
            if not valid:
                print(f"[!] Server certificate validation failed: {error}")
                return False
            
            print("[+] Server certificate validated successfully")
            self.server_cert = server_cert
            self.server_cert_pem = server_cert_pem
            
            return True
            
        except Exception as e:
            print(f"[!] Certificate exchange error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def phase_authentication(self):
        """Phase 2: User authentication (register/login)"""
        print("\n[Phase 2] Authentication")
        
        # Ask user for action
        print("\n1. Register new account")
        print("2. Login to existing account")
        choice = input("Choose option (1/2): ").strip()
        
        if choice == '1':
            return self.handle_registration()
        elif choice == '2':
            return self.handle_login()
        else:
            print("[!] Invalid choice")
            return False
    
    def handle_registration(self):
        """Handle user registration"""
        print("\n=== Registration ===")
        
        # Get user input
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        
        if not email or not username or not password:
            print("[!] All fields are required")
            return False
        
        try:
            # Perform temporary DH for credential encryption
            print("[+] Establishing temporary secure channel...")
            
            # Generate DH parameters
            p, g = crypto.generate_dh_parameters()
            client_private = crypto.generate_dh_private_key(p)
            client_public = crypto.compute_dh_public_key(g, client_private, p)
            
            # Send DH client message
            dh_msg = Protocol.create_dh_client(g, p, client_public)
            self.socket.send(dh_msg.encode('utf-8'))
            
            # Receive DH server response
            data = self.socket.recv(4096).decode('utf-8')
            msg = Protocol.parse_message(data)
            
            if not msg or msg['type'] != Protocol.MSG_DH_SERVER:
                print("[!] Expected DH server response")
                return False
            
            server_public = msg['B']
            
            # Compute shared secret and derive temporary AES key
            shared_secret = crypto.compute_dh_shared_secret(server_public, client_private, p)
            temp_aes_key = crypto.derive_aes_key_from_dh(shared_secret)
            
            print("[+] Temporary session key established")
            
            # Generate salt and hash password
            salt = crypto.generate_nonce(16)
            pwd_hash = crypto.sha256_hash_hex(salt + password.encode('utf-8'))
            
            # Create registration message
            reg_msg = Protocol.create_register(email, username, pwd_hash, salt)
            
            # Encrypt registration message
            iv, ciphertext = crypto.aes_encrypt(reg_msg, temp_aes_key)
            encrypted_data = iv + ciphertext
            
            # Send encrypted registration
            self.socket.send(encrypted_data)
            
            # Receive response
            response_data = self.socket.recv(4096)
            iv = response_data[:16]
            ciphertext = response_data[16:]
            
            response_json = crypto.aes_decrypt(iv, ciphertext, temp_aes_key)
            response = Protocol.parse_message(response_json)
            
            if response['type'] == Protocol.MSG_AUTH_SUCCESS:
                print(f"[+] {response['message']}")
                self.authenticated = True
                self.username = response['username']
                return True
            else:
                print(f"[!] Registration failed: {response['message']}")
                return False
                
        except Exception as e:
            print(f"[!] Registration error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def handle_login(self):
        """Handle user login"""
        print("\n=== Login ===")
        
        # Get user input
        email = input("Email: ").strip()
        password = getpass.getpass("Password: ")
        
        if not email or not password:
            print("[!] All fields are required")
            return False
        
        try:
            # Perform temporary DH for credential encryption
            print("[+] Establishing temporary secure channel...")
            
            # Generate DH parameters
            p, g = crypto.generate_dh_parameters()
            client_private = crypto.generate_dh_private_key(p)
            client_public = crypto.compute_dh_public_key(g, client_private, p)
            
            # Send DH client message
            dh_msg = Protocol.create_dh_client(g, p, client_public)
            self.socket.send(dh_msg.encode('utf-8'))
            
            # Receive DH server response
            data = self.socket.recv(4096).decode('utf-8')
            msg = Protocol.parse_message(data)
            
            if not msg or msg['type'] != Protocol.MSG_DH_SERVER:
                print("[!] Expected DH server response")
                return False
            
            server_public = msg['B']
            
            # Compute shared secret and derive temporary AES key
            shared_secret = crypto.compute_dh_shared_secret(server_public, client_private, p)
            temp_aes_key = crypto.derive_aes_key_from_dh(shared_secret)
            
            # Retrieve salt from database (in real scenario)
            # For now, we'll need to compute hash with retrieved salt
            # We'll send email first, server returns salt, then we send hash
            
            # Actually, let's simplify: client computes hash locally with salt
            # But client doesn't know salt until it queries server
            # Let's use a different approach: send email, server returns salt,
            # client computes hash, sends hash back
            
            # For simplicity in this implementation, we'll fetch salt inline
            # Create login message with placeholder
            
            # Alternative: Client retrieves salt from server first
            # But that requires extra round trip
            
            # Let's use the approach where we compute hash with known salt
            # We'll modify to: client sends email, gets salt, then sends hash
            
            # For now, simplified approach: get salt from user manager
            import mysql.connector
            from db_config import db_config
            
            conn = db_config.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT salt FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                print("[!] Invalid email or password")
                return False
            
            salt = result[0]
            
            # Compute password hash
            pwd_hash = crypto.sha256_hash_hex(salt + password.encode('utf-8'))
            
            # Create login message
            login_nonce = crypto.generate_nonce(16)
            login_msg = Protocol.create_login(email, pwd_hash, login_nonce)
            
            # Encrypt login message
            iv, ciphertext = crypto.aes_encrypt(login_msg, temp_aes_key)
            encrypted_data = iv + ciphertext
            
            # Send encrypted login
            self.socket.send(encrypted_data)
            
            # Receive response
            response_data = self.socket.recv(4096)
            iv = response_data[:16]
            ciphertext = response_data[16:]
            
            response_json = crypto.aes_decrypt(iv, ciphertext, temp_aes_key)
            response = Protocol.parse_message(response_json)
            
            if response['type'] == Protocol.MSG_AUTH_SUCCESS:
                print(f"[+] {response['message']}")
                self.authenticated = True
                self.username = response['username']
                return True
            else:
                print(f"[!] Login failed: {response['message']}")
                return False
                
        except Exception as e:
            print(f"[!] Login error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def phase_key_agreement(self):
        """Phase 3: Session key establishment via DH"""
        print("\n[Phase 3] Session Key Agreement")
        
        try:
            # Generate DH parameters for session key
            p, g = crypto.generate_dh_parameters()
            client_private = crypto.generate_dh_private_key(p)
            client_public = crypto.compute_dh_public_key(g, client_private, p)
            
            # Send DH client message
            dh_msg = Protocol.create_dh_client(g, p, client_public)
            self.socket.send(dh_msg.encode('utf-8'))
            print("[+] Sent DH parameters to server")
            
            # Receive DH server response
            data = self.socket.recv(4096).decode('utf-8')
            msg = Protocol.parse_message(data)
            
            if not msg or msg['type'] != Protocol.MSG_DH_SERVER:
                print("[!] Expected DH server response")
                return False
            
            server_public = msg['B']
            
            # Compute shared secret and derive session key
            shared_secret = crypto.compute_dh_shared_secret(server_public, client_private, p)
            self.session_key = crypto.derive_aes_key_from_dh(shared_secret)
            
            print(f"[+] Session key established: {self.session_key.hex()}")
            
            # Initialize transcript manager
            session_id = f"{self.username}_{int(datetime.now().timestamp())}"
            self.transcript = TranscriptManager(session_id, "client")
            
            return True
            
        except Exception as e:
            print(f"[!] Key agreement error: {e}")
            return False
    
    def phase_encrypted_chat(self):
        """Phase 4: Encrypted message exchange"""
        print("\n[Phase 4] Encrypted Chat")
        print("=" * 60)
        print(f"Chat session started as {self.username}")
        print("Type your messages and press Enter to send")
        print("Type 'quit' to exit")
        print("=" * 60)
        print()
        
        self.running = True
        
        # Start thread to receive messages
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Send messages from main thread
        try:
            while self.running:
                message = input()
                
                if message.lower() == 'quit':
                    self.running = False
                    break
                
                if not message.strip():
                    continue
                
                self.send_message(message)
                
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            self.running = False
        
        # Generate and send receipt
        self.finalize_session()
    
    def send_message(self, plaintext):
        """Send encrypted and signed message"""
        try:
            # Increment sequence number
            self.seqno += 1
            timestamp = Protocol.get_current_timestamp()
            
            # Encrypt message
            iv, ciphertext = crypto.aes_encrypt(plaintext, self.session_key)
            ct_with_iv = iv + ciphertext
            
            # Compute digest: SHA256(seqno || ts || ct)
            digest_data = f"{self.seqno}{timestamp}".encode('utf-8') + ct_with_iv
            digest = crypto.sha256_hash(digest_data)
            
            # Sign the digest
            signature = crypto.rsa_sign(digest, self.client_private_key)
            
            # Create message
            chat_msg = Protocol.create_chat_message(
                self.seqno,
                timestamp,
                ct_with_iv,
                signature
            )
            
            # Send message
            self.socket.send(chat_msg.encode('utf-8'))
            
            # Add to transcript
            peer_fingerprint = crypto.get_certificate_fingerprint(self.server_cert)
            self.transcript.add_entry(
                self.seqno,
                timestamp,
                base64.b64encode(ct_with_iv).decode('utf-8'),
                base64.b64encode(signature).decode('utf-8'),
                peer_fingerprint
            )
            
            print(f"[You] {plaintext}")
            
        except Exception as e:
            print(f"[!] Send error: {e}")
    
    def receive_messages(self):
        """Thread to receive messages from server"""
        try:
            while self.running:
                data = self.socket.recv(8192).decode('utf-8')
                if not data:
                    break
                
                msg = Protocol.parse_message(data)
                if not msg:
                    continue
                
                if msg['type'] == Protocol.MSG_CHAT:
                    self.handle_chat_message(msg)
                elif msg['type'] == Protocol.MSG_DISCONNECT:
                    print("\n[+] Server disconnected")
                    self.running = False
                    break
                elif msg['type'] == Protocol.MSG_RECEIPT:
                    self.handle_receipt(msg)
                    
        except Exception as e:
            if self.running:
                print(f"[!] Receive error: {e}")
    
    def handle_chat_message(self, msg):
        """Handle incoming encrypted chat message"""
        try:
            seqno = msg['seqno']
            timestamp = msg['ts']
            ct_b64 = msg['ct']
            sig_b64 = msg['sig']
            
            # Check sequence number (replay protection)
            if seqno <= self.peer_seqno:
                print(f"[!] REPLAY: Expected seqno > {self.peer_seqno}, got {seqno}")
                return
            
            self.peer_seqno = seqno
            
            # Decode ciphertext and signature
            ct_with_iv = base64.b64decode(ct_b64)
            signature = base64.b64decode(sig_b64)
            
            # Verify signature
            digest_data = f"{seqno}{timestamp}".encode('utf-8') + ct_with_iv
            digest = crypto.sha256_hash(digest_data)
            
            if not crypto.rsa_verify(digest, signature, self.server_cert):
                print(f"[!] SIG_FAIL: Message signature verification failed")
                return
            
            # Decrypt message
            iv = ct_with_iv[:16]
            ciphertext = ct_with_iv[16:]
            plaintext = crypto.aes_decrypt(iv, ciphertext, self.session_key)
            
            # Add to transcript
            peer_fingerprint = crypto.get_certificate_fingerprint(self.server_cert)
            self.transcript.add_entry(
                seqno,
                timestamp,
                ct_b64,
                sig_b64,
                peer_fingerprint
            )
            
            print(f"[Server] {plaintext}")
            
        except Exception as e:
            print(f"[!] Error handling chat message: {e}")
    
    def handle_receipt(self, msg):
        """Handle session receipt from server"""
        print(f"\n[+] Received session receipt from server")
        print(f"    First seq: {msg['first_seq']}, Last seq: {msg['last_seq']}")
        print(f"    Transcript hash: {msg['transcript_sha256']}")
        
        # Verify receipt
        try:
            signature = base64.b64decode(msg['sig'])
            transcript_hash = msg['transcript_sha256']
            
            if crypto.rsa_verify(transcript_hash, signature, self.server_cert):
                print(f"[+] Receipt signature verified successfully")
            else:
                print(f"[!] Receipt signature verification FAILED")
        except Exception as e:
            print(f"[!] Error verifying receipt: {e}")
    
    def finalize_session(self):
        """Generate session receipt and disconnect"""
        try:
            if self.transcript:
                print("\n[+] Generating session receipt...")
                receipt = self.transcript.generate_receipt(self.client_private_key)
                
                # Send receipt to server
                try:
                    receipt_msg = Protocol.create_receipt(
                        "client",
                        receipt['first_seq'],
                        receipt['last_seq'],
                        receipt['transcript_sha256'],
                        base64.b64decode(receipt['signature'])
                    )
                    self.socket.send(receipt_msg.encode('utf-8'))
                    print("[+] Receipt sent to server")
                except:
                    pass
        except Exception as e:
            print(f"[!] Error finalizing session: {e}")

def main():
    """Main client entry point"""
    print("=" * 60)
    print("          Secure Chat Client")
    print("=" * 60)
    
    # Check if certificates exist
    if not os.path.exists("certs/client_cert.pem"):
        print("[!] Error: Client certificate not found!")
        print("    Please run: python3 scripts/gen_ca.py")
        print("    Then run: python3 scripts/gen_cert.py")
        return
    
    if not os.path.exists("certs/ca_cert.pem"):
        print("[!] Error: CA certificate not found!")
        print("    Please run: python3 scripts/gen_ca.py first")
        return
    
    # Create client
    client = SecureChatClient(server_host='127.0.0.1', server_port=5555)
    
    try:
        # Phase 1: Connect and exchange certificates
        if not client.connect():
            return
        
        if not client.phase_certificate_exchange():
            client.disconnect()
            return
        
        # Phase 2: Authentication
        if not client.phase_authentication():
            client.disconnect()
            return
        
        # Phase 3: Session key agreement
        if not client.phase_key_agreement():
            client.disconnect()
            return
        
        # Phase 4: Encrypted chat
        client.phase_encrypted_chat()
        
    except KeyboardInterrupt:
        print("\n[!] Client interrupted by user")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
