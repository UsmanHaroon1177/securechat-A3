#!/usr/bin/env python3
"""
Secure Chat Server
Handles client connections, authentication, key exchange, and encrypted messaging
"""

import socket
import threading
import json
import os
import base64
from datetime import datetime
from crypto_utils import crypto
from protocol import Protocol
from user_manager import user_manager
from transcript_manager import TranscriptManager


class SecureChatServer:
    """Secure chat server implementation"""

    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None

        # Load server certificate and private key
        self.server_cert = crypto.load_certificate("certs/server_cert.pem")
        self.server_private_key = crypto.load_private_key("certs/server_key.pem")
        self.ca_cert = crypto.load_certificate("certs/ca_cert.pem")

        # Server certificate PEM string
        with open("certs/server_cert.pem", 'r') as f:
            self.server_cert_pem = f.read()

        print("[+] Server certificates loaded")

        # Connected clients
        self.clients = {}
        self.client_counter = 0

    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        print(f"[+] Server started on {self.host}:{self.port}")
        print("[+] Waiting for clients...")

        try:
            while True:
                client_socket, address = self.server_socket.accept()
                print(f"\n[+] New connection from {address}")

                # Handle client in a new thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()

        except KeyboardInterrupt:
            print("\n[!] Server shutting down...")
            self.stop()

    def stop(self):
        """Stop the server"""
        if self.server_socket:
            self.server_socket.close()
        print("[+] Server stopped")

    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        client_id = self.client_counter
        self.client_counter += 1

        client_state = {
            'socket': client_socket,
            'address': address,
            'id': client_id,
            'cert': None,
            'authenticated': False,
            'username': None,
            'session_key': None,
            'seqno': 0,
            'peer_seqno': 0,
            'transcript': None
        }

        self.clients[client_id] = client_state

        try:
            # Phase 1: Certificate Exchange (Hello)
            if not self.phase_certificate_exchange(client_state):
                return

            # Phase 2: Authentication (Register/Login)
            if not self.phase_authentication(client_state):
                return

            # Phase 3: Session Key Agreement (DH)
            if not self.phase_key_agreement(client_state):
                return

            # Phase 4: Encrypted Chat
            self.phase_encrypted_chat(client_state)

        except Exception as e:
            print(f"[!] Error handling client {client_id}: {e}")
        finally:
            self.cleanup_client(client_state)

    def phase_certificate_exchange(self, client_state):
        """Phase 1: Certificate exchange and validation"""
        print(f"\n[Phase 1] Certificate Exchange - Client {client_state['id']}")

        try:
            # Receive client hello
            data = client_state['socket'].recv(8192).decode('utf-8')
            msg = Protocol.parse_message(data)

            if not msg or msg['type'] != Protocol.MSG_HELLO:
                print("[!] Expected hello message")
                return False

            # Extract client certificate
            client_cert_pem = msg['client_cert']
            client_nonce = base64.b64decode(msg['nonce'])

            # Load and validate client certificate
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            client_cert = x509.load_pem_x509_certificate(
                client_cert_pem.encode('utf-8'),
                default_backend()
            )

            # Validate certificate
            valid, error = crypto.validate_certificate(
                client_cert,
                self.ca_cert,
                expected_cn="securechat.client"
            )

            if not valid:
                print(f"[!] Certificate validation failed: {error}")
                error_msg = Protocol.create_error(error)
                client_state['socket'].send(error_msg.encode('utf-8'))
                return False

            print(f"[+] Client certificate validated successfully")
            client_state['cert'] = client_cert
            client_state['cert_pem'] = client_cert_pem

            # Send server hello
            server_nonce = crypto.generate_nonce(16)
            server_hello = Protocol.create_server_hello(
                self.server_cert_pem,
                server_nonce
            )
            client_state['socket'].send(server_hello.encode('utf-8'))

            print(f"[+] Server hello sent")
            return True

        except Exception as e:
            print(f"[!] Certificate exchange error: {e}")
            return False

    def phase_authentication(self, client_state):
        """Phase 2: User authentication (register/login)"""
        print(f"\n[Phase 2] Authentication - Client {client_state['id']}")

        try:
            print("[+] Performing temporary DH exchange for credential encryption...")

            # Receive DH client message
            data = client_state['socket'].recv(4096).decode('utf-8')
            msg = Protocol.parse_message(data)

            if not msg or msg['type'] != Protocol.MSG_DH_CLIENT:
                print("[!] Expected DH client message")
                return False

            g = msg['g']
            p = msg['p']
            client_public = msg['A']

            # Generate server DH key pair
            server_private = crypto.generate_dh_private_key(p)
            server_public = crypto.compute_dh_public_key(g, server_private, p)

            # Send server DH response
            dh_response = Protocol.create_dh_server(server_public)
            client_state['socket'].send(dh_response.encode('utf-8'))

            # Compute shared secret and derive AES key
            shared_secret = crypto.compute_dh_shared_secret(client_public, server_private, p)
            temp_aes_key = crypto.derive_aes_key_from_dh(shared_secret)

            print("[+] Temporary session key established")

            # Receive encrypted auth message
            data = client_state['socket'].recv(4096)
            iv = data[:16]
            ciphertext = data[16:]

            auth_json = crypto.aes_decrypt(iv, ciphertext, temp_aes_key)
            auth_msg = Protocol.parse_message(auth_json)

            if not auth_msg:
                print("[!] Failed to parse auth message")
                return False

            if auth_msg['type'] == Protocol.MSG_REGISTER:
                return self.handle_registration(client_state, auth_msg, temp_aes_key)
            elif auth_msg['type'] == Protocol.MSG_LOGIN:
                return self.handle_login(client_state, auth_msg, temp_aes_key)
            else:
                print(f"[!] Unexpected auth message type: {auth_msg['type']}")
                return False

        except Exception as e:
            print(f"[!] Authentication error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def handle_registration(self, client_state, msg, temp_key):
        """Handle user registration"""
        print("[+] Processing registration...")

        email = msg['email']
        username = msg['username']
        pwd_hash = base64.b64decode(msg['pwd']).decode('utf-8')
        salt = base64.b64decode(msg['salt'])

        try:
            exists, msg_text = user_manager.user_exists(email=email, username=username)
            if exists:
                response = Protocol.create_auth_response(False, msg_text)
                iv, ct = crypto.aes_encrypt(response, temp_key)
                client_state['socket'].send(iv + ct)
                return False

            conn = user_manager._get_connection()
            cursor = conn.cursor()
            query = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (email, username, salt, pwd_hash))
            conn.commit()
            cursor.close()

            print(f"[+] User '{username}' registered successfully")
            client_state['username'] = username
            client_state['authenticated'] = True

            response = Protocol.create_auth_response(True, "Registration successful", username)
            iv, ct = crypto.aes_encrypt(response, temp_key)
            client_state['socket'].send(iv + ct)

            return True

        except Exception as e:
            print(f"[!] Registration error: {e}")
            response = Protocol.create_auth_response(False, f"Registration failed: {e}")
            iv, ct = crypto.aes_encrypt(response, temp_key)
            client_state['socket'].send(iv + ct)
            return False

    def handle_login(self, client_state, msg, temp_key):
        """Handle user login"""
        print("[+] Processing login...")

        email = msg['email']
        pwd_hash = base64.b64decode(msg['pwd']).decode('utf-8')

        try:
            conn = user_manager._get_connection()
            cursor = conn.cursor()
            query = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            cursor.close()

            if not result:
                response = Protocol.create_auth_response(False, "Invalid email or password")
                iv, ct = crypto.aes_encrypt(response, temp_key)
                client_state['socket'].send(iv + ct)
                return False

            username, salt, stored_hash = result

            if pwd_hash == stored_hash:
                print(f"[+] User '{username}' authenticated successfully")
                client_state['username'] = username
                client_state['authenticated'] = True

                response = Protocol.create_auth_response(True, "Login successful", username)
                iv, ct = crypto.aes_encrypt(response, temp_key)
                client_state['socket'].send(iv + ct)
                return True
            else:
                response = Protocol.create_auth_response(False, "Invalid email or password")
                iv, ct = crypto.aes_encrypt(response, temp_key)
                client_state['socket'].send(iv + ct)
                return False

        except Exception as e:
            print(f"[!] Login error: {e}")
            response = Protocol.create_auth_response(False, f"Login failed: {e}")
            iv, ct = crypto.aes_encrypt(response, temp_key)
            client_state['socket'].send(iv + ct)
            return False

    def phase_key_agreement(self, client_state):
        """Phase 3: Session key establishment via DH"""
        print(f"\n[Phase 3] Session Key Agreement - Client {client_state['id']}")

        try:
            data = client_state['socket'].recv(4096).decode('utf-8')
            msg = Protocol.parse_message(data)

            if not msg or msg['type'] != Protocol.MSG_DH_CLIENT:
                print("[!] Expected DH client message for session")
                return False

            g = msg['g']
            p = msg['p']
            client_public = msg['A']

            print(f"[+] Received DH parameters from client")

            server_private = crypto.generate_dh_private_key(p)
            server_public = crypto.compute_dh_public_key(g, server_private, p)

            dh_response = Protocol.create_dh_server(server_public)
            client_state['socket'].send(dh_response.encode('utf-8'))

            shared_secret = crypto.compute_dh_shared_secret(client_public, server_private, p)
            session_key = crypto.derive_aes_key_from_dh(shared_secret)

            client_state['session_key'] = session_key

            session_id = f"{client_state['username']}_{int(datetime.now().timestamp())}"
            client_state['transcript'] = TranscriptManager(session_id, "server")

            print(f"[+] Session key established: {session_key.hex()}")
            return True

        except Exception as e:
            print(f"[!] Key agreement error: {e}")
            return False

    def phase_encrypted_chat(self, client_state):
        """Phase 4: Encrypted message exchange"""
        print(f"\n[Phase 4] Encrypted Chat - Client {client_state['id']} ({client_state['username']})")
        print("[+] Chat session active. Waiting for messages...")
        print("[+] Type messages to send, or 'quit' to disconnect\n")

        send_thread = threading.Thread(target=self.send_messages, args=(client_state,))
        send_thread.daemon = True
        send_thread.start()

        try:
            while True:
                data = client_state['socket'].recv(8192).decode('utf-8')
                if not data:
                    break

                msg = Protocol.parse_message(data)
                if not msg:
                    continue

                if msg['type'] == Protocol.MSG_CHAT:
                    self.handle_chat_message(client_state, msg)
                elif msg['type'] == Protocol.MSG_DISCONNECT:
                    print(f"[+] Client {client_state['username']} disconnected")
                    break
                elif msg['type'] == Protocol.MSG_RECEIPT:
                    self.handle_receipt(client_state, msg)

        except Exception as e:
            print(f"[!] Chat error: {e}")

    def send_messages(self, client_state):
        """Thread to send messages from server console"""
        try:
            while True:
                message = input()
                if message.lower() == 'quit':
                    disconnect_msg = Protocol.create_disconnect()
                    client_state['socket'].send(disconnect_msg.encode('utf-8'))
                    break

                if not message.strip():
                    continue

                client_state['seqno'] += 1
                timestamp = Protocol.get_current_timestamp()

                iv, ciphertext = crypto.aes_encrypt(message, client_state['session_key'])
                ct_with_iv = iv + ciphertext

                digest_data = f"{client_state['seqno']}{timestamp}".encode('utf-8') + ct_with_iv
                digest = crypto.sha256_hash(digest_data)
                signature = crypto.rsa_sign(digest, self.server_private_key)

                chat_msg = Protocol.create_chat_message(
                    client_state['seqno'],
                    timestamp,
                    ct_with_iv,
                    signature
                )

                client_state['socket'].send(chat_msg.encode('utf-8'))

                peer_fingerprint = crypto.get_certificate_fingerprint(client_state['cert'])
                client_state['transcript'].add_entry(
                    client_state['seqno'],
                    timestamp,
                    base64.b64encode(ct_with_iv).decode('utf-8'),
                    base64.b64encode(signature).decode('utf-8'),
                    peer_fingerprint
                )

                print(f"[SENT] {message}")

        except Exception as e:
            print(f"[!] Send error: {e}")

    def handle_chat_message(self, client_state, msg):
        """Handle incoming encrypted chat message"""
        try:
            seqno = msg['seqno']
            timestamp = msg['ts']
            ct_b64 = msg['ct']
            sig_b64 = msg['sig']

            if seqno <= client_state['peer_seqno']:
                print(f"[!] REPLAY: Expected seqno > {client_state['peer_seqno']}, got {seqno}")
                return

            client_state['peer_seqno'] = seqno

            ct_with_iv = base64.b64decode(ct_b64)
            signature = base64.b64decode(sig_b64)

            digest_data = f"{seqno}{timestamp}".encode('utf-8') + ct_with_iv
            digest = crypto.sha256_hash(digest_data)

            if not crypto.rsa_verify(digest, signature, client_state['cert']):
                print(f"[!] SIG_FAIL: Message signature verification failed")
                return

            iv = ct_with_iv[:16]
            ciphertext = ct_with_iv[16:]
            plaintext = crypto.aes_decrypt(iv, ciphertext, client_state['session_key'])

            peer_fingerprint = crypto.get_certificate_fingerprint(client_state['cert'])
            client_state['transcript'].add_entry(
                seqno,
                timestamp,
                ct_b64,
                sig_b64,
                peer_fingerprint
            )

            print(f"[{client_state['username']}] {plaintext}")

        except Exception as e:
            print(f"[!] Error handling chat message: {e}")
            import traceback
            traceback.print_exc()

    def handle_receipt(self, client_state, msg):
        """Handle session receipt"""
        print(f"\n[+] Received session receipt from {client_state['username']}")
        print(f"    First seq: {msg['first_seq']}, Last seq: {msg['last_seq']}")
        print(f"    Transcript hash: {msg['transcript_sha256']}")

    def cleanup_client(self, client_state):
        """Clean up client connection and generate receipt"""
        try:
            if client_state['transcript'] and client_state['authenticated']:
                print(f"\n[+] Generating session receipt for {client_state['username']}...")
                receipt = client_state['transcript'].generate_receipt(self.server_private_key)

                try:
                    receipt_msg = Protocol.create_receipt(
                        "server",
                        receipt['first_seq'],
                        receipt['last_seq'],
                        receipt['transcript_sha256'],
                        base64.b64decode(receipt['signature'])
                    )
                    client_state['socket'].send(receipt_msg.encode('utf-8'))
                except:
                    pass

            client_state['socket'].close()

            if client_state['id'] in self.clients:
                del self.clients[client_state['id']]

            print(f"[+] Client {client_state['id']} cleaned up")

        except Exception as e:
            print(f"[!] Cleanup error: {e}")


def main():
    """Main server entry point"""
    print("=" * 60)
    print("          Secure Chat Server")
    print("=" * 60)

    if not os.path.exists("certs/server_cert.pem"):
        print("[!] Error: Server certificate not found!")
        print("    Please run: python3 scripts/gen_ca.py")
        print("    Then run: python3 scripts/gen_cert.py")
        return

    if not os.path.exists("certs/ca_cert.pem"):
        print("[!] Error: CA certificate not found!")
        print("    Please run: python3 scripts/gen_ca.py first")
        return

    server = SecureChatServer(host='127.0.0.1', port=5555)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Server interrupted by user")
        server.stop()


if __name__ == "__main__":
    main()
