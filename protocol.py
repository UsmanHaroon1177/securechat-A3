#!/usr/bin/env python3
"""
Protocol message definitions and handlers
Defines JSON message formats for the secure chat protocol
"""

import json
import time
import base64

class Protocol:
    """Protocol message builder and parser"""
    
    # Message types
    MSG_HELLO = "hello"
    MSG_SERVER_HELLO = "server_hello"
    MSG_REGISTER = "register"
    MSG_LOGIN = "login"
    MSG_AUTH_SUCCESS = "auth_success"
    MSG_AUTH_FAIL = "auth_fail"
    MSG_DH_CLIENT = "dh_client"
    MSG_DH_SERVER = "dh_server"
    MSG_CHAT = "msg"
    MSG_RECEIPT = "receipt"
    MSG_ERROR = "error"
    MSG_DISCONNECT = "disconnect"
    
    @staticmethod
    def create_hello(cert_pem, nonce):
        """Create hello message with certificate and nonce"""
        return json.dumps({
            "type": Protocol.MSG_HELLO,
            "client_cert": cert_pem,
            "nonce": base64.b64encode(nonce).decode('utf-8')
        })
    
    @staticmethod
    def create_server_hello(cert_pem, nonce):
        """Create server hello message"""
        return json.dumps({
            "type": Protocol.MSG_SERVER_HELLO,
            "server_cert": cert_pem,
            "nonce": base64.b64encode(nonce).decode('utf-8')
        })
    
    @staticmethod
    def create_register(email, username, pwd_hash, salt):
        """Create registration message (to be encrypted)"""
        return json.dumps({
            "type": Protocol.MSG_REGISTER,
            "email": email,
            "username": username,
            "pwd": base64.b64encode(pwd_hash.encode('utf-8')).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8')
        })
    
    @staticmethod
    def create_login(email, pwd_hash, nonce):
        """Create login message (to be encrypted)"""
        return json.dumps({
            "type": Protocol.MSG_LOGIN,
            "email": email,
            "pwd": base64.b64encode(pwd_hash.encode('utf-8')).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8')
        })
    
    @staticmethod
    def create_auth_response(success, message, username=None):
        """Create authentication response"""
        if success:
            return json.dumps({
                "type": Protocol.MSG_AUTH_SUCCESS,
                "message": message,
                "username": username
            })
        else:
            return json.dumps({
                "type": Protocol.MSG_AUTH_FAIL,
                "message": message
            })
    
    @staticmethod
    def create_dh_client(g, p, public_key):
        """Create DH client message with parameters"""
        return json.dumps({
            "type": Protocol.MSG_DH_CLIENT,
            "g": g,
            "p": p,
            "A": public_key
        })
    
    @staticmethod
    def create_dh_server(public_key):
        """Create DH server response"""
        return json.dumps({
            "type": Protocol.MSG_DH_SERVER,
            "B": public_key
        })
    
    @staticmethod
    def create_chat_message(seqno, timestamp, ciphertext, signature):
        """Create encrypted chat message with signature"""
        return json.dumps({
            "type": Protocol.MSG_CHAT,
            "seqno": seqno,
            "ts": timestamp,
            "ct": base64.b64encode(ciphertext).decode('utf-8'),
            "sig": base64.b64encode(signature).decode('utf-8')
        })
    
    @staticmethod
    def create_receipt(peer, first_seq, last_seq, transcript_hash, signature):
        """Create session receipt for non-repudiation"""
        return json.dumps({
            "type": Protocol.MSG_RECEIPT,
            "peer": peer,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": base64.b64encode(signature).decode('utf-8')
        })
    
    @staticmethod
    def create_error(message):
        """Create error message"""
        return json.dumps({
            "type": Protocol.MSG_ERROR,
            "message": message
        })
    
    @staticmethod
    def create_disconnect():
        """Create disconnect message"""
        return json.dumps({
            "type": Protocol.MSG_DISCONNECT
        })
    
    @staticmethod
    def parse_message(json_str):
        """Parse JSON message"""
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"[!] JSON parse error: {e}")
            return None
    
    @staticmethod
    def get_current_timestamp():
        """Get current Unix timestamp in milliseconds"""
        return int(time.time() * 1000)
