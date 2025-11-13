#!/usr/bin/env python3
"""
Transcript management for non-repudiation
Maintains append-only log of all messages with metadata
"""

import os
from datetime import datetime
from crypto_utils import crypto

class TranscriptManager:
    """Manages session transcripts for non-repudiation"""
    
    def __init__(self, session_id, peer_type):
        """
        Initialize transcript manager
        session_id: unique identifier for this session
        peer_type: "client" or "server"
        """
        self.session_id = session_id
        self.peer_type = peer_type
        self.transcript_lines = []
        self.first_seq = None
        self.last_seq = None
        
        # Create transcripts directory if it doesn't exist
        os.makedirs("transcripts", exist_ok=True)
        
        # Transcript file path
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.transcript_file = f"transcripts/{peer_type}_{session_id}_{timestamp}.txt"
        
        print(f"[+] Transcript initialized: {self.transcript_file}")
    
    def add_entry(self, seqno, timestamp, ciphertext, signature, peer_cert_fingerprint):
        """
        Add an entry to the transcript
        Format: seqno | ts | ct | sig | peer-cert-fingerprint
        """
        # Update sequence tracking
        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno
        
        # Create transcript line
        line = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_cert_fingerprint}"
        self.transcript_lines.append(line)
        
        # Append to file immediately (append-only)
        try:
            with open(self.transcript_file, 'a') as f:
                f.write(line + "\n")
        except Exception as e:
            print(f"[!] Error writing to transcript: {e}")
    
    def compute_transcript_hash(self):
        """
        Compute SHA-256 hash of the entire transcript
        Returns: hex string of hash
        """
        # Concatenate all transcript lines
        transcript_data = "\n".join(self.transcript_lines)
        
        # Compute SHA-256 hash
        hash_hex = crypto.sha256_hash_hex(transcript_data)
        
        return hash_hex
    
    def generate_receipt(self, private_key):
        """
        Generate a signed session receipt
        Returns: dict with receipt data
        """
        if not self.transcript_lines:
            print("[!] No transcript entries to generate receipt")
            return None
        
        # Compute transcript hash
        transcript_hash = self.compute_transcript_hash()
        
        # Sign the transcript hash
        signature = crypto.rsa_sign(transcript_hash, private_key)
        
        receipt = {
            "peer": self.peer_type,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "transcript_sha256": transcript_hash,
            "signature": crypto.base64_encode(signature),
            "transcript_file": self.transcript_file
        }
        
        # Save receipt to file
        receipt_file = self.transcript_file.replace(".txt", "_receipt.json")
        import json
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[+] Session receipt generated: {receipt_file}")
        
        return receipt
    
    def verify_receipt(self, receipt, certificate):
        """
        Verify a session receipt
        Returns: (valid: bool, message: str)
        """
        try:
            # Decode signature
            signature = crypto.base64_decode(receipt["signature"])
            
            # Verify signature
            transcript_hash = receipt["transcript_sha256"]
            is_valid = crypto.rsa_verify(transcript_hash, signature, certificate)
            
            if is_valid:
                return True, "Receipt signature is valid"
            else:
                return False, "Receipt signature is INVALID"
                
        except Exception as e:
            return False, f"Receipt verification error: {e}"
    
    def get_stats(self):
        """Get transcript statistics"""
        return {
            "session_id": self.session_id,
            "peer_type": self.peer_type,
            "total_messages": len(self.transcript_lines),
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "transcript_file": self.transcript_file
        }
