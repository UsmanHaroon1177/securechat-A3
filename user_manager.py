#!/usr/bin/env python3
"""
User registration and authentication management
Handles salted password hashing and credential verification
"""

import hashlib
import os
from db_config import db_config
from mysql.connector import Error

class UserManager:
    """Manages user registration and authentication"""
    
    def __init__(self):
        self.connection = None
    
    def _get_connection(self):
        """Get database connection"""
        if self.connection is None or not self.connection.is_connected():
            self.connection = db_config.get_connection()
        return self.connection
    
    def _generate_salt(self):
        """Generate a random 16-byte salt"""
        return os.urandom(16)
    
    def _hash_password(self, salt, password):
        """
        Compute salted password hash: SHA256(salt || password)
        Returns hex string of 64 characters
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
        if isinstance(salt, str):
            salt = salt.encode('utf-8')
        
        # Concatenate salt and password
        salted = salt + password
        
        # Compute SHA-256 hash
        pwd_hash = hashlib.sha256(salted).hexdigest()
        return pwd_hash
    
    def user_exists(self, email=None, username=None):
        """
        Check if user exists by email or username
        Returns: (exists: bool, message: str)
        """
        try:
            conn = self._get_connection()
            if not conn:
                return False, "Database connection failed"
            
            cursor = conn.cursor()
            
            if email:
                cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s", (email,))
                count = cursor.fetchone()[0]
                cursor.close()
                if count > 0:
                    return True, "Email already registered"
            
            if username:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
                count = cursor.fetchone()[0]
                cursor.close()
                if count > 0:
                    return True, "Username already taken"
            
            return False, "User does not exist"
            
        except Error as e:
            print(f"[!] Database error in user_exists: {e}")
            return False, f"Database error: {e}"
    
    def register_user(self, email, username, password):
        """
        Register a new user with salted password hash
        Returns: (success: bool, message: str)
        """
        try:
            # Check if user already exists
            exists, msg = self.user_exists(email=email, username=username)
            if exists:
                return False, msg
            
            # Generate salt
            salt = self._generate_salt()
            
            # Compute password hash
            pwd_hash = self._hash_password(salt, password)
            
            # Insert into database
            conn = self._get_connection()
            if not conn:
                return False, "Database connection failed"
            
            cursor = conn.cursor()
            query = """
                INSERT INTO users (email, username, salt, pwd_hash) 
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query, (email, username, salt, pwd_hash))
            conn.commit()
            cursor.close()
            
            print(f"[+] User '{username}' registered successfully")
            return True, "Registration successful"
            
        except Error as e:
            print(f"[!] Database error in register_user: {e}")
            return False, f"Registration failed: {e}"
    
    def authenticate_user(self, email, password):
        """
        Authenticate user with email and password
        Returns: (success: bool, username: str or None, message: str)
        """
        try:
            conn = self._get_connection()
            if not conn:
                return False, None, "Database connection failed"
            
            cursor = conn.cursor()
            query = "SELECT username, salt, pwd_hash FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                return False, None, "Invalid email or password"
            
            username, salt, stored_hash = result
            
            # Recompute hash with provided password
            computed_hash = self._hash_password(salt, password)
            
            # Constant-time comparison to prevent timing attacks
            if self._constant_time_compare(computed_hash, stored_hash):
                print(f"[+] User '{username}' authenticated successfully")
                return True, username, "Authentication successful"
            else:
                return False, None, "Invalid email or password"
                
        except Error as e:
            print(f"[!] Database error in authenticate_user: {e}")
            return False, None, f"Authentication failed: {e}"
    
    def _constant_time_compare(self, a, b):
        """
        Constant-time string comparison to prevent timing attacks
        """
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y)
        
        return result == 0
    
    def get_user_info(self, email):
        """
        Get user information by email
        Returns: dict with user info or None
        """
        try:
            conn = self._get_connection()
            if not conn:
                return None
            
            cursor = conn.cursor(dictionary=True)
            query = "SELECT email, username, created_at FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            cursor.close()
            
            return result
            
        except Error as e:
            print(f"[!] Database error in get_user_info: {e}")
            return None

# Create singleton instance
user_manager = UserManager()
