#!/usr/bin/env python3
"""
Database configuration and connection management
Handles MySQL connection pooling and configuration loading
"""

import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class DatabaseConfig:
    """Database configuration singleton"""
    
    def __init__(self):
        self.host = os.getenv('DB_HOST', 'localhost')
        self.user = os.getenv('DB_USER', 'chatuser')
        self.password = os.getenv('DB_PASSWORD', 'your_secure_password')
        self.database = os.getenv('DB_NAME', 'securechat')
        self.connection = None
    
    def get_connection(self):
        """Create and return a database connection"""
        try:
            if self.connection is None or not self.connection.is_connected():
                self.connection = mysql.connector.connect(
                    host=self.host,
                    user=self.user,
                    password=self.password,
                    database=self.database
                )
                if self.connection.is_connected():
                    print("[+] Successfully connected to MySQL database")
            return self.connection
        except Error as e:
            print(f"[!] Error connecting to MySQL: {e}")
            return None
    
    def close_connection(self):
        """Close the database connection"""
        if self.connection and self.connection.is_connected():
            self.connection.close()
            print("[+] MySQL connection closed")

# Singleton instance
db_config = DatabaseConfig()
