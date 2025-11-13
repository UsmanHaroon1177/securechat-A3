#!/usr/bin/env python3
"""
Test script for UserManager
"""

from user_manager import user_manager

def test_user_manager():
    print("=== Testing User Manager ===\n")
    
    # Test 1: Register new user
    print("Test 1: Registering new user...")
    success, msg = user_manager.register_user(
        email="test@example.com",
        username="testuser",
        password="SecurePass123!"
    )
    print(f"Result: {success}, Message: {msg}\n")
    
    # Test 2: Try to register duplicate
    print("Test 2: Attempting duplicate registration...")
    success, msg = user_manager.register_user(
        email="test@example.com",
        username="testuser2",
        password="AnotherPass456!"
    )
    print(f"Result: {success}, Message: {msg}\n")
    
    # Test 3: Authenticate with correct password
    print("Test 3: Authenticating with correct password...")
    success, username, msg = user_manager.authenticate_user(
        email="test@example.com",
        password="SecurePass123!"
    )
    print(f"Result: {success}, Username: {username}, Message: {msg}\n")
    
    # Test 4: Authenticate with wrong password
    print("Test 4: Authenticating with wrong password...")
    success, username, msg = user_manager.authenticate_user(
        email="test@example.com",
        password="WrongPassword!"
    )
    print(f"Result: {success}, Username: {username}, Message: {msg}\n")
    
    # Test 5: Get user info
    print("Test 5: Getting user info...")
    user_info = user_manager.get_user_info("test@example.com")
    if user_info:
        print(f"User Info: {user_info}\n")
    else:
        print("User not found\n")

if __name__ == "__main__":
    test_user_manager()
