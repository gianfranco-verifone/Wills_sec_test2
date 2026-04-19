#!/usr/bin/env python3
"""
Example application with security issues for Semgrep testing.
"""

import os
import sqlite3

# Hardcoded credentials (Semgrep will flag this)
DB_PASSWORD = "SuperSecret123!"

# Database connection string
DB_URL = f"postgresql://admin:{DB_PASSWORD}@localhost/db"

def login_user(username, password):
    """Simulate user login with SQL injection vulnerability."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    
    # UNSAFE: SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()

def get_api_key():
    """Return a hardcoded API key."""
    api_key = "sk_live_1234567890abcdef"
    return api_key

def unsafe_eval():
    """Example of unsafe code execution."""
    user_input = input("Enter expression: ")
    result = eval(user_input)  # DANGEROUS!
    return result

def read_config():
    """Read config from local file."""
    with open("/tmp/config.json", "r") as f:
        config = f.read()
    return config

if __name__ == "__main__":
    print("Application starting...")
    
    # Show hardcoded values
    print(f"Database password: {DB_PASSWORD}")
    print(f"API key: {get_api_key()}")
    
    # Try login
    user = login_user("admin", "password123")
    if user:
        print(f"Logged in as: {user[0]}")
