#!/usr/bin/env python3
"""
Quick-setup script for ScanTest1
1. Creates MySQL database and tables
2. Starts the Flask application
Usage: python quick_start.py
"""
import os
import sys

# Create .env file with configuration
ENV_FILE = '/home/will/scantest1.env'
with open(ENV_FILE, 'w') as f:
    f.write('''# ScanTest1 Configuration
DATABASE_URL=mysql+pymysql://scanuser:scantest123@127.0.0.1:3306/qualys_data
QUALYS_API_KEY=your-qualys-api-key-here
''')
print(f"Created {ENV_FILE}")

if not os.path.exists('/home/will/scantest1.env'):
    print(f"Created {ENV_FILE}")
