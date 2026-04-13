#!/usr/bin/env python3
"""
Setup script for ScanTest1 database
Creates necessary tables, users, and grants permissions
Usage: python db_setup.py [config_file]
"""
import os
import sys
import pymysql

# Database configuration
DB_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'port': int(os.getenv('MYSQL_PORT', '3306')),
    'user': os.getenv('MYSQL_USER', 'qualys_user'),
    'password': os.getenv('MYSQL_PASSWORD', 'scan_password'),
    'database': os.getenv('MYSQL_DATABASE', 'qualys_db'),
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci'
}

def create_connections():
    """
    Create connection objects
    Returns a dict of connection objects
    """
    return pymysql.connect(**DB_CONFIG)

def create_tables():
    """
    Create necessary tables
    """
    tables = [
        '''
        CREATE TABLE IF NOT EXISTS assets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            os VARCHAR(100) NOT NULL,
            interface VARCHAR(100) NOT NULL,
            ip_address VARCHAR(50) NOT NULL,
            first_scan_date DATETIME NOT NULL,
            last_scan_date DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        '''
    ]

    tables.append('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(200) NOT NULL,
            severity VARCHAR(50) NOT NULL,
            vuln_type VARCHAR(100) NOT NULL,
            vuln_service VARCHAR(100),
            detected_date DATETIME NOT NULL,
            fixed_date DATETIME,
            asset_ref INT NOT NULL,
            FOREIGN KEY (asset_ref) REFERENCES assets(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        '''
    )

    tables.append('''
        CREATE TABLE IF NOT EXISTS qualys_results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_date DATETIME NOT NULL,
            asset_id INT,
            asset_name VARCHAR(255),
            vuln_name VARCHAR(200) NOT NULL,
            severity VARCHAR(50) NOT NULL,
            vuln_service VARCHAR(100),
            host VARCHAR(100),
            cve_id VARCHAR(50),
            cvss_score INT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        '''
    )

conn = create_connections()
conn.execute('SET FOREIGN_KEY_CHECKS=0')
for table in tables:
    conn.execute(table)
conn.execute('SET FOREIGN_KEY_CHECKS=1')
conn.close()

print("Tables created successfully")
