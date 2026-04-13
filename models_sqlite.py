"""
ScanTest1 - Database Models (SQLite mode)
"""
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker

import os

# SQLite database file path
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL and 'mysql' in DATABASE_URL:
    # MySQL configuration
    from sqlalchemy import create_engine
    engine = create_engine(DATABASE_URL, echo=False)
else:
    # SQLite fallback
    DATABASE_URL = 'sqlite:///~/scan.db'
    engine = create_engine(DATABASE_URL, echo=False)

db_session = sessionmaker(bind=engine)
db = engine

# Base class for models
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

class Asset(Base):
    """SQLite version of the Asset model"""
    __tablename__ = 'assets'
    
    id = __table__.c.id
    name = __table__.c.name
    os = __table__.c.os
    interface = __table__.c.interface
    ip_address = __table__.c.ip_address
    first_scan_date = __table__.c.first_scan_date
    last_scan_date = __table__.c.last_scan_date

class Vulnerability(Base):
    """SQLite version of the Vulnerability model"""
    __tablename__ = 'vulnerabilities'
    
    id = __table__.c.id
    name = __table__.c.name
    severity = __table__.c.severity
    vuln_type = __table__.c.vuln_type
    vuln_service = __table__.c.vuln_service
    detected_date = __table__.c.detected_date
    fixed_date = __table__.c.fixed_date

# Create tables if not exists
with engine.connect() as conn:
    conn.execute(text("CREATE TABLE IF NOT EXISTS assets (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(255) NOT NULL, os VARCHAR(100) NOT NULL, interface VARCHAR(100) NOT NULL, ip_address VARCHAR(50) NOT NULL, first_scan_date DATETIME NOT NULL, last_scan_date DATETIME NOT NULL);"))
    conn.execute(text("CREATE TABLE IF NOT EXISTS vulnerabilities (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(200) NOT NULL, severity VARCHAR(50) NOT NULL, vuln_type VARCHAR(100) NOT NULL, vuln_service VARCHAR(100), detected_date DATETIME NOT NULL, fixed_date DATETIME);"))
    conn.commit()

print("Database tables created successfully (SQLite)")
print(f"Database URL: {DATABASE_URL}")
