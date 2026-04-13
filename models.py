"""
Database models for Qualys asset and vulnerability data tracking.
Author: Will
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
import os

# Create SQLAlchemy base
Base = declarative_base()

# Database initialization - MySQL (UPDATE THIS)
DATABASE_URL = os.getenv('DATABASE_URL', 'mysql+pymysql://user:pass@localhost:3306/qualys_db')
# SQLite alternative: DATABASE_URL = 'sqlite:///~/scan.db'

engine = create_engine(DATABASE_URL, echo=False)
db_session = scoped_session(sessionmaker(bind=engine))
db = engine

class Asset(Base):
    """Asset model representing a network device or resource."""
    __tablename__ = 'assets'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    os = Column(String(100), nullable=False)
    interface = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=False)
    first_scan_date = Column(DateTime, nullable=False)
    last_scan_date = Column(DateTime, nullable=False)
    
    # Relationship to vulnerabilities
    vulnerabilities = relationship('Vulnerability', backref='asset', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Asset {self.name} ({self.os})>'

class Vulnerability(Base):
    """Vulnerability model representing a security issue."""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    severity = Column(String(50), nullable=False)  # critical, high, medium, low
    vuln_type = Column(String(100), nullable=False)
    vuln_service = Column(String(100))  # e.g., HTTP-80, SSH-22
    
    detected_date = Column(DateTime, nullable=False)
    fixed_date = Column(DateTime)  # Can be null if not fixed
    
    # Relationship to asset
    asset_id = Column(Integer, nullable=False)
    
    from sqlalchemy.orm import foreign
    # This needs to work with foreign key constraint
    # For now using a workaround
    asset_ref = Column(Integer, nullable=False)
    
    def __repr__(self):
        return f'<Vulnerability {self.name} [{self.severity}]>'

class QualysData(Base):
    """Optional: Direct Qualys API result storage (future enhancement)"""
    __tablename__ = 'qualys_results'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_date = Column(DateTime, nullable=False)
    asset_id = Column(Integer, nullable=True)  # Cross-reference to Asset table
    asset_name = Column(String(255))
    vuln_name = Column(String(200), nullable=False)
    severity = Column(String(50), nullable=False)
    vuln_service = Column(String(100))
    host = Column(String(100))  # For service-based vulns
    cve_id = Column(String(50))
    cvss_score = Column(Integer)
