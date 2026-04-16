"""
Database models for Qualys asset and vulnerability data tracking.
Author: Will
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Create SQLAlchemy base
Base = declarative_base()

# Database initialization - MySQL (UPDATE THIS)
DATABASE_URL = os.getenv('DATABASE_URL', 'mysql+pymysql://user:pass@localhost:3306/qualys_db')
# SQLite alternative: DATABASE_URL = 'sqlite:///~/scan.db'

engine = create_engine(DATABASE_URL, echo=False)
db_session = scoped_session(sessionmaker(bind=engine))
db = engine

class User(Base):
    """User model for authentication."""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(80), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    email = Column(String(120), unique=True, nullable=True)
    active = Column(Integer, default=1)
    role = Column(String(50), default='user')
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def get_id(self):
        return str(self.id)
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return self.active == 1
    
    def is_anonymous(self):
        return False
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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
    created_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    
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
    asset_id = Column(Integer, nullable=False)  # Maps to Asset.id
    created_by = Column(Integer, ForeignKey('users.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    
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
