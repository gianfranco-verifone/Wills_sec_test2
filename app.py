"""
Flask web application for managing Qualys asset and vulnerability data.
SECURE VERSION
Author: Will
Created: 2026-04-10
Run: cd scantest1 && python app.py
"""
import os
import re
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify, abort, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import secrets

app = Flask(__name__)

# === CRITICAL FIX: Secure Secret Key ===
# Do not use hardcoded fallback - fail fast if not set
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable must be set. Example: export FLASK_SECRET_KEY='$(openssl rand -hex 32)'")

# SQLAlchemy imports
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///scan.db')  # Fixed path

# Create database engine and session with error handling
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
db_session = scoped_session(sessionmaker(bind=engine))

# Models
from models import Base, User, Asset, Vulnerability

# Helper: Initialize database safely
def init_db():
    try:
        Base.metadata.create_all(engine)
        # Create default admin user if none exists
        if not db_session.query(User).filter_by(username='admin').first():
            admin = User(username='admin', role='admin')
            #admin.set_password('admin')  # CHANGE THIS IN PRODUCTION!
            if django.contrib.auth.password_validation.validate_password('admin',user=admin): 
                admin.set_password('admin')
            db_session.add(admin)
            db_session.commit()
    except Exception as e:
        print(f"Database initialization error: {e}")

# === CRITICAL FIX: Input Validation Functions ===
def validate_ip_address(ip):
    """Validate IP address format."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        raise ValueError("Invalid IP format")
    octets = ip.split('.')
    for octet in octets:
        if not 0 <= int(octet) <= 255:
            raise ValueError("Invalid IP octet")
    return True

def validate_date_string(date_str):
    """Validate date string in YYYY-MM-DD format."""
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        raise ValueError("Invalid date format. Use YYYY-MM-DD")

def sanitize_input(input_str, max_length=255):
    """Sanitize and limit input length."""
    if not input_str:
        return ''
    # Remove dangerous characters but keep basic text
    sanitized = re.sub(r'[<>\"\';`]', '', str(input_str))
    return sanitized[:max_length].strip()

# === CRITICAL FIX: Authentication Decorator ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        user = db_session.query(User).get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# === CRITICAL FIX: Secure Routes ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login endpoint."""
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'), 80)
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password required', 'danger')
            return render_template('login.html')
        
        user = db_session.query(User).filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f'Welcome back, {username}!', 'success')
            
            # Update last login
            user.last_login = datetime.utcnow()
            db_session.commit()
            
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout endpoint."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# === CRITICAL FIX: Main Routes with Auth ===
@app.route('/')
@login_required
def index():
    """Dashboard with key metrics and statistics."""
    # Use parameterized queries
    assets_count = db_session.query(Asset).count()
    
    # Fixed SQL injection vulnerability
    critical_high_count = db_session.query(Vulnerability).filter(
        Vulnerability.severity.in_(['critical', 'high'])
    ).count()
    
    critical_percent = (critical_high_count / assets_count * 100) if assets_count > 0 else 0
    
    # Safe query using parameterized session
    os_stats = []
    try:
        result = db_session.execute(
            text("SELECT os, COUNT(*) as count FROM assets GROUP BY os")
        )
        os_stats = [{'os': row[0], 'count': row[1]} for row in result]
    except Exception as e:
        print(f"Query error: {e}")
    
    return render_template('index.html',
                          assets_count=assets_count,
                          critical_percent=round(critical_percent, 2),
                          os_stats=os_stats)

# === CRITICAL FIX: Secure Add Asset ===
@app.route('/add_asset', methods=['GET', 'POST'])
@login_required
def add_asset():
    """Manage assets with validation."""
    if request.method == 'POST':
        errors = []
        
        # Sanitize all inputs
        name = sanitize_input(request.form.get('name'))
        os_type = sanitize_input(request.form.get('os'))
        interface = sanitize_input(request.form.get('interface'))
        ip_address = request.form.get('ip_address')
        first_scan_date = request.form.get('first_scan_date')
        last_scan_date = request.form.get('last_scan_date')
        
        # Validate
        if not name:
            errors.append('Asset name is required')
        
        if not os_type:
            errors.append('OS type is required')
        
        try:
            validate_ip_address(ip_address)
        except ValueError as e:
            errors.append(str(e))
        
        try:
            validate_date_string(first_scan_date)
            validate_date_string(last_scan_date)
        except ValueError as e:
            errors.append(str(e))
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('add_asset.html')
        
        try:
            asset = Asset(
                name=name,
                os=os_type,
                interface=interface,
                ip_address=ip_address,
                first_scan_date=datetime.strptime(first_scan_date, '%Y-%m-%d'),
                last_scan_date=datetime.strptime(last_scan_date, '%Y-%m-%d'),
                created_by=session['user_id']
            )
            
            db_session.add(asset)
            db_session.commit()
            flash(f'Asset {name} added successfully!', 'success')
            return redirect(url_for('get_assets'))
        except Exception as e:
            db_session.rollback()
            flash(f'Error adding asset: {str(e)}', 'danger')
    
    return render_template('add_asset.html')

# === CRITICAL FIX: Secure Add Vulnerability ===
@app.route('/vulnerability', methods=['GET', 'POST'])
@login_required
def add_vulnerability():
    """Manage vulnerabilities with validation."""
    if request.method == 'POST':
        errors = []
        
        asset_id = request.form.get('asset_id')
        vuln_name = sanitize_input(request.form.get('vuln_name'))
        severity = sanitize_input(request.form.get('severity'))
        vuln_type = sanitize_input(request.form.get('vuln_type'))
        vuln_service = sanitize_input(request.form.get('vuln_service'))
        detected_date = request.form.get('detected_date')
        fixed_date = request.form.get('fixed_date')
        
        # Validation
        if not asset_id or not asset_id.isdigit():
            errors.append('Valid asset ID required')
        
        if not vuln_name:
            errors.append('Vulnerability name required')
        
        if severity not in ['critical', 'high', 'medium', 'low']:
            errors.append('Valid severity required')
        
        try:
            validate_date_string(detected_date)
            if fixed_date:
                validate_date_string(fixed_date)
        except ValueError as e:
            errors.append(str(e))
        
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('vulnerability.html')
        
        try:
            vuln = Vulnerability(
                name=vuln_name,
                severity=severity,
                vuln_type=vuln_type,
                vuln_service=vuln_service,
                detected_date=datetime.strptime(detected_date, '%Y-%m-%d'),
                fixed_date=datetime.strptime(fixed_date, '%Y-%m-%d') if fixed_date else None,
                asset_id=int(asset_id),
                created_by=session['user_id']
            )
            
            db_session.add(vuln)
            db_session.commit()
            flash(f'Vulnerability {vuln_name} added successfully!', 'success')
            return redirect(url_for('get_vulnerabilities'))
        except Exception as e:
            db_session.rollback()
            flash(f'Error adding vulnerability: {str(e)}', 'danger')
    
    return render_template('vulnerability.html')

# === CRITICAL FIX: Secure Listing Routes ===
@app.route('/assets')
@login_required
def get_assets():
    """List all assets with SQL injection protection."""
    search = sanitize_input(request.args.get('search', ''))
    os_filter = sanitize_input(request.args.get('os', ''))
    
    query = db_session.query(Asset)
    
    if search:
        query = query.filter(Asset.name.like('%' + search + '%'))  # Safe with SQLAlchemy
    if os_filter:
        query = query.filter(Asset.os.like('%' + os_filter + '%'))
    
    assets = query.all()
    
    return render_template('assets.html', assets=assets)

@app.route('/asset/<int:asset_id>')
@login_required
def get_asset(asset_id):
    """Get asset detail with parameterized query."""
    try:
        # SQLAlchemy handles parameter
        asset = db_session.query(Asset).get(asset_id)
        if not asset:
            flash('Asset not found', 'warning')
            return redirect(url_for('get_assets'))
        
        # Safe query with explicit parameter
        vulns = db_session.query(Vulnerability).filter(Vulnerability.asset_id == asset_id).all()
        
        return render_template('asset_detail.html', asset=asset, vulnerabilities=vulns)
    except Exception as e:
        flash(f'Error loading asset: {str(e)}', 'danger')
        return redirect(url_for('get_assets'))

@app.route('/vulnerabilities')
@login_required
def get_vulnerabilities():
    """List all vulnerabilities securely."""
    search = sanitize_input(request.args.get('search', ''))
    severity_filter = sanitize_input(request.args.get('severity', ''))
    
    query = db_session.query(Vulnerability)
    
    if search:
        query = query.filter(Vulnerability.name.like('%' + search + '%'))
    if severity_filter and severity_filter in ['critical', 'high', 'medium', 'low']:
        query = query.filter(Vulnerability.severity == severity_filter)
    
    vulnerabilities = query.all()
    
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities)

# === CRITICAL FIX: Health Check ===
@app.route('/health')
def health_check():
    """Health check without sensitive data."""
    status = 'healthy'
    try:
        db_session.execute(text("SELECT 1"))
    except Exception as e:
        status = 'unhealthy'
    
    return jsonify({
        'status': status,
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0'
    })

# === CRITICAL FIX: Production Configuration ===
if __name__ == '__main__':
    print("Initializing database...")
    init_db()
    
    # DISABLE DEBUG IN PRODUCTION
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    host_addr = os.environ.get('FLASK_HOST', '127.0.0.1')
    port_num = int(os.environ.get('FLASK_PORT', 5000))
    
    # Production warning
    if debug_mode:
        print("=== WARNING ===")
        print("DEBUG MODE IS ENABLED - DISABLE IN PRODUCTION!")
        print("Set FLASK_DEBUG=false")
        print("==============")
    
    print(f"Starting server on {host_addr}:{port_num}")
    app.run(debug=debug_mode, host=host_addr, port=port_num)
