"""
Flask web application for managing Qualys asset and vulnerability data.
Author: Will
Created: 2026-04-10
Run: cd scantest1 && python app.py
"""
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-do-not-use-in-production')

# SQLAlchemy imports
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

# Database configuration - UPDATE THIS FOR YOUR MILY
# Example: MySQL on Docker or local
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///~/scan.db')

# Create database engine and session
engine = create_engine(DATABASE_URL, echo=False)
db_session = scoped_session(sessionmaker(bind=engine))

# Models will be imported after database connection
from models import db, Asset, Vulnerability

# Routes
@app.route('/')
def index():
    """Dashboard with key metrics and statistics."""
    # Get counts
    assets_count = db_session.query(Asset).count()
    critical_high_count = db_session.query(Vulnerability).filter(
        Vulnerability.severity.in_(['critical', 'high'])
    )\
    .join(Asset, Vulnerability.asset_id == Asset.id)\
    .count()
    
    if assets_count > 0:
        critical_percent = (critical_high_count / assets_count) * 100
    else:
        critical_percent = 0
    
    # Get asset by OS distribution
    os_stats = db_session.query(Asset.os).distinct().all()
    os_dict = {}
    for row in os_stats:
        count = db_session.query().filter(Asset.os == row[0]).count()
        os_dict[row[0]] = count
    os_stats = [{'os': k, 'count': v} for k, v in os_dict.items()]
    
    # Get vulnerability statistics
    total_vulns = db_session.query(Vulnerability).count()
    severity_counts = db_session.query(Vulnerability.severity).distinct().all()
    
    # Recent vulnerabilities (last 30 days)
    cutoff = datetime.now() - timedelta(days=30)
    recent_vulns = db_session.query(Vulnerability).filter(
        Vulnerability.detected_date >= cutoff
    ).count()
    
    # Critical assets by critical vuln count
    top_critical = db_session.query(Asset.id, db.session.func.count(Vulnerability.id).label('count'))\
    .join(Vulnerability, Asset.id == Vulnerability.asset_id)\
    .filter(Vulnerability.severity == 'critical')\
    .order_by(db.session.func.count(Vulnerability.id).desc())\
    .limit(10)\
    .all()
    
    top_critical_count = [{'id': i.id, 'asset': None, 'os': None, 
                          'critical_vulns': i.count} for i in top_critical]
    
    # Get vulnerabilities per asset top 5
    top_assets_by_vulns = db_session.query(Asset.id, Vulnerability.name)\
    .join(Vulnerability, Asset.id == Vulnerability.asset_id)\
    .group_by(Asset.id)\
    .having(db.session.func.count(Vulnerability.id) > 0)\
    .limit(5)\
    .all()
    
    return render_template('index.html',
                          assets_count=assets_count,
                          critical_percent=round(critical_percent, 2),
                          total_vulns=total_vulns,
                          recent_vulns=recent_vulns,
                          os_stats=os_stats,
                          top_critical_count=top_critical_count,
                          severity_counts=severity_counts)

@app.route('/add_asset', methods=['GET', 'POST'])
def add_asset():
    """Manage assets."""
    if request.method == 'POST':
        asset_name = request.form.get('name')
        os_type = request.form.get('os')
        interface = request.form.get('interface')
        ip_address = request.form.get('ip_address')
        first_scan_date = request.form.get('first_scan_date')
        last_scan_date = request.form.get('last_scan_date')
        
        asset = Asset(name=asset_name,
                     os=os_type,
                     interface=interface,
                     ip_address=ip_address,
                     first_scan_date=datetime.strptime(first_scan_date, '%Y-%m-%d'),
                     last_scan_date=datetime.strptime(last_scan_date, '%Y-%m-%d'))
        
        db_session.add(asset)
        db_session.commit()
    
    return render_template('add_asset.html')

@app.route('/vulnerability', methods=['GET', 'POST'])
def add_vulnerability():
    """Manage vulnerabilities."""
    if request.method == 'POST':
        asset_id = request.form.get('asset_id')
        vuln_name = request.form.get('vuln_name')
        severity = request.form.get('severity')
        vuln_type = request.form.get('vuln_type')
        vuln_service = request.form.get('vuln_service')
        detected_date = request.form.get('detected_date')
        fixed_date = request.form.get('fixed_date')
        
        vuln = Vulnerability(name=vuln_name,
                            severity=severity,
                            vuln_type=vuln_type,
                            vuln_service=vuln_service,
                            detected_date=datetime.strptime(detected_date, '%Y-%m-%d'),
                            fixed_date=datetime.strptime(fixed_date, '%Y-%m-%d') if fixed_date else None)
        
        asset = db_session.query(Asset).get(asset_id)
        if asset:
            asset.vulnerabilities.append(vuln)
        
        db_session.commit()
    
    return render_template('vulnerability.html')

@app.route('/assets')
def get_assets():
    """List all assets."""
    search = request.args.get('search', '').lower()
    os_filter = request.args.get('os', '').lower()
    
    query = db_session.query(Asset)
    
    if search:
        query = query.filter(Asset.name.ilike(f'%{search}%'))
    if os_filter:
        query = query.filter(Asset.os.ilike(f'%{os_filter}%'))
    
    assets = query.all()
    
    return render_template('assets.html', assets=assets)

@app.route('/asset/<int:asset_id>')
def get_asset(asset_id):
    """Get asset detail with vulnerabilities."""
    asset = db_session.query(Asset).get(asset_id)
    if not asset:
        return redirect(url_for('index'))
    
    vulns = db_session.query(Vulnerability).filter(Vulnerability.asset_id == asset_id).all()
    
    return render_template('asset_detail.html', asset=asset, vulnerabilities=vulns)

@app.route('/vulnerabilities')
def get_vulnerabilities():
    """List all vulnerabilities."""
    search = request.args.get('search', '').lower()
    severity_filter = request.args.get('severity', '').lower()
    
    query = db_session.query(Vulnerability)
    
    if search:
        query = query.filter(Vulnerability.name.ilike(f'%{search}%'))
    if severity_filter:
        query = query.filter(Vulnerability.severity.ilike(f'%{severity_filter}%'))
    
    vulnerabilities = query.all()
    
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities)

@app.route('/health')
def health_check():
    """Health check."""
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    # Check and create database
    from models import db
    if not db.engine:
        print("Creating database engine...")
    else:
        try:
            db.create_all()
        except:
            print("Database may not exist yet. Ensure MySQL connection is correct.")
    
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    host_addr = os.environ.get('FLASK_HOST', '127.0.0.1')
    port_num = int(os.environ.get('FLASK_PORT', 5000))
    
    app.run(debug=debug_mode, host=host_addr, port=port_num)
