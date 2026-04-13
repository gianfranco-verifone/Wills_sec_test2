"""
Qualys SaaS Sync Script
Downloads asset and vulnerability data from Qualys Cloud and populates the database.
Usage: python qualys_sync.py [--api-key YOUR_API_KEY] [api-key]
Author: Will
Created: 2026-04-10
"""
import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta
import httpx
import requests
from sqlalchemy import create_engine, text, inspect

# Configure logging
LOG_FILE = os.path.expanduser('~/scan.log')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', 
                    filehandle=open(LOG_FILE, 'a'))

# API Configuration - UPDATE WITH YOUR QUALYS API KEY
# Get API key from https://qualys.com/help/qualys-cloud/security-services-and-tools/security-api-using-qualys-api-key-for-integrations
API_KEY = os.getenv('QUALYS_API_KEY') or 'your-qualys-api-key-here'
API_HOST = 'https://api.qualys.com'
QUALYS_BASE_URL = f'{API_HOST}/v5'

# Database configuration
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL:
    db_engine = create_engine(DATABASE_URL, echo=False)
    db_session = db_engine.connect()
else:
    # Local MySQL example
    import pymysql
    DATABASE_URL = 'mysql+pymysql://user:pass@localhost:3306/qualys_db'
    db_engine = create_engine(DATABASE_URL, echo=False)
    db_session = db_engine.connect()

def log_sync_status(status, message=''):
    """Log sync status with timestamp."""
    timestamp = datetime.now().isoformat()
    log_msg = f"[{timestamp}] {status}"
    print(log_msg)
    logging.info(f"{status} - {message}" if message else log_msg)

def run_qualys_sync():
    """
    Main function to run the Qualys sync process.
    - Get assets from Qualys
    - Get vulnerabilities for each asset
    - Insert/update database
    """
    log_sync_status("Starting Qualys Sync")
    
    try:
        # Step 1: Get all managed systems from Qualys
        log_sync_status("Fetching asset data from Qualys")
        assets_response = httpx.get(f'{QUALYS_BASE_URL}/assets', 
                                    headers={'Authorization': f'Basic {API_KEY}'}
                                    )
        
        if assets_response.status_code != 200:
            log_sync_status("Warning", f"Failed to fetch assets: {assets_response.status_code}")
            print(f"Error: {assets_response.text}")
            return
        
        assets_data = assets_response.json()
        
        # Extract asset list (structure may vary by Qualys API version)
        # Assuming simplified structure - may need adjustment
        assets = assets_data.get('system', []) if isinstance(assets_data, dict) else assets_data
        
        log_sync_status(f"Fetched {len(assets)} assets")
        
        if not assets:
            log_sync_status("No assets found in Qualys")
            return
        
        asset_inserted = []
        asset_ids = {a['id'] for a in assets}
        
        # Step 2: Download vulnerability reports for each asset
        log_sync_status(f"Downloading vulnerability data for {len(assets)} assets")
        
        for asset in assets:
            asset_id = asset.get('id')
            if not asset_id:
                continue
            
            log_sync_status("Fetching vulnerabilities for asset")
            
            # Get vulnerability report for this asset
            vuln_response = httpx.get(f'{QUALYS_BASE_URL}/reports/detail?assetid={asset_id}',
                                     headers={'Authorization': f'Basic {API_KEY}'}
                                     )
            
            if vuln_response.status_code != 200:
                log_sync_status("Warning", f"Failed to fetch vulns for asset {asset_id}")
                continue
            
            try:
                vulns_data = vuln_response.json()
            
                # Parse vulnerability data
                # Structure varies - here's a basic implementation
                vulns = vuln_data.get('result', {}).get('vuln', []) if isinstance(vulns_data, dict) else []
                
                for vuln in vulns:
                    try:
                        # Extract vulnerability fields (structure may vary)
                        # This is simplified - you may need to adjust based on actual Qualys response
                        vuln_name = vuln.get('name') or vuln.get('title')
                        severity = vuln.get('severity') or vuln.get('severityCode')
                        vuln_type = vuln.get('type') or vuln.get('typeText')
                        vuln_service = vuln.get('service') or vuln.get('serviceName')
                        detected_date = vuln.get('vulndate')
                        detected_timestamp = detected_date.split('T')[0] if detected_date else None
                        
                        # Insert into database
                        vuln_model = db_session.execute(text("""
                            INSERT INTO vulnerabilities (name, severity, vuln_type, vuln_service, detected_date, asset_ref) 
                            VALUES (:name, :severity, :vuln_type, :vuln_service, :detected_date, :asset_id)
                            ON DUPLICATE KEY UPDATE name=:name, severity=:severity, detected_date=:detected_date
                        """), {
                            'name': vuln_name,
                            'severity': severity,
                            'vuln_type': vuln_type,
                            'vuln_service': vuln_service,
                            'detected_date': detected_timestamp,
                            'asset_id': asset_id
                        })
                        
                    except Exception as e:
                        log_sync_status("Warning", f"Error processing vuln: {e}")
                
                # Update asset's last scan date if needed
                asset['lastscan']
                # Extract scan data
                scan_date = asset.get('lastscan', datetime.now())
                
            except Exception as e:
                log_sync_status("Warning", f"Error processing asset {asset_id}: {e}")
            
            log_sync_status(f"Processed {len(vulns_data)} vulnerabilities for asset {asset_id}",
                           f"{len(vulns) or 'vulnerabilities' if 'len' in dir() else 'vulnerabilities'}")
            
            # Rate limiting - wait between assets
            time.sleep(1)
        
        log_sync_status("Qualys Sync completed successfully")
        
    except Exception as e:
        log_sync_status("Error", f"Exception during sync: {e}")
        raise

def main():
    """Entry point for qualys_sync.py"""
    if __name__ == "__main__":
        run_qualys_sync()

if __name__ == "__main__":
    main()
