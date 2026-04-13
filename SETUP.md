# ScanTest1 - Setup Instructions

## Quick Start (requires MySQL)

1. **Install MySQL Database**:
   ```bash
   # Ubuntu/Debian
   sudo apt install mysql-server -y
   
   # Check MySQL is running
   service mysql status
   
   # Create database and user
   mysql -u root -p
   CREATE DATABASE qualys_data CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'scanuser'@'localhost' IDENTIFIED BY 'scantest123';
   GRANT ALL PRIVILEGES ON qualys_data.* TO 'scanuser'@'localhost';
   FLUSH PRIVILEGES;
   EXIT;
   
   # Verify tables exist (run db_setup.py)
   ```

2. **Install Dependencies**:
   ```bash
   cd /home/will/code/scantest1
   pip3 install --break-system-packages Flask==3.0.0 SQLAlchemy==2.0.23 pymysql==1.1.0
   ```

3. **Configure Database Connection**:
   Edit `app.py` line 48:
   ```python
   DATABASE_URL = 'mysql+pymysql://scanuser:scantest123@localhost:3306/qualys_data'
   ```

4. **Create Database Tables**:
   ```bash
   cd /home/will/code/scantest1
   pip3 install --break-system-packages pymysql 2>/dev/null
   python3 db_setup.py
   ```

5. **Run the Application**:
   ```bash
   cd /home/will/code/scantest1
   python3 app.py
   ```
   
   Visit: http://localhost:5000

## Alternative: Use SQLite for Testing

If MySQL isn't available, temporarily use SQLite:

1. **Change database configuration in app.py**:
   ```python
   DATABASE_URL = 'sqlite:///~/scan.db'
   ```

2. **Run application**:
   ```bash
   cd /home/will/code/scantest1
   python3 app.py
   ```

3. **Access at http://localhost:5000**

## Daily Sync with Qualys

1. Set Qualys API key:
   ```bash
   export QUALYS_API_KEY=your-api-key-here
   ```

2. Run sync nightly:
   ```bash
   # Edit crontab (crontab -e)
   # Run this entry
   0 8 * * * cd /home/will/code/scantest1 && python3 qualys_sync.py >> ~/qualys_sync.log 2>&1
   ```

3. Run manually:
   ```bash
   cd /home/will/code/scantest1
   python3 qualys_sync.py
   ```

## Database Structure

**assets table:**
- id, name, os, interface, ip_address, first_scan_date, last_scan_date

**vulnerabilities table:**
- id, name, severity, vuln_type, vuln_service, detected_date, fixed_date, asset_ref (FK to assets.id)

## Quick CLI Commands

```bash
# View all assets
http://localhost:5000/assets

# View vulnerabilities
http://localhost:5000/vulnerabilities

# View dashboard with stats
http://localhost:5000/

# Export all data to CSV
http://localhost:5000/export_csv

# Run Qualys sync
http://localhost:5000/qualys_sync
```

## Next Steps

1. Add test assets via the dashboard
2. Add sample vulnerabilities
3. Configure your Qualys API key
4. Set up nightly sync (cron)
5. Monitor the dashboard for critical vulnerabilities

Created: 2026-04-10
