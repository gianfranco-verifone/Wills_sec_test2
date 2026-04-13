# ScanTest1 - Asset & Vulnerability Database Dashboard

A Python web application that provides a graphical interface to manage Qualys asset and vulnerability data with MySQL backend.

## Features

- 📊 **Dashboard** with key metrics (total assets, critical vulnerabilities %, OS distribution)
- ➕ **Add Assets** - Track operating system info, interfaces, scan dates
- 🔍 **Manage Vulnerabilities** - Add, filter, search vulnerabilities by severity/type
- 📈 **Reports** - Critical vuln counts, recent vuln tracking
- ⚡ **Qualys Sync Script** - Automated nightly sync from Qualys Cloud
- 📝 **CSV Export** - Download all data as CSV

## Prerequisites

- Python 3.8+
- MySQL (local or remote)
- Qualys API Key: https://qualys.com/help/qualys-cloud/security-services-and-tools/security-api-using-qualys-api-key-for-integrations

## Installation

### 1. Create a MySQL Database

```bash
# In MySQL
CREATE DATABASE qualys_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'qualys_user'@'localhost' IDENTIFIED BY 'your_secure_password';
GRANT ALL PRIVILEGES ON qualys_db.* TO 'qualys_user'@'localhost';
FLUSH PRIVILEGES;
```

### 2. Install Dependencies

```bash
cd /home/will/code/scantest1
pip install -r requirements.txt
```

### 3. Config Database URL

Edit `app.py` line 57:
```python
DATABASE_URL = 'mysql+pymysql://qualys_user:your_secure_password@localhost:3306/qualys_db'
```

### 4. Configure Qualys API Key

Edit `qualys_sync.py` line 6 or set env var:
```bash
export QUALYS_API_KEY=your-qualys-api-key-here
```

### 5. Run the Application

```bash
cd /home/will/code/scantest1
python app.py
```

Visit: `http://localhost:5000`

## Adding Test Data

### Add Asset (Dashboard → ➕ Add Asset)

Fill in:
- Name: "Web Server 1"
- OS: "Ubuntu 22.04"
- Interface: "Apache HTTP Server"
- IP Address: "192.168.1.50"
- First Scan: 2026-01-15
- Last Scan: 2026-04-01

### Add Vulnerabilities

After adding an asset, click "➕ Add Vulnerability" to add issues.

### Run Daily Sync

1. Dashboard → ⚡ Run Sync
2. Or execute: `python qualys_sync.py`
3. Results auto-populate the database

## Daily Sync Schedule

Add to crontab (crontab -e):
```
0 8 * * * cd /home/will/code/scantest1 && python qualys_sync.py >> ~/qualys_sync.log
```

## Quick Notes

- The app uses SQLAlchemy models (`models.py`)
- Dashboard shows stats, charts, and top critical vulnerabilities
- Use filters to find assets by OS, search by name
- CSV export pulls all data from `app.py`

## Folder Structure

```
/home/will/code/scantest1/
├── app.py              # Flask web app
├── models.py           # Database models
├── qualys_sync.py      # Sync script
├── requirements.txt    # Python deps
├── templates/          # HTML templates
└── static/            # CSS/JS
```

---

Created: 2026-04-10
Last Updated: 2026-04-10
