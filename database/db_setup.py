import sqlite3
import os
from datetime import datetime

DB_PATH = "database/cspm_findings.db"

def create_database():
    print("🗄️ Setting up CSPM Database...")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create S3 findings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS s3_findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            bucket_name TEXT,
            risk_level  TEXT,
            issues      TEXT,
            scan_time   TEXT
        )
    ''')

    # Create EC2 findings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ec2_findings (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT,
            group_id   TEXT,
            risk_level TEXT,
            issues     TEXT,
            scan_time  TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Database created successfully!")
    print(f"📁 Location: {DB_PATH}")

if __name__ == "__main__":
    create_database()