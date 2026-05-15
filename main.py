from scanner.s3_scanner  import scan_s3_buckets
from scanner.ec2_scanner import scan_security_groups
from database.db_setup   import create_database
import sqlite3
import json

DB_PATH = "database/cspm_findings.db"

def save_findings(s3_findings, ec2_findings):
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Save S3 findings
    for f in s3_findings:
        cursor.execute('''
            INSERT INTO s3_findings
            (bucket_name, risk_level, issues, scan_time)
            VALUES (?, ?, ?, ?)
        ''', (
            f['bucket_name'],
            f['risk_level'],
            json.dumps(f['issues']),
            f['scan_time']
        ))

    # Save EC2 findings
    for f in ec2_findings:
        cursor.execute('''
            INSERT INTO ec2_findings
            (group_name, group_id, risk_level, issues, scan_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            f['group_name'],
            f['group_id'],
            f['risk_level'],
            json.dumps(f['issues']),
            f['scan_time']
        ))

    conn.commit()
    conn.close()
    print("\n✅ All findings saved to database!")

def main():
    print("\n" + "="*50)
    print("🛡️  ENTERPRISE CSPM TOOL")
    print("    Cloud Security Posture Management")
    print("="*50)

    # Setup database
    create_database()

    # Run scanners
    s3_findings  = scan_s3_buckets()
    ec2_findings = scan_security_groups()

    # Save to database
    save_findings(s3_findings, ec2_findings)

    print("\n✅ CSPM Scan Complete!")
    print("="*50)

if __name__ == "__main__":
    main() 
