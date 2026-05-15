Cloud Security Posture Management (CSPM) Tool

Overview
This project is a Python-based Cloud Security Posture Management (CSPM) tool that scans AWS resources for common security misconfigurations such as IAM privilege risks and publicly exposed S3 buckets.

It helps identify security vulnerabilities in cloud infrastructure and improves overall cloud security posture.


Features
- IAM policy risk detection (over-permission analysis)
- S3 bucket public access scanning
- Modular scanner architecture
- Centralized main execution file
- Database integration for storing scan results
- Simple dashboard for viewing findings

---

Project Structure

```
enterprise-cspm/
├── scanners/
│   ├── ec2_scanner.py
│   ├── iam_scanner.py
│   └── s3_scanner.py
├── dashboard/
├── reports/
├── remediation/
├── utils/
├── tests/
│   └── test_aws.py
├── main.py
├── .gitignore
└── README.md
```

---

Tech Stack
- Python
- AWS (IAM, S3)
- Boto3
- SQLite / Database
- Streamlit (Dashboard)

---

How to Run 
Install dependencies
```bash
pip install -r requirements.txt
```

Configure AWS credentials
```bash
aws configure
```

Run all scanners
```bash
python main.py
```

View the dashboard
```bash
streamlit run dashboard/app.py
```
