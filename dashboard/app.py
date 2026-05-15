import streamlit as st
import boto3
import pandas as pd

st.set_page_config(page_title="Enterprise CSPM", layout="wide")
st.title("☁️ Enterprise Cloud Security Posture Management")
st.markdown("Real-Time AWS Cloud Security Monitoring")
st.divider()

# ─── S3 SCANNER ───
s3 = boto3.client('s3')
buckets = s3.list_buckets()['Buckets']
total_buckets = len(buckets)
critical_alerts = 0
s3_findings = []

for bucket in buckets:
    bucket_name = bucket['Name']
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        public = False
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                public = True
        if public:
            critical_alerts += 1
            s3_findings.append({"Bucket": bucket_name, "Status": "PUBLIC", "Risk Level": "HIGH"})
        else:
            s3_findings.append({"Bucket": bucket_name, "Status": "Private", "Risk Level": "LOW"})
    except Exception as e:
        s3_findings.append({"Bucket": bucket_name, "Status": "Error", "Risk Level": str(e)})

# ─── EC2 SCANNER ───
ec2 = boto3.client('ec2', region_name='ap-south-1')
response = ec2.describe_security_groups()
ec2_findings = []

for sg in response['SecurityGroups']:
    group_name = sg['GroupName']
    for rule in sg.get('IpPermissions', []):
        from_port = rule.get('FromPort', 0)
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            if cidr in ('0.0.0.0/0', '::/0'):
                ec2_findings.append({
                    "Security Group": group_name,
                    "Open Port": from_port,
                    "CIDR": cidr,
                    "Risk Level": "HIGH"
                })

if not ec2_findings:
    ec2_findings.append({"Security Group": "No issues found", "Open Port": "-", "CIDR": "-", "Risk Level": "LOW"})

# ─── IAM SCANNER ───
iam = boto3.client('iam')
users = iam.list_users()['Users']
iam_findings = []

for user in users:
    username = user['UserName']
    mfa = iam.list_mfa_devices(UserName=username)
    if len(mfa['MFADevices']) == 0:
        iam_findings.append({"Username": username, "MFA Status": "NOT Enabled", "Risk Level": "HIGH"})
    else:
        iam_findings.append({"Username": username, "MFA Status": "Enabled", "Risk Level": "LOW"})

# ─── METRICS ───
high_risks = sum(1 for f in s3_findings if f['Risk Level'] == 'HIGH') + \
             sum(1 for f in ec2_findings if f['Risk Level'] == 'HIGH') + \
             sum(1 for f in iam_findings if f['Risk Level'] == 'HIGH')

col1, col2, col3, col4 = st.columns(4)
col1.metric("S3 Buckets", total_buckets)
col2.metric("EC2 Security Groups", len(response['SecurityGroups']))
col3.metric("IAM Users", len(users))
col4.metric("High Risk Alerts", high_risks)

st.divider()

# ─── SCAN SUMMARY TABLE ───
st.subheader("📊 AWS Security Scan Summary")
summary = pd.DataFrame([
    {"Service": "EC2 Security Groups", "Status": "Scanned", "Risk Level": "HIGH" if any(f['Risk Level']=='HIGH' for f in ec2_findings) else "LOW"},
    {"Service": "S3 Buckets", "Status": "Scanned", "Risk Level": "HIGH" if any(f['Risk Level']=='HIGH' for f in s3_findings) else "LOW"},
    {"Service": "IAM Users", "Status": "Scanned", "Risk Level": "HIGH" if any(f['Risk Level']=='HIGH' for f in iam_findings) else "MEDIUM"},
])
st.dataframe(summary, use_container_width=True)

st.divider()

# ─── S3 FINDINGS ───
st.subheader("🪣 S3 Security Findings")
st.dataframe(pd.DataFrame(s3_findings), use_container_width=True)

st.divider()

# ─── EC2 FINDINGS ───
st.subheader("🖥️ EC2 Security Group Findings")
st.dataframe(pd.DataFrame(ec2_findings), use_container_width=True)

st.divider()

# ─── IAM FINDINGS ───
st.subheader("👤 IAM User Findings")
st.dataframe(pd.DataFrame(iam_findings), use_container_width=True)

st.divider()
st.success("✅ CSPM Scan Completed Successfully")