import boto3

def scan_security_groups():
    print("EC2 Security Group Scan")
    print("=" * 40)

    ec2 = boto3.client('ec2', region_name='ap-southeast-2')  # Sydney region
    response = ec2.describe_security_groups()

    findings = []

    for sg in response['SecurityGroups']:
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']

        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)
            protocol = rule.get('IpProtocol', 'all')

            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                if cidr in ('0.0.0.0/0', '::/0'):
                    findings.append({
                        'sg_id': sg_id,
                        'sg_name': sg_name,
                        'port': f"{from_port}-{to_port}",
                        'protocol': protocol,
                        'cidr': cidr,
                        'severity': 'CRITICAL' if from_port == 22 else 'HIGH'
                    })

    if findings:
        print(f"\n[!] {len(findings)} finding(s) detected:\n")
        for f in findings:
            print(f"  [{f['severity']}] {f['sg_id']} ({f['sg_name']})")
            print(f"         Port: {f['port']} | Protocol: {f['protocol']} | Open to: {f['cidr']}\n")
    else:
        print("\n[OK] No open security group issues found.")

if __name__ == "__main__":
    scan_security_groups()