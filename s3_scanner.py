import boto3

def scan_s3_buckets():
    s3 = boto3.client('s3')
    buckets = s3.list_buckets()
    
    print("\nScanning S3 Buckets...\n")
    findings = []
    
    for bucket in buckets['Buckets']:
        bucket_name = bucket['Name']
        print(f"Bucket: {bucket_name}")
        
        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            public = False
            
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    public = True
            
            if public:
                print(f"  [HIGH] {bucket_name} is PUBLICLY accessible!")
                findings.append({"Bucket": bucket_name, "Status": "Public", "Risk": "HIGH"})
            else:
                print(f"  [OK] {bucket_name} is Private")
                findings.append({"Bucket": bucket_name, "Status": "Private", "Risk": "LOW"})
                
        except Exception as e:
            print(f"  [ERROR] {bucket_name}: {str(e)}")
    
    return findings

if __name__ == "__main__":
    scan_s3_buckets()