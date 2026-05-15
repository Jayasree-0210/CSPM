import boto3

s3 = boto3.client('s3')

buckets = s3.list_buckets()

print("\nScanning S3 Buckets...\n")

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
            print("Status: PUBLIC BUCKET")
        else:
            print("Status: Private")

    except Exception as e:
        print("Error:", e)

    print("-" * 40)