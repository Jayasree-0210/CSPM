import boto3

iam = boto3.client('iam')

users = iam.list_users()['Users']

print("\nIAM MFA Security Check\n")

for user in users:

    username = user['UserName']

    mfa_devices = iam.list_mfa_devices(UserName=username)

    if len(mfa_devices['MFADevices']) == 0:
        print(f"{username} -> MFA NOT Enabled")
    else:
        print(f"{username} -> MFA Enabled")