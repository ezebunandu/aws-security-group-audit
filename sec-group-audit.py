import boto3


def list_accounts():
    """List the security groups in the AWS org"""
    # Initialize the boto3 client for AWS Organizations
    org_client = boto3.client("organizations")

    # Pagination is used as there can be more accounts than the default limit
    paginator = org_client.get_paginator("list_accounts")

    # List to store all accounts
    all_accounts = []

    for page in paginator.paginate():
        # Extracting account details from each page
        accounts = page["Accounts"]

        # Appending accounts to the list
        all_accounts.extend(accounts)

    return all_accounts


def list_active_regions():
    """List the active regions in an account using the ec2 client"""
    ec2_client = boto3.client("ec2")
    region_list = []

    for region in ec2_client.describe_regions()["Regions"]:
        region_name = str(region["RegionName"])
        opt_in_status = str(region["OptInStatus"])

        if opt_in_status == "not-opted-in":
            pass
        region_list.append(region_name)
    return region_list


def has_ipv4_open_ssh_or_rdp(security_group_rule):
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ip4_range in rule.get("IpRanges"):
                return ip4_range.get("CidrIp") in ["0.0.0.0/0"]


def has_ipv6_open_ssh_or_rdp(security_group_rule):
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ipv6_range in rule.get("Ipv6Ranges"):
                return ipv6_range.get("CidrIpv6") in ["::/0"]


def list_security_groups(account_id):
    pass


def main():
    # Listing all accounts in the AWS Organization
    accounts = list_accounts()

    # Dictionary to store account IDs and their corresponding open security groups
    open_security_groups_by_account = {}

    # Iterate through each account
    for account in accounts:
        account_id = account["Id"]
        print(f"Enumerating security groups in {account_id}")
        print("--------------------------------------------------------------")
        open_security_groups = list_security_groups(account_id)
        if open_security_groups:
            print("Found open security group rules allowing ssh or rdp access")
            open_security_groups_by_account[account_id] = open_security_groups

    # Print the results
    for account_id, open_security_groups in open_security_groups_by_account.items():
        print(
            f"Account Id: {account_id}, Name: {account['Name']}, Email: {account['Email']}, Status: {account['Status']}"
        )
        for sg in open_security_groups:
            print(
                f"\tSecurity Group Id: {sg['GroupId']}, Name: {sg['GroupName']}, Description: {sg['Description']}"
            )


if __name__ == "__main__":
    main()
