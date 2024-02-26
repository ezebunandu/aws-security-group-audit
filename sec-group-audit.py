import boto3
import boto3.session
import botocore

# make this into an input to the cli wrapper (arg parse)
CROSS_ACCOUNT_ACCESS_ROLE_NAME = "OrganizationAccountAccessRole"

# make this into an optional cli input
# the name of the master account in the test env is "securing-the-cloud"
MASTER_ACCOUNT_NAME = "securing-the-cloud"


def get_active_accounts(org_client):
    """get all the active accounts in an aws org
    returns list of {"account_name": account_name, "account_id": account_id}"""

    # Pagination is used as there can be more accounts than the default limit
    paginator = org_client.get_paginator("list_accounts")

    # List to store all accounts
    all_active_accounts = []

    for page in paginator.paginate():
        # Extracting account details from each page
        accounts = page["Accounts"]
        for account in accounts:
            account_id, account_status, account_name = (
                account["Id"],
                account["Status"],
                account["Name"],
            )
            # only add active accounts to the list
            if account_status == "ACTIVE":
                all_active_accounts.append(
                    {"account_name": account_name, "account_id": account_id}
                )
    return all_active_accounts


def list_active_regions(ec2_client):
    """List the active regions in an account using the ec2 client"""
    region_list = []

    for region in ec2_client.describe_regions()["Regions"]:
        region_name = str(region["RegionName"])
        opt_in_status = str(region["OptInStatus"])

        if opt_in_status == "not-opted-in":
            pass
        region_list.append(region_name)
    return region_list


def has_ipv4_open_ssh_or_rdp(security_group_rule):
    """returns true if the security group rule allows open ssh or rdp from 0.0.0.0/0"""
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ip4_range in rule.get("IpRanges"):
                return ip4_range.get("CidrIp") in ["0.0.0.0/0"]


def has_ipv6_open_ssh_or_rdp(security_group_rule):
    """returns true if the security group rule allows open ssh or rdp from ::/0"""
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ipv6_range in rule.get("Ipv6Ranges"):
                return ipv6_range.get("CidrIpv6") in ["::/0"]


def get_network_acls_with_open_ssh_or_rdp_all_regions(role_session, active_regions):
    pass


def get_security_groups_with_open_ssh_or_rdp_all_regions(role_session, active_regions):
    violations = []
    for region in active_regions:

        ec2 = role_session.resource("ec2", region_name=region)

        security_groups = ec2.security_groups.all()

        for security_group in security_groups:
            security_group_name = security_group.group_name
            if has_ipv4_open_ssh_or_rdp(security_group):
                violations.append(
                    {
                        security_group_name: "Has open ipv4 ssh or rdp access from the internet"
                    }
                )
            if has_ipv6_open_ssh_or_rdp(security_group):
                violations.append(
                    {
                        security_group_name: "has open ipv6 ssh or rdp access from the internet"
                    }
                )
    return violations


def main():
    main_session = boto3.session.Session()
    master_account_org_client = main_session.client("organizations")
    master_account_ec2_client = main_session.client("ec2")
    sts_client = main_session.client("sts")

    security_group_audit_results = {}
    network_acl_audit_results = {}

    active_accounts = get_active_accounts(master_account_org_client)
    active_regions = list_active_regions(master_account_ec2_client)

    session = main_session
    for account in active_accounts:
        regions = active_regions
        account_name, account_id = account.get("account_name"), account.get(
            "account_id"
        )

        # the name of the master account in the test env is `securing-the-cloud`
        if account_name != MASTER_ACCOUNT_NAME:
            # assume role

            role_arn = (
                f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ACCESS_ROLE_NAME}"
            )
            try:
                print(f"Assuming cross account role for {account_id}")
                # test env always expect original user (hezebonica) in role session name
                member_account = sts_client.assume_role(
                    RoleArn=role_arn, RoleSessionName="hezebonica"
                )
                xAcctAccessKey = member_account["Credentials"]["AccessKeyId"]
                xAcctSecretKey = member_account["Credentials"]["SecretAccessKey"]
                xAcctSeshToken = member_account["Credentials"]["SessionToken"]

                cross_account_session = boto3.Session(
                    aws_access_key_id=xAcctAccessKey,
                    aws_secret_access_key=xAcctSecretKey,
                    aws_session_token=xAcctSeshToken,
                )
                session = cross_account_session
            except botocore.exceptions as error:
                # raise error
                print(f"error assuming role: {error}")
                continue
        security_group_violations_found = (
            get_security_groups_with_open_ssh_or_rdp_all_regions(session, regions)
        )
        if security_group_violations_found:
            security_group_audit_results[account_name] = security_group_violations_found

        # network_acl_violations_found = get_security_groups_with_open_ssh_or_rdp_all_regions
        # network_acl_audit_results[account_name] = network_acl_violations_found

    # convert the dict to csv and write to console/file
    print(security_group_audit_results)


if __name__ == "__main__":
    main()
