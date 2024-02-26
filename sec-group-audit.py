import boto3
import boto3.session
import botocore

from utils import (
    get_active_accounts,
    list_active_regions,
    get_security_groups_with_open_ssh_or_rdp_all_regions,
    get_network_acls_with_open_ssh_or_rdp_all_regions,
    nacl_has_open_ssh_or_rdp,
)

# make this into an input to the cli wrapper (arg parse)
CROSS_ACCOUNT_ACCESS_ROLE_NAME = "OrganizationAccountAccessRole"

# make this into an optional cli input
# the name of the master account in the test env is "securing-the-cloud"
MASTER_ACCOUNT_NAME = "securing-the-cloud"


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

        nacl_violations_found = get_network_acls_with_open_ssh_or_rdp_all_regions(
            session, regions
        )

        if nacl_violations_found:
            network_acl_audit_results[account_name] = nacl_violations_found

        # network_acl_violations_found = get_security_groups_with_open_ssh_or_rdp_all_regions
        # network_acl_audit_results[account_name] = network_acl_violations_found

    # convert the dict to csv and write to console/file
    print(security_group_audit_results)
    print(network_acl_audit_results)


if __name__ == "__main__":
    main()
