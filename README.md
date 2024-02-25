# AWS Security Group Audit

Python script to audit the security groups within all accounts in an AWS org for open ssh or rdp access (ingress) from the internet

## Assumptions

- The script will be run from the management account of the AWS org
- The script will be run with AdministratorAccess permissions
- There should be `OrganizationAccountAccessRole` roles in all the member accounts
- The script user should be assume the `OrganizationAccountAccessRole into the member accounts

## How to run

1. Make a virtual environment

    `python -m venv .venv && source .venv/bin/activate`

2. Install the dependencies

    `pip install -r requirements.txt`

3. Run the script
    `python sec-group-audit.py`

## Expected Output

csv report with all violations found.
