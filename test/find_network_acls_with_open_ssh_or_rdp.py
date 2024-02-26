#!/usr/bin/python
import boto3

ec2 = boto3.resource("ec2", region_name="us-west-2")


def has_open_ssh_or_rdp(nacl_entry):
    rule_action, is_egress, rule_protocol = (
        entry.get("RuleAction"),
        entry.get("Egress"),
        entry.get("Protocol"),
    )
    # specificially check for rules allowing ssh or rdp
    # protocol -1 rules that open all ports are ignored for now
    if rule_action == "allow" and not is_egress and rule_protocol != "-1":
        if entry.get("PortRange").get("To") in [22, 3389]:
            return entry.get("CidrBlock") in ["0.0.0.0/0"] or entry.get(
                "Ipv6CidrBlock"
            ) in ["::/0"]
    return False


violations = []

nacls = ec2.network_acls.all()
for nacl in nacls:
    nacl_id = nacl.network_acl_id
    for entry in nacl.entries:
        if has_open_ssh_or_rdp(entry):
            violations.append(
                {f"{nacl_id}": "has entry allowing unrestricted ssh or rdp"}
            )
            continue

print(violations)
