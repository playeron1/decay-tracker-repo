import boto3
from moto import mock_aws

from decay_tracker.models import Reachability
from decay_tracker.scanners.ec2_scanner import Ec2Scanner


@mock_aws
def test_stopped_instance_marked_unreachable():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = resp["Instances"][0]["InstanceId"]
    ec2.stop_instances(InstanceIds=[instance_id])

    assets = list(Ec2Scanner(session, "us-east-1").scan_instances())
    assert len(assets) == 1
    assert assets[0].reachability == Reachability.UNREACHABLE


@mock_aws
def test_unassociated_elastic_ip_flagged():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    ec2.allocate_address(Domain="vpc")

    assets = list(Ec2Scanner(session, "us-east-1").scan_elastic_ips())
    assert len(assets) == 1
    assert "NOT associated" in assets[0].probe_detail


@mock_aws
def test_associated_elastic_ip_not_flagged_as_orphan():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    run_resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = run_resp["Instances"][0]["InstanceId"]
    alloc = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(InstanceId=instance_id, AllocationId=alloc["AllocationId"])

    assets = list(Ec2Scanner(session, "us-east-1").scan_elastic_ips())
    assert len(assets) == 1
    assert "Associated with" in assets[0].probe_detail


@mock_aws
def test_terminated_instances_excluded():
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, InstanceType="t2.micro")
    instance_id = resp["Instances"][0]["InstanceId"]
    ec2.terminate_instances(InstanceIds=[instance_id])

    assets = list(Ec2Scanner(session, "us-east-1").scan_instances())
    assert len(assets) == 0
