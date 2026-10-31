from decay_tracker.models import Reachability
from decay_tracker.scanners.dns_scanner import DnsScanner, _looks_like_cloud_endpoint


def test_looks_like_cloud_endpoint_matches_s3():
    assert _looks_like_cloud_endpoint("old-bucket.s3.amazonaws.com") is not None


def test_looks_like_cloud_endpoint_matches_elb():
    assert _looks_like_cloud_endpoint("my-lb-123456.us-east-1.elb.amazonaws.com") is not None


def test_looks_like_cloud_endpoint_no_match_for_unrelated_domain():
    assert _looks_like_cloud_endpoint("example.com") is None


def test_nonexistent_domain_marked_unreachable():
    scanner = DnsScanner(["this-domain-definitely-does-not-exist-decaytest.invalid"], probe_http=False)
    assets = list(scanner.scan())
    assert len(assets) == 1
    assert assets[0].reachability in (Reachability.UNREACHABLE, Reachability.RESPONSIVE_ERROR)
