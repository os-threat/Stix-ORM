import pytest
from stix2.v21 import IPv4Address
from identifiers import makeid
def test_ids():
    ip1 = IPv4Address(value="1.2.3.4")
    ip2 = IPv4Address(value="1.2.3.4")
    ip3 = IPv4Address(value="1.2.3.5")

    oid1 = makeid(ip1)
    oid2 = makeid(ip2)
    oid3 = makeid(ip3)
    assert oid1 == oid2
    assert oid1 != oid3