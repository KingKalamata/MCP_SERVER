import pytest
from pydantic import ValidationError
from main import MasscanRequest, CVSSRequest

def test_masscan_request_valid():
    req = MasscanRequest(target="127.0.0.1", ports="80,443", rate=500)
    assert req.target == "127.0.0.1"
    assert req.ports == "80,443"
    assert req.rate == 500

def test_masscan_request_invalid_target():
    with pytest.raises(ValidationError):
        MasscanRequest(target="127.0.0.1; rm -rf /", ports="80", rate=500)

def test_cvss_request_valid():
    req = CVSSRequest(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert req.vector.startswith("CVSS:3.1")

def test_cvss_request_invalid():
    with pytest.raises(ValidationError):
        CVSSRequest(vector="INVALID")
