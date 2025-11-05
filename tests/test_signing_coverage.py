"""
Additional test to achieve 100% code coverage for signing module.
This tests an edge case that can't happen in normal usage but is theoretically possible.
"""

import hashlib
import hmac
from unittest import mock

from starlette.signing import TimestampSigner, _base64url_encode


def test_invalid_payload_with_valid_signature() -> None:
    """
    Test the edge case where payload is invalid base64 but has a valid signature.
    This can't happen in normal usage since sign() always creates valid base64,
    but we test it for 100% coverage.
    """
    signer = TimestampSigner("secret")

    # Create a payload_encoded that is invalid base64 (length 4n+1)
    payload_encoded = b"AAAAA"  # Length 5, will fail base64 decode

    # Create valid timestamp
    with mock.patch("time.time", return_value=1000):
        timestamp_bytes = int(1000).to_bytes(5, "big")
    timestamp_encoded = _base64url_encode(timestamp_bytes)

    # Create a VALID signature over the invalid payload
    # This simulates an attacker who knows the secret and deliberately
    # creates an invalid payload but with a correct signature
    message = payload_encoded + timestamp_bytes
    signature = hmac.new(b"secret", message, hashlib.sha256).digest()[:16]
    signature_encoded = _base64url_encode(signature)

    # Construct the malicious token with version marker
    malicious_token = payload_encoded + timestamp_encoded + signature_encoded + b"_"

    # This should fail at the payload decode step
    # not at the signature verification step
    result = signer.unsign(malicious_token)
    assert result is None
