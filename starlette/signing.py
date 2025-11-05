from __future__ import annotations

import base64
import hashlib
import hmac
import time


def _base64url_encode(data: bytes) -> bytes:
    """Encode bytes to base64url format without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _base64url_decode(data: bytes) -> bytes | None:
    """Decode base64url format, adding padding if needed. Returns None on error."""
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data = data + b"=" * padding

    try:
        return base64.urlsafe_b64decode(data)
    except Exception:
        return None


class TimestampSigner:
    """
    Signs and unsigns data with HMAC-SHA256 and timestamp validation.

    Highly optimized for cookie-based session storage with:
    - base64url encoding (cookie-safe, compact)
    - 128-bit HMAC-SHA256 truncated signature (cryptographically strong, compact)
    - 32-bit timestamp (valid until year 2106, compact)
    - Fixed-format encoding (no separators, fast slicing)
    - No exceptions on verification (returns None instead)
    - Minimal allocations and copies

    Format: <base64url(payload)><base64url(timestamp4)><base64url(signature16)>
    Fixed suffix length: 28 chars (6 for timestamp + 22 for signature)

    Size comparison for typical 65-byte session:
    - Total cookie size: 115 chars (87 payload + 28 overhead)
    - Previous format: 143 chars (50% more overhead)
    """

    def __init__(self, secret: str) -> None:
        """
        Initialize signer with a secret key.

        Args:
            secret: Secret key for HMAC signing (will be UTF-8 encoded)
        """
        self._secret = secret.encode("utf-8")

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with current timestamp.

        Args:
            data: Raw data to sign (e.g., JSON bytes)

        Returns:
            Signed token as bytes (cookie-safe, base64url encoded)
            Format: <payload><timestamp><signature> (no separators, fixed 28-char suffix)
        """
        # Encode payload
        payload_encoded = _base64url_encode(data)

        # Current timestamp as 4-byte big-endian integer (valid until 2106)
        timestamp_bytes = int(time.time()).to_bytes(4, "big")
        timestamp_encoded = _base64url_encode(timestamp_bytes)

        # Create signature over encoded payload + raw timestamp bytes
        # Using raw timestamp bytes ensures consistent message format
        message = payload_encoded + timestamp_bytes
        signature = hmac.new(self._secret, message, hashlib.sha256).digest()[:16]  # Truncate to 128 bits
        signature_encoded = _base64url_encode(signature)

        # Fixed format: payload + timestamp (6 chars) + signature (22 chars)
        return payload_encoded + timestamp_encoded + signature_encoded

    def unsign(self, signed_data: bytes, max_age: int | None = None) -> bytes | None:
        """
        Verify and extract data from signed token.

        Args:
            signed_data: Signed token (base64url encoded)
            max_age: Maximum age in seconds (None = no expiry check)

        Returns:
            Payload bytes on success, None on failure (invalid signature, expired, or malformed)
        """
        # Fixed format: last 28 chars are timestamp (6) + signature (22)
        # Minimum length check: at least 28 chars for timestamp + signature
        if len(signed_data) < 28:
            return None

        # Extract components using fixed offsets (no split needed - faster!)
        payload_encoded = signed_data[:-28]
        timestamp_encoded = signed_data[-28:-22]  # 6 chars for 4-byte timestamp
        signature_encoded = signed_data[-22:]  # 22 chars for 16-byte signature

        # Decode timestamp first (needed for signature verification)
        timestamp_bytes = _base64url_decode(timestamp_encoded)
        if timestamp_bytes is None or len(timestamp_bytes) != 4:
            return None

        # Verify signature over encoded payload + raw timestamp bytes
        message = payload_encoded + timestamp_bytes
        expected_signature = hmac.new(self._secret, message, hashlib.sha256).digest()[:16]
        expected_signature_encoded = _base64url_encode(expected_signature)

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signature_encoded, expected_signature_encoded):
            return None

        # Check timestamp age if max_age is set
        if max_age is not None:
            timestamp = int.from_bytes(timestamp_bytes, "big")
            current_time = int(time.time())

            if current_time - timestamp >= max_age:
                return None

        # Decode and return payload
        payload = _base64url_decode(payload_encoded)
        if payload is None:
            return None

        return payload
