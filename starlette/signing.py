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

    Optimized for cookie-based session storage with:
    - base64url encoding (cookie-safe, no padding issues)
    - HMAC-SHA256 (fast and secure)
    - No exceptions on verification (returns bool instead)
    - Minimal allocations and copies

    Format: <base64url(payload)>.<base64url(timestamp)>.<base64url(signature)>
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
            Format: <payload>.<timestamp>.<signature>
        """
        # Encode payload
        payload = _base64url_encode(data)

        # Current timestamp as 8-byte big-endian integer
        timestamp = int(time.time())
        timestamp_bytes = timestamp.to_bytes(8, "big")
        timestamp_encoded = _base64url_encode(timestamp_bytes)

        # Create signature over payload + timestamp
        message = payload + b"." + timestamp_encoded
        signature = hmac.new(self._secret, message, hashlib.sha256).digest()
        signature_encoded = _base64url_encode(signature)

        return message + b"." + signature_encoded

    def unsign(self, signed_data: bytes, max_age: int | None = None) -> tuple[bool, bytes]:
        """
        Verify and extract data from signed token.

        Args:
            signed_data: Signed token (base64url encoded)
            max_age: Maximum age in seconds (None = no expiry check)

        Returns:
            Tuple of (success: bool, data: bytes)
            If success=False, data will be empty bytes b""
        """
        # Split into components
        parts = signed_data.split(b".")
        if len(parts) != 3:
            return (False, b"")

        payload_encoded, timestamp_encoded, signature_encoded = parts

        # Verify signature
        message = payload_encoded + b"." + timestamp_encoded
        expected_signature = hmac.new(self._secret, message, hashlib.sha256).digest()
        expected_signature_encoded = _base64url_encode(expected_signature)

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(signature_encoded, expected_signature_encoded):
            return (False, b"")

        # Decode and verify timestamp if max_age is set
        if max_age is not None:
            timestamp_bytes = _base64url_decode(timestamp_encoded)
            if timestamp_bytes is None or len(timestamp_bytes) != 8:
                return (False, b"")

            timestamp = int.from_bytes(timestamp_bytes, "big")
            current_time = int(time.time())

            if current_time - timestamp > max_age:
                return (False, b"")

        # Decode payload
        payload = _base64url_decode(payload_encoded)
        if payload is None:
            return (False, b"")

        return (True, payload)
