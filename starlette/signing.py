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
    - 40-bit timestamp (valid until year 36,811, compact)
    - Fixed-format encoding (no separators, fast slicing)
    - Version marker for future compatibility
    - No exceptions on verification (returns None instead)
    - Minimal allocations and copies

    Format: <base64url(payload)><base64url(timestamp5)><base64url(signature16)>_
    Fixed suffix length: 30 chars (7 for timestamp + 22 for signature + 1 for version marker)
    Version marker '_' (chr(ord('A')+30) = chr(95)) allows quick validation and future format changes.

    Size comparison for typical 65-byte session:
    - Total cookie size: 117 chars (87 payload + 30 overhead)
    - itsdangerous format: 143 chars (43% more overhead)
    """

    VERSION_MARKER = ord(b"_")  # Byte value 95, conveniently chr(ord('A')+30)

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
            Format: <payload><timestamp><signature>_ (fixed 30-char suffix with version marker)
        """
        # Encode payload
        payload_encoded = _base64url_encode(data)

        # Current timestamp as 5-byte big-endian integer (valid until year 36,811)
        timestamp_bytes = int(time.time()).to_bytes(5, "big")
        timestamp_encoded = _base64url_encode(timestamp_bytes)

        # Create signature over encoded payload + raw timestamp bytes
        # Using raw timestamp bytes ensures consistent message format
        message = payload_encoded + timestamp_bytes
        signature = hmac.new(self._secret, message, hashlib.sha256).digest()[:16]  # Truncate to 128 bits
        signature_encoded = _base64url_encode(signature)

        # Fixed format: payload + timestamp (7 chars) + signature (22 chars) + version marker (1 byte)
        # Using join() is more efficient than multiple concatenations
        return b"".join([payload_encoded, timestamp_encoded, signature_encoded, bytes([self.VERSION_MARKER])])

    def unsign(self, signed_data: bytes, max_age: int | None = None) -> bytes | None:
        """
        Verify and extract data from signed token.

        Args:
            signed_data: Signed token (base64url encoded)
            max_age: Maximum age in seconds (None = no expiry check)

        Returns:
            Payload bytes on success, None on failure (invalid signature, expired, or malformed)
        """
        # Quick validation: check version marker FIRST (fast rejection of invalid tokens)
        # Using [-1] is more efficient than [-1:] as it returns int directly
        if not signed_data or signed_data[-1] != self.VERSION_MARKER:
            return None

        # Length check: minimum 30 chars for timestamp (7) + signature (22) + marker (1)
        if len(signed_data) < 30:
            return None

        # Fixed format: last 30 chars are timestamp (7) + signature (22) + version marker (1)
        # Extract components using fixed offsets (no split needed - faster!)
        payload_encoded = signed_data[:-30]
        timestamp_encoded = signed_data[-30:-23]  # 7 chars for 5-byte timestamp
        signature_encoded = signed_data[-23:-1]  # 22 chars for 16-byte signature

        # Decode timestamp first (needed for signature verification)
        timestamp_bytes = _base64url_decode(timestamp_encoded)
        if timestamp_bytes is None or len(timestamp_bytes) != 5:
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
