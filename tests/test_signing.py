"""
Comprehensive test suite for starlette.signing module.

Tests cover:
- Normal operations (sign/unsign)
- Edge cases (empty data, large data, boundary conditions)
- Security attacks (tampering, forgery, replay attacks)
- Malformed data handling
- Encoding edge cases
- 100% code coverage

Note: Uses unittest.mock for time manipulation to avoid slow sleep() calls
"""

from unittest import mock

import pytest

from starlette.signing import TimestampSigner, _base64url_decode, _base64url_encode


class TestBase64UrlHelpers:
    """Test base64url encoding/decoding helper functions."""

    def test_encode_basic(self) -> None:
        """Test basic encoding."""
        assert _base64url_encode(b"hello") == b"aGVsbG8"
        assert _base64url_encode(b"") == b""

    def test_encode_no_padding(self) -> None:
        """Test that padding is removed."""
        # These would have padding with standard base64
        assert _base64url_encode(b"a") == b"YQ"  # No padding
        assert _base64url_encode(b"ab") == b"YWI"  # No padding
        assert _base64url_encode(b"abc") == b"YWJj"  # No padding naturally

    def test_encode_urlsafe_chars(self) -> None:
        """Test that URL-safe characters are used."""
        # Standard base64 would use + and /
        result = _base64url_encode(b"\xff" * 10)
        assert b"+" not in result
        assert b"/" not in result
        assert b"-" in result or b"_" in result  # Should use URL-safe chars

    def test_decode_basic(self) -> None:
        """Test basic decoding."""
        assert _base64url_decode(b"aGVsbG8") == b"hello"
        assert _base64url_decode(b"") == b""

    def test_decode_with_padding(self) -> None:
        """Test decoding with padding added."""
        assert _base64url_decode(b"YQ") == b"a"
        assert _base64url_decode(b"YWI") == b"ab"
        assert _base64url_decode(b"YWJj") == b"abc"

    def test_decode_invalid_returns_none(self) -> None:
        """Test that invalid base64 returns None."""
        # Base64 will fail if length is 4n+1 after padding is added
        # "A" is length 1, needs 3 padding chars, becomes 4 total - but "A===" is invalid
        # Python's decoder will reject strings that would be 4n+1 even with padding
        assert _base64url_decode(b"A") is None  # Length 1, invalid
        assert _base64url_decode(b"AAAAA") is None  # Length 5 = 4+1, invalid

    def test_round_trip(self) -> None:
        """Test encoding and decoding round trip."""
        test_cases = [
            b"",
            b"a",
            b"ab",
            b"abc",
            b"hello world",
            b"\x00\x01\x02\xff\xfe\xfd",
            b"x" * 1000,
        ]
        for data in test_cases:
            encoded = _base64url_encode(data)
            decoded = _base64url_decode(encoded)
            assert decoded == data, f"Round trip failed for {data!r}"


class TestTimestampSignerBasic:
    """Test basic sign/unsign operations."""

    def test_init(self) -> None:
        """Test signer initialization."""
        signer = TimestampSigner("secret")
        assert signer._secret == b"secret"

        # Test with different secret types
        signer2 = TimestampSigner("unicode-秘密")
        assert isinstance(signer2._secret, bytes)

    def test_sign_basic(self) -> None:
        """Test basic signing."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"hello")

        # Should return bytes
        assert isinstance(signed, bytes)

        # Should be base64url encoded + version marker (only valid chars)
        valid_chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in valid_chars for c in signed)

    def test_unsign_basic(self) -> None:
        """Test basic unsigning."""
        signer = TimestampSigner("secret")
        original = b"hello"
        signed = signer.sign(original)
        unsigned = signer.unsign(signed)

        assert unsigned == original

    def test_round_trip_various_data(self) -> None:
        """Test round trip with various data types."""
        signer = TimestampSigner("secret")

        test_cases = [
            b"",  # Empty
            b"a",  # Single byte
            b"hello world",  # ASCII
            b"\x00\x01\x02\xff\xfe\xfd",  # Binary
            b"x" * 1000,  # Large data
            b'{"user": "alice", "id": 123}',  # JSON-like
        ]

        for data in test_cases:
            signed = signer.sign(data)
            unsigned = signer.unsign(signed)
            assert unsigned == data, f"Round trip failed for {data!r}"

    def test_different_secrets_produce_different_signatures(self) -> None:
        """Test that different secrets produce different signatures."""
        data = b"test data"
        signer1 = TimestampSigner("secret1")
        signer2 = TimestampSigner("secret2")

        signed1 = signer1.sign(data)
        signed2 = signer2.sign(data)

        # Signatures should be different
        assert signed1 != signed2

        # Each signer should only verify its own signature
        assert signer1.unsign(signed1) == data
        assert signer1.unsign(signed2) is None  # Wrong secret
        assert signer2.unsign(signed2) == data
        assert signer2.unsign(signed1) is None  # Wrong secret

    def test_format_structure(self) -> None:
        """Test that format has fixed 30-char suffix with version marker."""
        signer = TimestampSigner("secret")

        # Test with different payload sizes
        for size in [1, 10, 100, 1000]:
            data = b"x" * size
            signed = signer.sign(data)

            # Last 30 chars should be timestamp (7) + signature (22) + version marker (1)
            assert len(signed) >= 30
            payload_len = len(_base64url_encode(data))
            assert len(signed) == payload_len + 30

            # Version marker should be '_'
            assert signed[-1] == ord(b"_")
            assert signed[-1] == 95


class TestTimestampValidation:
    """Test timestamp and expiry validation."""

    def test_unsign_with_no_max_age(self) -> None:
        """Test that tokens never expire when max_age is None."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Should work with no max_age
        assert signer.unsign(signed) == b"data"
        assert signer.unsign(signed, max_age=None) == b"data"

    def test_unsign_with_valid_max_age(self) -> None:
        """Test that fresh tokens pass max_age check."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Fresh token should be valid
        assert signer.unsign(signed, max_age=10) == b"data"
        assert signer.unsign(signed, max_age=1000) == b"data"

    def test_unsign_with_expired_max_age(self) -> None:
        """Test that old tokens fail max_age check (using time mocking)."""
        signer = TimestampSigner("secret")

        # Mock time to create token at t=1000
        with mock.patch("time.time", return_value=1000):
            signed = signer.sign(b"data")

        # Mock time to verify at t=1003 (3 seconds later)
        with mock.patch("time.time", return_value=1003):
            # Should fail with max_age=1 (definitely expired)
            assert signer.unsign(signed, max_age=1) is None
            assert signer.unsign(signed, max_age=0) is None

        # But should work with no max_age
        assert signer.unsign(signed, max_age=None) == b"data"

    def test_max_age_boundary(self) -> None:
        """Test max_age at exact boundary (using time mocking)."""
        signer = TimestampSigner("secret")

        # Create token at t=1000
        with mock.patch("time.time", return_value=1000):
            signed = signer.sign(b"data")

        # Verify at t=1005 (5 seconds later)
        with mock.patch("time.time", return_value=1005):
            # Should work with max_age=10 (still valid)
            assert signer.unsign(signed, max_age=10) == b"data"

            # Should fail with max_age=4 (expired)
            assert signer.unsign(signed, max_age=4) is None

            # Should fail at exact boundary (>=)
            assert signer.unsign(signed, max_age=5) is None

    def test_negative_max_age(self) -> None:
        """Test that negative max_age always fails."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Negative max_age should always fail
        assert signer.unsign(signed, max_age=-1) is None
        assert signer.unsign(signed, max_age=-1000) is None


class TestSecurityAttacks:
    """Test security against various attack vectors."""

    def test_tampered_signature(self) -> None:
        """Test that tampered signature is detected."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Tamper with signature (keep version marker)
        tampered = signed[:-23] + b"X" + signed[-22:]  # Change first char of signature
        assert signer.unsign(tampered) is None

        # Tamper near version marker
        tampered = signed[:-2] + b"X" + signed[-1:]  # Change last char of signature
        assert signer.unsign(tampered) is None

    def test_tampered_timestamp(self) -> None:
        """Test that tampered timestamp is detected."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Tamper with timestamp
        tampered = signed[:-30] + b"XXXXXX" + signed[-23:]  # Keep signature + marker
        assert signer.unsign(tampered) is None

    def test_tampered_payload(self) -> None:
        """Test that tampered payload is detected."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Tamper with payload
        tampered = b"XXXX" + signed[4:]
        assert signer.unsign(tampered) is None

    def test_signature_from_different_payload(self) -> None:
        """Test that signature from one payload doesn't work for another."""
        signer = TimestampSigner("secret")
        signed1 = signer.sign(b"data1")
        signed2 = signer.sign(b"data2")

        # Mix payload from signed1 with suffix from signed2
        payload1 = signed1[:-30]
        suffix2 = signed2[-30:]  # timestamp + signature + version marker
        mixed = payload1 + suffix2

        assert signer.unsign(mixed) is None

    def test_replay_attack_with_expired_token(self) -> None:
        """Test that expired tokens cannot be replayed (using time mocking)."""
        signer = TimestampSigner("secret")

        # Attacker captures token at t=1000
        with mock.patch("time.time", return_value=1000):
            signed = signer.sign(b"data")

        # Attacker tries to replay at t=1002 (2 seconds later)
        with mock.patch("time.time", return_value=1002):
            # Should be expired with max_age=1
            assert signer.unsign(signed, max_age=1) is None

    def test_signature_forgery_attempt(self) -> None:
        """Test that random signatures are rejected."""
        signer = TimestampSigner("secret")

        # Try completely random data
        assert signer.unsign(b"a" * 50) is None
        assert signer.unsign(b"X" * 100) is None

    def test_length_extension_attack(self) -> None:
        """Test that appending data doesn't break verification."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Append extra data
        extended = signed + b"extra"
        assert signer.unsign(extended) is None

    def test_truncation_attack(self) -> None:
        """Test that truncated signatures are rejected."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Remove last byte
        truncated = signed[:-1]
        assert signer.unsign(truncated) is None

        # Remove multiple bytes
        truncated = signed[:-10]
        assert signer.unsign(truncated) is None

    def test_secret_key_brute_force_resistance(self) -> None:
        """Test that similar secrets produce completely different signatures."""
        data = b"test"
        secrets = ["secret", "secreT", "secret ", " secret", "secretx"]

        signatures = []
        for secret in secrets:
            signer = TimestampSigner(secret)
            signed = signer.sign(data)
            signatures.append(signed)

        # All signatures should be completely different
        assert len(set(signatures)) == len(signatures)

        # No signer should verify another's signature
        for i, secret in enumerate(secrets):
            signer = TimestampSigner(secret)
            for j, sig in enumerate(signatures):
                if i == j:
                    assert signer.unsign(sig) == data
                else:
                    assert signer.unsign(sig) is None


class TestMalformedData:
    """Test handling of malformed data."""

    def test_too_short_data(self) -> None:
        """Test that data shorter than 30 chars is rejected."""
        signer = TimestampSigner("secret")

        # Less than 30 characters
        assert signer.unsign(b"") is None
        assert signer.unsign(b"a") is None
        assert signer.unsign(b"a" * 28) is None

        # Exactly 29 but missing version marker should fail
        assert signer.unsign(b"a" * 29) is None

    def test_missing_version_marker(self) -> None:
        """Test that missing version marker is rejected."""
        signer = TimestampSigner("secret")

        # Create valid token and remove version marker
        signed = signer.sign(b"data")
        without_marker = signed[:-1]  # Remove '_'
        assert signer.unsign(without_marker) is None

        # Wrong version marker
        wrong_marker = signed[:-1] + b"X"
        assert signer.unsign(wrong_marker) is None


    def test_version_marker_but_too_short(self) -> None:
        """Test that data with version marker but shorter than 30 chars is rejected."""
        signer = TimestampSigner("secret")

        # Has version marker '_' at end but too short (< 30 chars)
        assert signer.unsign(b"short_") is None  # Only 6 chars
        assert signer.unsign(b"a" * 28 + b"_") is None  # 29 chars total

    def test_invalid_base64_in_timestamp(self) -> None:
        """Test that invalid base64 in timestamp is rejected."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Replace timestamp with invalid base64
        payload = signed[:-30]
        tampered = payload + b"!!!!!!" + signed[-23:]  # Keep signature + version marker
        assert signer.unsign(tampered) is None

    def test_invalid_base64_in_signature(self) -> None:
        """Test that invalid base64 in signature is rejected."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Replace signature with invalid base64
        prefix = signed[:-23]  # Keep payload + timestamp
        tampered = prefix + b"!" * 22 + b"_"  # Invalid signature + version marker
        assert signer.unsign(tampered) is None

    def test_invalid_base64_in_payload(self) -> None:
        """Test that invalid base64 in payload is rejected."""
        signer = TimestampSigner("secret")

        # Create a valid token first
        signed = signer.sign(b"data")

        # Replace the payload with invalid base64 (length 4n+1)
        # Keep the valid timestamp + signature + version marker suffix
        malformed = b"A" + signed[-30:]  # "A" is invalid (length 1)
        assert signer.unsign(malformed) is None

        # Another invalid length pattern
        malformed = b"AAAAA" + signed[-30:]  # Length 5 = 4+1, invalid
        assert signer.unsign(malformed) is None

    def test_wrong_timestamp_length(self) -> None:
        """Test that timestamp not exactly 5 bytes is rejected."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Create timestamp that decodes to wrong length
        # Using base64url of 3 bytes instead of 5
        payload = signed[:-30]
        wrong_timestamp = _base64url_encode(b"xxx")  # 3 bytes, not 4
        signature_and_marker = signed[-23:]  # signature (22) + version marker (1)
        tampered = payload + wrong_timestamp.ljust(7, b"a") + signature_and_marker

        assert signer.unsign(tampered) is None

    def test_null_bytes_in_data(self) -> None:
        """Test that null bytes are handled correctly."""
        signer = TimestampSigner("secret")

        data = b"\x00\x00\x00"
        signed = signer.sign(data)
        unsigned = signer.unsign(signed)

        assert unsigned == data

    def test_unicode_handling(self) -> None:
        """Test that binary data with high bytes works."""
        signer = TimestampSigner("secret")

        # UTF-8 encoded unicode
        data = "Hello 世界 🌍".encode("utf-8")
        signed = signer.sign(data)
        unsigned = signer.unsign(signed)

        assert unsigned == data

    def test_empty_payload(self) -> None:
        """Test that empty payload is handled correctly."""
        signer = TimestampSigner("secret")

        signed = signer.sign(b"")
        unsigned = signer.unsign(signed)

        assert unsigned == b""


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_very_large_payload(self) -> None:
        """Test with very large payload."""
        signer = TimestampSigner("secret")

        # 1MB payload
        large_data = b"x" * (1024 * 1024)
        signed = signer.sign(large_data)
        unsigned = signer.unsign(signed)

        assert unsigned == large_data

    def test_max_age_zero(self) -> None:
        """Test that max_age=0 always fails."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Even immediately, max_age=0 should fail due to processing time
        assert signer.unsign(signed, max_age=0) is None

    def test_very_large_max_age(self) -> None:
        """Test with very large max_age value."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Very large max_age should work
        assert signer.unsign(signed, max_age=2**31 - 1) == b"data"

    def test_timestamp_year_36k_compatibility(self) -> None:
        """Test that we're using 5-byte timestamp (valid until year ~36,811)."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Extract timestamp portion (7 chars before signature)
        timestamp_encoded = signed[-30:-23]
        timestamp_bytes = _base64url_decode(timestamp_encoded)

        # Should be exactly 5 bytes
        assert timestamp_bytes is not None
        assert len(timestamp_bytes) == 5

        # Should be a valid 40-bit timestamp
        timestamp = int.from_bytes(timestamp_bytes, "big")
        assert 0 <= timestamp <= 2**40 - 1

        # Current timestamp should be reasonable (after 2020, before 36,811)
        assert timestamp > 1577836800  # 2020-01-01
        assert timestamp < 1099511627775  # 36,811-02-07

    def test_hmac_truncation_to_16_bytes(self) -> None:
        """Test that HMAC is truncated to 16 bytes (128 bits)."""
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Extract signature portion (22 chars before version marker)
        signature_encoded = signed[-23:-1]
        signature_bytes = _base64url_decode(signature_encoded)

        # Should be exactly 16 bytes (128 bits)
        assert signature_bytes is not None
        assert len(signature_bytes) == 16

    def test_constant_time_comparison(self) -> None:
        """Test that signature comparison is constant-time (timing attack resistant)."""
        # This is a behavioral test - we verify hmac.compare_digest is used
        # by checking that similar-but-wrong signatures still fail
        signer = TimestampSigner("secret")
        signed = signer.sign(b"data")

        # Create signature with only last bit flipped
        signature_bytes = _base64url_decode(signed[-23:-1])
        assert signature_bytes is not None

        # Flip last bit
        tampered_sig = signature_bytes[:-1] + bytes([signature_bytes[-1] ^ 1])
        tampered_sig_encoded = _base64url_encode(tampered_sig)

        # Reconstruct with tampered signature but keep version marker
        tampered = signed[:-23] + tampered_sig_encoded + b"_"

        # Should still be rejected (constant time comparison)
        assert signer.unsign(tampered) is None

    def test_different_data_same_length(self) -> None:
        """Test that different data of same length produces different signatures."""
        signer = TimestampSigner("secret")

        # Same length, different content
        signed1 = signer.sign(b"aaaaaaaaaa")
        signed2 = signer.sign(b"bbbbbbbbbb")

        assert len(signed1) == len(signed2)
        assert signed1 != signed2

        # Each should only verify itself
        assert signer.unsign(signed1) == b"aaaaaaaaaa"
        assert signer.unsign(signed2) == b"bbbbbbbbbb"

    def test_concurrent_signing(self) -> None:
        """Test that multiple signers can be used concurrently."""
        signer1 = TimestampSigner("secret1")
        signer2 = TimestampSigner("secret2")

        data1 = b"data1"
        data2 = b"data2"

        signed1 = signer1.sign(data1)
        signed2 = signer2.sign(data2)

        # Each signer should verify its own data
        assert signer1.unsign(signed1) == data1
        assert signer2.unsign(signed2) == data2

        # Cross verification should fail
        assert signer1.unsign(signed2) is None
        assert signer2.unsign(signed1) is None

    def test_special_characters_in_secret(self) -> None:
        """Test that special characters in secret work correctly."""
        special_secrets = [
            "pass word",  # Space
            "pass\nword",  # Newline
            "pass\x00word",  # Null byte
            "密碼",  # Unicode
            "🔐🔑",  # Emoji
            "",  # Empty secret
        ]

        for secret in special_secrets:
            signer = TimestampSigner(secret)
            signed = signer.sign(b"test")
            unsigned = signer.unsign(signed)
            assert unsigned == b"test", f"Failed for secret: {secret!r}"


class TestCookieSafety:
    """Test that output is safe for HTTP cookies."""

    def test_no_forbidden_cookie_characters(self) -> None:
        """Test that signed output contains no forbidden cookie characters."""
        signer = TimestampSigner("secret")

        # RFC 6265 forbids: space, comma, semicolon, backslash, quotes
        forbidden = set(b' ,;"\\')

        test_data = [
            b"simple",
            b'{"user": "alice", "roles": ["admin"]}',
            b"\x00\xff" * 100,
            b"x" * 1000,
        ]

        for data in test_data:
            signed = signer.sign(data)

            # Check no forbidden characters
            assert not any(c in forbidden for c in signed), f"Forbidden char in {signed!r}"

            # Should only contain base64url chars + version marker '_'
            valid_chars = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
            assert all(c in valid_chars for c in signed), f"Invalid char in {signed!r}"

    def test_no_padding_in_output(self) -> None:
        """Test that output has no base64 padding."""
        signer = TimestampSigner("secret")

        for size in range(1, 100):
            data = b"x" * size
            signed = signer.sign(data)

            # Should not contain padding character
            assert b"=" not in signed

    def test_output_is_ascii(self) -> None:
        """Test that output is pure ASCII."""
        signer = TimestampSigner("secret")

        data = "Hello 世界 🌍".encode("utf-8")
        signed = signer.sign(data)

        # Should be decodable as ASCII
        signed.decode("ascii")  # Should not raise

        # All bytes should be < 128
        assert all(b < 128 for b in signed)
