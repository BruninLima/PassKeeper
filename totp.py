"""Two-factor (2FA) codes: time-based one-time passwords, RFC 6238.

Accepts either the plain base32 secret shown by a website ("JBSW Y3DP EHPK 3PXP")
or the full ``otpauth://totp/...`` link encoded in its QR code.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


@dataclass(frozen=True)
class TotpConfig:
    secret: bytes
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"


def _decode_base32(text: str) -> bytes:
    cleaned = "".join(text.split()).replace("-", "").upper()
    if not cleaned:
        raise ValueError("The 2FA secret is empty.")
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        secret = base64.b32decode(cleaned)
    except (binascii.Error, ValueError):
        raise ValueError("The 2FA secret should be the letters/numbers code "
                         "(base32) or an otpauth:// link.") from None
    if len(secret) < 10:
        raise ValueError("The 2FA secret is too short.")
    return secret


def parse(value: str) -> TotpConfig:
    """Parse a base32 secret or an otpauth:// URI. Raises ValueError."""
    value = value.strip()
    if not value.lower().startswith("otpauth://"):
        return TotpConfig(_decode_base32(value))

    uri = urlparse(value)
    if uri.netloc.lower() != "totp":
        raise ValueError("Only time-based (TOTP) 2FA codes are supported.")
    query = {k.lower(): v[0] for k, v in parse_qs(uri.query).items()}
    if "secret" not in query:
        raise ValueError("The otpauth:// link has no secret.")
    try:
        digits = int(query.get("digits", 6))
        period = int(query.get("period", 30))
    except ValueError:
        raise ValueError("The otpauth:// link has invalid digits/period.") from None
    algorithm = unquote(query.get("algorithm", "SHA1")).upper()
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unsupported 2FA algorithm: {algorithm}")
    if not 6 <= digits <= 10 or period <= 0:
        raise ValueError("The otpauth:// link has invalid digits/period.")
    return TotpConfig(_decode_base32(query["secret"]), digits, period, algorithm)


def code(value: str | TotpConfig, at: float | None = None) -> str:
    config = value if isinstance(value, TotpConfig) else parse(value)
    counter = int((time.time() if at is None else at) // config.period)
    digest = hmac.new(config.secret, struct.pack(">Q", counter),
                      ALGORITHMS[config.algorithm]).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** config.digits).zfill(config.digits)


def seconds_left(value: str | TotpConfig, at: float | None = None) -> int:
    config = value if isinstance(value, TotpConfig) else parse(value)
    now = time.time() if at is None else at
    return config.period - int(now) % config.period
