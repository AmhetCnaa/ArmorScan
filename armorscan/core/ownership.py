"""
Zero-Trust Domain Ownership Gate & Military-Grade Master Key Verifier for ArmorScan.

Prevents unauthorized scanning of external targets by requiring either:
1. Live cryptographic Domain Ownership Proof placed by the target administrator via:
   - HTTP Well-Known File: https://<host>/.well-known/armorscan-verify.txt
   - HTML Meta Tag: <meta name="armorscan-verification" content="<token>">
   - HTTP Response Header: X-ArmorScan-Verification: <token>
2. Military-Grade Developer Master Key (verified via 600,000-iteration PBKDF2-HMAC-SHA512
   with constant-time comparison; the raw key is NEVER stored in the repository).
3. Localhost / Loopback Development Targets (127.0.0.1, localhost, ::1).
"""

from __future__ import annotations

import binascii
from datetime import datetime, timezone
import hashlib
import hmac
import os
import re
from typing import Optional, Tuple

from pydantic import BaseModel

from armorscan.core.client import HttpClient
from armorscan.core.models import ScanTarget

# 600,000-iteration PBKDF2-HMAC-SHA512 Master Key Verifier (OWASP 2024+ Standard)
# The plaintext Master Key exists ONLY in the creator's private environment.
MASTER_PBKDF2_ITERATIONS: int = 600_000
MASTER_SALT_HEX: str = "3d1583e3a4667d58cc133bd3e2b004711d1fd1a9ebf4ed94ac544757704d752a"
MASTER_HASH_HEX: str = (
    "0911e5468a90c0483e5da43bbdc2601942a65790ec6ac1d3694ab8e8785094"
    "540127a024082d836a759a98860d6dd3d52fbb6600f8f2d1c8025e85fae682f9d5"
)


class OwnershipVerificationResult(BaseModel):
    """Result of pre-flight domain ownership or master key authorization check."""

    authorized: bool
    mode: str  # "localhost", "master_key", "well_known", "meta_tag", "http_header", "denied"
    host: str
    expected_token: str
    message: str


class OwnershipGate:
    """Enforces cryptographic domain ownership verification and Master Key authentication."""

    WELL_KNOWN_PATH = "/.well-known/armorscan-verify.txt"
    HEADER_NAME = "x-armorscan-verification"

    @staticmethod
    def verify_master_key(candidate_key: Optional[str] = None) -> bool:
        """
        Verify a candidate Master Key against the embedded PBKDF2-HMAC-SHA512 digest
        using constant-time comparison (`hmac.compare_digest`).
        Checks `candidate_key` first, then falls back to `ARMORSCAN_MASTER_KEY` env var.
        """
        key = (candidate_key or os.environ.get("ARMORSCAN_MASTER_KEY") or "").strip()
        if not key:
            return False

        try:
            salt = binascii.unhexlify(MASTER_SALT_HEX)
            expected_dk = binascii.unhexlify(MASTER_HASH_HEX)
            computed_dk = hashlib.pbkdf2_hmac(
                "sha512",
                key.encode("utf-8"),
                salt,
                MASTER_PBKDF2_ITERATIONS,
            )
            return hmac.compare_digest(computed_dk, expected_dk)
        except Exception:
            return False

    @staticmethod
    def generate_domain_challenge(host: str, date_str: Optional[str] = None) -> str:
        """
        Generate a deterministic daily domain verification token for a target hostname.
        Every website has a unique cryptographic challenge token rotated daily (UTC).
        Format: `armorscan-site-verification=<32-hex-chars>`
        """
        normalized_host = host.strip().lower().split(":")[0]
        if not date_str:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        domain_salt = binascii.unhexlify(MASTER_SALT_HEX)[:16]
        msg = f"armorscan-domain-ownership:{normalized_host}:{date_str}".encode("utf-8")
        digest = hmac.new(domain_salt, msg, hashlib.sha256).hexdigest()[:32]
        return f"armorscan-site-verification={digest}"

    @classmethod
    async def verify_target_access(
        cls,
        target: ScanTarget,
        client: HttpClient,
        master_key: Optional[str] = None,
    ) -> OwnershipVerificationResult:
        """
        Verify whether the user is authorized to scan `target`.
        1. Localhost targets (127.0.0.1, localhost, ::1) are always permitted.
        2. Valid Master Key unlocks unrestricted Root/Master Auditor mode.
        3. External targets require live proof of ownership via:
           - `/.well-known/armorscan-verify.txt`
           - `<meta name="armorscan-verification" content="...">` on `/`
           - `X-ArmorScan-Verification` HTTP response header on `/`
        """
        expected_token = cls.generate_domain_challenge(target.host)

        # 1. Localhost / Loopback check
        if target.is_localhost:
            return OwnershipVerificationResult(
                authorized=True,
                mode="localhost",
                host=target.host,
                expected_token=expected_token,
                message="Localhost development target authorized automatically.",
            )

        # 2. Military-Grade Master Key check
        if cls.verify_master_key(master_key):
            return OwnershipVerificationResult(
                authorized=True,
                mode="master_key",
                host=target.host,
                expected_token=expected_token,
                message="Master Auditor Key verified (PBKDF2-HMAC-SHA512). Unrestricted target audit unlocked.",
            )

        # 3. Live Domain Ownership Proof Check on Target Server
        well_known_url = f"{target.base_url.rstrip('/')}{cls.WELL_KNOWN_PATH}"
        wk_resp = await client.get(well_known_url, follow_redirects=True)
        if wk_resp.ok and wk_resp.status_code == 200:
            if expected_token in (wk_resp.text or ""):
                return OwnershipVerificationResult(
                    authorized=True,
                    mode="well_known",
                    host=target.host,
                    expected_token=expected_token,
                    message=f"Domain ownership verified via {cls.WELL_KNOWN_PATH}.",
                )

        # 4. Check Root Page for HTTP Header or HTML <meta> Tag
        root_resp = await client.get(target.base_url, follow_redirects=True)
        if root_resp.ok:
            header_val = root_resp.headers.get(cls.HEADER_NAME, "").strip()
            if expected_token in header_val:
                return OwnershipVerificationResult(
                    authorized=True,
                    mode="http_header",
                    host=target.host,
                    expected_token=expected_token,
                    message=f"Domain ownership verified via '{cls.HEADER_NAME}' HTTP header.",
                )

            body = root_resp.text or ""
            meta_pattern = re.compile(
                r'<meta[^>]+name=["\']armorscan-verification["\'][^>]+content=["\']([^"\']+)["\']',
                re.IGNORECASE,
            )
            meta_pattern_rev = re.compile(
                r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']armorscan-verification["\']',
                re.IGNORECASE,
            )
            for pat in (meta_pattern, meta_pattern_rev):
                match = pat.search(body)
                if match and match.group(1).strip() == expected_token:
                    return OwnershipVerificationResult(
                        authorized=True,
                        mode="meta_tag",
                        host=target.host,
                        expected_token=expected_token,
                        message="Domain ownership verified via HTML <meta name='armorscan-verification'> tag.",
                    )

        return OwnershipVerificationResult(
            authorized=False,
            mode="denied",
            host=target.host,
            expected_token=expected_token,
            message=(
                f"Unauthorized external target '{target.host}'. "
                f"Prove domain ownership using token '{expected_token}' or authenticate with Master Key."
            ),
        )
