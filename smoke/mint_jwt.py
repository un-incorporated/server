#!/usr/bin/env python3
"""Mint a short-lived HS256 JWT for chain-api smoke testing.

No third-party deps — pure stdlib so the smoke script can rely on every
dev machine having `python3` on PATH.

Usage:
    mint_jwt.py --secret <hex or utf-8> --sub <user_id> --aud chain-api-user
    mint_jwt.py --secret <hex or utf-8> --sub operator    --aud chain-api-admin

The token's `exp` defaults to now + 300 seconds.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time


def b64url(data: bytes) -> str:
    """RFC 7515 base64url, no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--secret", required=True,
                   help="HS256 secret (matches JWT_SECRET env on the proxy)")
    p.add_argument("--sub", required=True, help="Subject claim")
    p.add_argument("--aud", required=True,
                   choices=["chain-api-user", "chain-api-admin"])
    p.add_argument("--exp-seconds", type=int, default=300,
                   help="Lifetime in seconds (default 300)")
    p.add_argument("--iss", default="uninc-smoke")
    args = p.parse_args()

    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "iss": args.iss,
        "sub": args.sub,
        "aud": args.aud,
        "exp": now + args.exp_seconds,
        "iat": now,
        "jti": os.urandom(16).hex(),
    }

    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    claims_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{claims_b64}".encode()

    sig = hmac.new(args.secret.encode(), signing_input, hashlib.sha256).digest()
    token = f"{header_b64}.{claims_b64}.{b64url(sig)}"
    sys.stdout.write(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
