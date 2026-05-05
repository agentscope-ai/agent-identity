"""``python -m agent_id_service_sdk.keygen`` — mint a hub signing keypair.

Convenience CLI for hub adopters. Prints (or writes) a fresh Ed25519
private key in PEM (PKCS#8) form plus the corresponding public JWK,
ready to drop into the hub's env config and JWKS endpoint.

A one-shot tool: hub keys are minted once per environment and stored
in a secret manager. There's no rotation flow yet — that comes when
the spec adds key-rotation guidance.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .manifest_signing import generate_signing_keypair


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent_id_service_sdk.keygen",
        description=(
            "Generate an Ed25519 keypair for hub manifest signing. "
            "Output: private key in PEM (PKCS#8), corresponding public "
            "JWK with the matching kid."
        ),
    )
    parser.add_argument(
        "--kid",
        default="hub-key-1",
        help="Key id to embed in the public JWK (default: hub-key-1).",
    )
    parser.add_argument(
        "--out",
        help=(
            "Write the private PEM to this file (mode 0600) instead of "
            "stdout. Operators typically point the hub's env config at "
            "the file's contents via a secret manager."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit a JSON object {kid, public_jwk, private_pem} instead "
            "of human-readable output. Useful for piping into a secret "
            "manager or another tool."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    _, public_jwk, private_pem = generate_signing_keypair(kid=args.kid)

    out_path: Path | None = None
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(private_pem)
        out_path.chmod(0o600)

    if args.json:
        payload = {
            "kid": args.kid,
            "public_jwk": public_jwk,
            "private_pem": None if out_path else private_pem,
            "private_pem_path": str(out_path) if out_path else None,
        }
        print(json.dumps(payload, indent=2))
        return 0

    if out_path is not None:
        print(f"wrote private key to {out_path} (mode 0600)")
    else:
        print(private_pem, end="")
    print()
    print(f"kid: {args.kid}")
    print(f"public jwk: {json.dumps(public_jwk)}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
