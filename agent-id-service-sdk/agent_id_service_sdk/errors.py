class AIPError(Exception):
    """Base exception for AIP verification errors."""


class AIPTokenExpired(AIPError):
    """The AIP token has expired."""


class AIPTokenInvalid(AIPError):
    """The AIP token is invalid (wrong audience, malformed, etc.)."""


class AIPProviderUntrusted(AIPError):
    """The token's issuer is not in the list of trusted providers."""


class AIPSignatureInvalid(AIPError):
    """The cryptographic signature on the token or report is invalid."""
