class AgentIDError(Exception):
    """Base exception for AIP verification errors."""


class TokenExpiredError(AgentIDError):
    """The AIP token has expired."""


class TokenInvalidError(AgentIDError):
    """The AIP token is invalid (wrong audience, malformed, etc.)."""


class ProviderUntrustedError(AgentIDError):
    """The token's issuer is not in the list of trusted providers."""


class SignatureInvalidError(AgentIDError):
    """The cryptographic signature on the token or report is invalid."""
