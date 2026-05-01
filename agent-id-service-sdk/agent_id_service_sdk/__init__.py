from .events import ActivityEvent, TIER1_CATEGORIES, match_category
from .verifier import Verifier, VerifiedAgent
from .reporter import ActivityReporter  # noqa: F401  # deprecated; kept for one minor
from .errors import (
    AgentIDError,
    TokenExpiredError,
    TokenInvalidError,
    ProviderUntrustedError,
    SignatureInvalidError,
)

__all__ = [
    "Verifier",
    "VerifiedAgent",
    "ActivityEvent",
    "TIER1_CATEGORIES",
    "match_category",
    "ActivityReporter",
    "AgentIDError",
    "TokenExpiredError",
    "TokenInvalidError",
    "ProviderUntrustedError",
    "SignatureInvalidError",
]

# v0.1 compatibility aliases — to be removed in v1.0.
AIPVerifier = Verifier
AIPAgent = VerifiedAgent
AIPActivityReporter = ActivityReporter
AIPError = AgentIDError
AIPTokenExpired = TokenExpiredError
AIPTokenInvalid = TokenInvalidError
AIPProviderUntrusted = ProviderUntrustedError
AIPSignatureInvalid = SignatureInvalidError
