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
from .manifest import (
    CategoriesDoc,
    CategoryEntry,
    HubManifest,
    HubManifestError,
    HubManifestFetchError,
    HubManifestFetcher,
    HubManifestInvalidError,
    HubManifestSignatureError,
    WELL_KNOWN_JWKS_PATH,
    WELL_KNOWN_MANIFEST_PATH,
)
from .manifest_signing import (
    ManifestSigningError,
    build_manifest,
    sign_manifest,
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
    "HubManifest",
    "HubManifestError",
    "HubManifestFetchError",
    "HubManifestFetcher",
    "HubManifestInvalidError",
    "HubManifestSignatureError",
    "WELL_KNOWN_JWKS_PATH",
    "WELL_KNOWN_MANIFEST_PATH",
    "CategoryEntry",
    "CategoriesDoc",
    "ManifestSigningError",
    "build_manifest",
    "sign_manifest",
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
