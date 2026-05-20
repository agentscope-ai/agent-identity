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
from .envelope import (
    AUTHORIZATION_SCHEME,
    EnvelopeBodyMismatchError,
    EnvelopeMalformedError,
    EnvelopeReplayError,
    EnvelopeSignatureError,
    EnvelopeSigningError,
    EnvelopeSkewError,
    EnvelopeVerificationError,
    sign_envelope,
    verify_envelope,
)
from .manifest_signing import (
    ManifestSigningError,
    build_manifest,
    generate_signing_keypair,
    public_key_to_jwk,
    sign_manifest,
)
from .namespace_ownership import (
    NamespaceOwnershipError,
    verify_namespace_ownership,
)
from .dpop import (
    DPoPError,
    DPoPMalformedError,
    DPoPSignatureError,
    DPoPBindingError,
    DPoPHTTPBindingError,
    DPoPSkewError,
    DPoPReplayError,
    DPoPTokenBindingError,
    InMemoryReplayCache,
    jwk_thumbprint,
    verify_dpop_proof,
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
    "generate_signing_keypair",
    "public_key_to_jwk",
    "sign_manifest",
    "AUTHORIZATION_SCHEME",
    "EnvelopeBodyMismatchError",
    "EnvelopeMalformedError",
    "EnvelopeReplayError",
    "EnvelopeSignatureError",
    "EnvelopeSigningError",
    "EnvelopeSkewError",
    "EnvelopeVerificationError",
    "sign_envelope",
    "verify_envelope",
    "NamespaceOwnershipError",
    "verify_namespace_ownership",
    "DPoPError",
    "DPoPMalformedError",
    "DPoPSignatureError",
    "DPoPBindingError",
    "DPoPHTTPBindingError",
    "DPoPSkewError",
    "DPoPReplayError",
    "DPoPTokenBindingError",
    "InMemoryReplayCache",
    "jwk_thumbprint",
    "verify_dpop_proof",
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
