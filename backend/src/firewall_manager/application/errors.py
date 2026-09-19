"""Safe application exceptions mapped by delivery interfaces."""


class ApplicationError(Exception):
    """Base error containing a stable safe-to-return code."""

    code = "APPLICATION_ERROR"
    status_code = 400
    safe_message = "The request could not be completed."

    def __init__(self, *, details: dict[str, object] | None = None) -> None:
        super().__init__(self.safe_message)
        self.details = details or {}


class NotAuthenticatedError(ApplicationError):
    code = "NOT_AUTHENTICATED"
    status_code = 401
    safe_message = "Authentication is required."


class ResourceOutOfScopeError(ApplicationError):
    code = "RESOURCE_OUT_OF_SCOPE"
    status_code = 403
    safe_message = "The requested operation is not permitted."


class ProviderError(ApplicationError):
    """Base provider/domain failure safe for interface mapping."""

    code = "PROVIDER_ERROR"
    status_code = 502
    safe_message = "The provider request could not be completed."


class ProviderUnavailableError(ProviderError):
    code = "PROVIDER_UNAVAILABLE"
    status_code = 503
    safe_message = "Provider inventory is temporarily unavailable."


class ProviderAuthenticationError(ProviderError):
    code = "AUTHENTICATION_FAILED"
    status_code = 401
    safe_message = "The provider rejected the configured credential."


class ProviderTlsValidationError(ProviderError):
    code = "TLS_VALIDATION_FAILED"
    safe_message = "The provider TLS certificate could not be validated."


class ProviderPermissionError(ProviderError):
    code = "INSUFFICIENT_PRIVILEGES"
    status_code = 403
    safe_message = "The provider identity lacks a required read permission."


class ProviderRateLimitedError(ProviderError):
    code = "RATE_LIMITED"
    status_code = 429
    safe_message = "The provider rate limit was reached."


class ProviderUnsupportedVersionError(ProviderError):
    code = "UNSUPPORTED_VERSION"
    safe_message = "The provider version has not passed compatibility validation."


class ProviderConfigurationError(ApplicationError):
    code = "CONFIGURATION_INVALID"
    status_code = 422
    safe_message = "The provider connection configuration is invalid."


class SecretStoreUnavailableError(ApplicationError):
    code = "SECRET_STORE_UNAVAILABLE"
    status_code = 503
    safe_message = "Secure credential storage is not configured."


class ProviderContractError(ProviderError):
    code = "PROVIDER_CONTRACT_ERROR"
    safe_message = "The provider returned an invalid discovery response."


class ProviderPaginationError(ProviderError):
    code = "PROVIDER_PAGINATION_FAILED"
    safe_message = "Provider discovery stopped before all pages were read."


class ProviderMismatchError(ProviderError):
    code = "PROVIDER_MISMATCH"
    safe_message = "The configured provider does not match the manager."


class InvalidPaginationError(ApplicationError):
    code = "INVALID_PAGINATION"
    status_code = 422
    safe_message = "The pagination cursor or limit is invalid."


class InvalidInputError(ApplicationError):
    code = "INVALID_INPUT"
    status_code = 422
    safe_message = "The request parameters are invalid."


class StaleWriteError(ApplicationError):
    code = "STALE_REVISION"
    status_code = 409
    safe_message = "The resource changed before this update could be applied."


class ChangeSetConflictError(ApplicationError):
    code = "CHANGE_SET_CONFLICT"
    status_code = 409
    safe_message = "The ChangeSet conflicts with current provider state."


class InvalidChangeSetStateError(ApplicationError):
    code = "INVALID_CHANGE_SET_STATE"
    status_code = 409
    safe_message = "The ChangeSet is not in a state that permits this operation."


class ProductionWriteDisabledError(ApplicationError):
    code = "PRODUCTION_PROVIDER_WRITE_DISABLED"
    status_code = 403
    safe_message = "Production FMC and SCC writes are disabled."


class ReconciliationRequiredError(ApplicationError):
    code = "RECONCILIATION_REQUIRED"
    status_code = 409
    safe_message = "The provider result is ambiguous and requires reconciliation."
