"""FastAPI process composition root."""

import logging
import time
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pythonjsonlogger.json import JsonFormatter
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from firewall_manager.api.dependencies import (
    get_change_set_execution_dispatcher,
    get_provider_factory,
    get_provider_sync_dispatcher,
)
from firewall_manager.api.routes import auth_router, dev_router, get_provider_readers, router
from firewall_manager.api.schemas import ErrorEnvelope
from firewall_manager.application.errors import ApplicationError
from firewall_manager.config import get_settings
from firewall_manager.observability import request as record_request
from firewall_manager.providers.factory import build_real_provider
from firewall_manager.providers.fmc import FmcProviderReader
from firewall_manager.providers.scc import SccProviderReader
from firewall_manager.security.csrf import CSRF_COOKIE_NAME
from firewall_manager.security.csrf import token as csrf_token
from firewall_manager.security.csrf import valid as csrf_valid
from firewall_manager.security.oidc import COOKIE_NAME
from firewall_manager.security.redaction import SecretRedactionFilter
from firewall_manager.worker.tasks import execute_change_set, synchronize_provider_connection

HEALTH_PROBE_PATHS = frozenset(
    {
        "/api/v1/health/live",
        "/api/v1/health/ready",
        "/api/v1/metrics",
    }
)


def dispatch_provider_sync(connection_id: UUID, mode: str = "FULL") -> object:
    """Publish one connection UUID after the repository has committed its queue state."""
    return synchronize_provider_connection.send(str(connection_id), mode)


def dispatch_change_set_execution(
    change_set_id: UUID, principal_id: UUID, group_id: UUID, organization_id: UUID
) -> object:
    """Publish the immutable ChangeSet execution context after its queue claim commits."""
    return execute_change_set.send(
        str(change_set_id), str(principal_id), str(group_id), str(organization_id)
    )


def configure_logging() -> None:
    """Emit parseable logs without provider payloads or secrets."""
    handler = logging.StreamHandler()
    handler.addFilter(SecretRedactionFilter())
    handler.setFormatter(JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.basicConfig(level=get_settings().app_log_level, handlers=[handler], force=True)


def create_app() -> FastAPI:  # noqa: PLR0915 -- composition root owns all process wiring
    """Build the API with explicit infrastructure adapters."""
    settings = get_settings()
    configure_logging()
    error_response = {"model": ErrorEnvelope, "description": "Safe application error envelope"}
    docs_enabled = settings.app_environment in {"development", "test"}
    application = FastAPI(
        title="Firewall Manager API",
        version="0.1.0",
        responses=dict.fromkeys((401, 403, 404, 409, 422, 500, 502, 503), error_response),
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Correlation-ID", "X-Dev-User", "X-CSRF-Token"],
    )
    providers = tuple(
        reader
        for reader, base_url in (
            (FmcProviderReader(str(settings.fmc_base_url)), settings.fmc_base_url),
            (SccProviderReader(str(settings.scc_base_url)), settings.scc_base_url),
        )
        if "mock" not in str(base_url).casefold()
    )
    application.dependency_overrides[get_provider_readers] = lambda: providers
    application.dependency_overrides[get_provider_factory] = lambda: build_real_provider
    application.dependency_overrides[get_provider_sync_dispatcher] = lambda: dispatch_provider_sync
    application.dependency_overrides[get_change_set_execution_dispatcher] = lambda: (
        dispatch_change_set_execution
    )
    rate_window_started: dict[str, float] = {}
    rate_counts: dict[str, int] = {}

    @application.middleware("http")
    async def correlation_id(request: Request, call_next: RequestResponseEndpoint) -> Response:
        correlation = request.headers.get("X-Correlation-ID") or str(uuid4())
        request.state.correlation_id = correlation
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation
        return response

    @application.middleware("http")
    async def security_boundary(request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Apply a bounded per-process API limit and browser security headers."""
        now = time.monotonic()
        client = request.client.host if request.client else "unknown"
        if settings.app_environment in {"development", "test"}:
            development_user = request.headers.get("X-Dev-User", "").strip().lower()
            if development_user:
                client = f"{client}:dev:{development_user}"
        if request.url.path.startswith("/api/") and request.url.path not in HEALTH_PROBE_PATHS:
            request_limit = settings.api_rate_limit_requests
            if settings.app_environment == "development" and settings.dev_auth_enabled:
                # Development UI polling and multiple local tabs should not exhaust the
                # production-sized default while the development identity remains bounded.
                request_limit = max(request_limit, 5_000)
            started = rate_window_started.get(client, now)
            if now - started >= settings.api_rate_limit_window_seconds:
                rate_window_started[client] = now
                rate_counts[client] = 0
            rate_counts[client] = rate_counts.get(client, 0) + 1
            if rate_counts[client] > request_limit:
                response = JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": "Too many requests.",
                            "details": {},
                            "correlation_id": getattr(
                                request.state, "correlation_id", str(uuid4())
                            ),
                        }
                    },
                    headers={"Retry-After": str(settings.api_rate_limit_window_seconds)},
                )
                record_request(request.method, request.url.path, response.status_code)
                return response
        response = await call_next(request)
        record_request(request.method, request.url.path, response.status_code)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.app_environment in {"staging", "production"}:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; frame-ancestors 'none'"
            )
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @application.middleware("http")
    async def csrf_protection(request: Request, call_next: RequestResponseEndpoint) -> Response:
        state_change = request.method in {"POST", "PUT", "PATCH", "DELETE"}
        callback = request.url.path.startswith("/api/v1/auth/") and request.url.path.endswith(
            "/callback"
        )
        if (
            state_change
            and request.cookies.get(COOKIE_NAME)
            and not callback
            and not csrf_valid(request)
        ):
            correlation = getattr(request.state, "correlation_id", str(uuid4()))
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "code": "CSRF_VALIDATION_FAILED",
                        "message": "The security token is missing or invalid.",
                        "details": {},
                        "correlation_id": correlation,
                    }
                },
                headers={"X-Correlation-ID": correlation},
            )
        response = await call_next(request)
        if not request.cookies.get(CSRF_COOKIE_NAME):
            response.set_cookie(
                CSRF_COOKIE_NAME,
                csrf_token(),
                httponly=False,
                secure=settings.app_environment in {"staging", "production"},
                samesite="lax",
                max_age=settings.auth_session_absolute_hours * 3600,
                path="/",
            )
        return response

    @application.exception_handler(ApplicationError)
    async def application_error(request: Request, exc: ApplicationError) -> JSONResponse:
        correlation = getattr(request.state, "correlation_id", str(uuid4()))
        response = JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.safe_message,
                    "details": exc.details,
                    "correlation_id": correlation,
                }
            },
            headers={"X-Correlation-ID": correlation},
        )
        if exc.code == "NOT_AUTHENTICATED":
            response.delete_cookie(COOKIE_NAME, path="/")
        return response

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, _exc: RequestValidationError) -> JSONResponse:
        correlation = getattr(request.state, "correlation_id", str(uuid4()))
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "INVALID_REQUEST",
                    "message": "The request parameters are invalid.",
                    "details": {},
                    "correlation_id": correlation,
                }
            },
            headers={"X-Correlation-ID": correlation},
        )

    @application.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        correlation = getattr(request.state, "correlation_id", str(uuid4()))
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": "NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR",
                    "message": "The requested API resource was not found."
                    if exc.status_code == 404
                    else "The request could not be completed.",
                    "details": {},
                    "correlation_id": correlation,
                }
            },
            headers={"X-Correlation-ID": correlation},
        )

    @application.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        correlation = getattr(request.state, "correlation_id", str(uuid4()))
        logging.getLogger(__name__).exception(
            "unhandled application error", extra={"correlation_id": correlation}, exc_info=exc
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "The request could not be completed.",
                    "details": {},
                    "correlation_id": correlation,
                }
            },
            headers={"X-Correlation-ID": correlation},
        )

    application.include_router(router)
    # OIDC login/callback routes remain available in development for an admin-configured
    # integration test; development auth still remains the principal source for normal API calls.
    application.include_router(auth_router)
    if settings.dev_auth_enabled:
        application.include_router(dev_router)
    return application


app = create_app()
