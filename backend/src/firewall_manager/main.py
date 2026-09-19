"""FastAPI process composition root."""

import logging
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pythonjsonlogger.json import JsonFormatter
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

from firewall_manager.api.dependencies import get_provider_factory, get_provider_sync_dispatcher
from firewall_manager.api.routes import dev_router, get_provider_readers, router
from firewall_manager.api.schemas import ErrorEnvelope
from firewall_manager.application.errors import ApplicationError
from firewall_manager.config import get_settings
from firewall_manager.providers.factory import build_real_provider
from firewall_manager.providers.fmc import FmcProviderReader
from firewall_manager.providers.scc import SccProviderReader
from firewall_manager.security.redaction import SecretRedactionFilter
from firewall_manager.worker.tasks import synchronize_provider_connection


def dispatch_provider_sync(connection_id: UUID) -> object:
    """Publish one connection UUID after the repository has committed its queue state."""
    return synchronize_provider_connection.send(str(connection_id))


def configure_logging() -> None:
    """Emit parseable logs without provider payloads or secrets."""
    handler = logging.StreamHandler()
    handler.addFilter(SecretRedactionFilter())
    handler.setFormatter(JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logging.basicConfig(level=get_settings().app_log_level, handlers=[handler], force=True)


def create_app() -> FastAPI:
    """Build the API with explicit infrastructure adapters."""
    settings = get_settings()
    configure_logging()
    error_response = {"model": ErrorEnvelope, "description": "Safe application error envelope"}
    application = FastAPI(
        title="Firewall Manager API",
        version="0.1.0",
        responses=dict.fromkeys((401, 403, 404, 409, 422, 500, 502, 503), error_response),
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Correlation-ID", "X-Dev-User"],
    )
    providers = (
        FmcProviderReader(str(settings.fmc_base_url)),
        SccProviderReader(str(settings.scc_base_url)),
    )
    application.dependency_overrides[get_provider_readers] = lambda: providers
    application.dependency_overrides[get_provider_factory] = lambda: build_real_provider
    application.dependency_overrides[get_provider_sync_dispatcher] = lambda: dispatch_provider_sync

    @application.middleware("http")
    async def correlation_id(request: Request, call_next: RequestResponseEndpoint) -> Response:
        correlation = request.headers.get("X-Correlation-ID") or str(uuid4())
        request.state.correlation_id = correlation
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation
        return response

    @application.exception_handler(ApplicationError)
    async def application_error(request: Request, exc: ApplicationError) -> JSONResponse:
        correlation = getattr(request.state, "correlation_id", str(uuid4()))
        return JSONResponse(
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
    if settings.dev_auth_enabled:
        application.include_router(dev_router)
    return application


app = create_app()
