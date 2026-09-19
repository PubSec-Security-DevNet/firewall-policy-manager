"""Deterministic test environment configured before application imports."""

import os

os.environ.update(
    {
        "APP_ENVIRONMENT": "test",
        "DATABASE_URL": "postgresql+psycopg://firewall:firewall@localhost:5432/firewall_manager_test",
        "REDIS_URL": "redis://localhost:6379/15",
        "FMC_BASE_URL": "http://mock-fmc:9000",
        "SCC_BASE_URL": "http://mock-scc:9000",
        "DEV_AUTH_ENABLED": "true",
        "CORS_ORIGINS": '["http://localhost:5173"]',
    }
)
