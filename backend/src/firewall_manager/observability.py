# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Low-overhead Prometheus text metrics for operational scraping."""

import re
from collections import Counter
from threading import Lock

_lock = Lock()
_requests: Counter[tuple[str, str, int]] = Counter()
_jobs: Counter[tuple[str, str]] = Counter()


def request(method: str, path: str, status: int) -> None:
    route = path.split("?", 1)[0]
    route = re.sub(
        r"/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,36}(?=/|$)",
        "/:id",
        route,
    )
    with _lock:
        _requests[(method, route, status)] += 1


def job(name: str, outcome: str) -> None:
    with _lock:
        _jobs[(name, outcome)] += 1


def render(*, worker_healthy: bool | None = None, scheduler_healthy: bool | None = None) -> str:
    lines = [
        "# HELP firewall_manager_http_requests_total HTTP requests handled.",
        "# TYPE firewall_manager_http_requests_total counter",
    ]
    with _lock:
        for (method, path, status), value in sorted(_requests.items()):
            labels = f'method="{method}",path="{path}",status="{status}"'
            lines.append(f"firewall_manager_http_requests_total{{{labels}}} {value}")
        lines.extend(
            [
                "# HELP firewall_manager_jobs_total Background jobs completed.",
                "# TYPE firewall_manager_jobs_total counter",
            ]
        )
        for (name, outcome), value in sorted(_jobs.items()):
            lines.append(f'firewall_manager_jobs_total{{job="{name}",outcome="{outcome}"}} {value}')
        if worker_healthy is not None:
            lines.extend(
                [
                    "# HELP firewall_manager_worker_healthy Whether a worker heartbeat is current.",
                    "# TYPE firewall_manager_worker_healthy gauge",
                    f"firewall_manager_worker_healthy {int(worker_healthy)}",
                ]
            )
        if scheduler_healthy is not None:
            lines.extend(
                [
                    "# HELP firewall_manager_scheduler_healthy "
                    "Whether the scheduler heartbeat is current.",
                    "# TYPE firewall_manager_scheduler_healthy gauge",
                    f"firewall_manager_scheduler_healthy {int(scheduler_healthy)}",
                ]
            )
    return "\n".join(lines) + "\n"
