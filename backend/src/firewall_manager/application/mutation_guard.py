# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Request-local mutation boundary; durable authority lives in the supplied guard."""

from contextvars import ContextVar
from typing import Protocol


class MutationGuard(Protocol):
    def before_mutation(self, method: str, path: str, payload: object = None) -> None: ...
    def after_mutation(self, result: object = None) -> None: ...


current_mutation_guard: ContextVar[MutationGuard | None] = ContextVar(
    "mutation_guard", default=None
)

mutation_context: ContextVar[dict[str, object] | None] = ContextVar(
    "mutation_context", default=None
)
