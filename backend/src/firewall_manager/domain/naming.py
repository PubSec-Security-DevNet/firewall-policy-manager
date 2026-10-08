# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Centralized provider-facing Group prefix rules."""

import re

_PROVIDER_SLUG_PATTERN = re.compile(r"^[A-Z][A-Z0-9-]{1,63}$")


def normalize_provider_slug(value: str) -> str:
    """Normalize and validate an immutable provider-facing Group slug.

    Display names are intentionally not accepted as implicit authorization identifiers. Callers
    may propose a slug at Group creation, but later display-name changes never rewrite it.
    """
    normalized = re.sub(r"[^A-Z0-9]+", "-", value.strip().upper()).strip("-")
    if not _PROVIDER_SLUG_PATTERN.fullmatch(normalized):
        msg = "provider slug must be 2-64 characters and start with an ASCII letter"
        raise ValueError(msg)
    return normalized
