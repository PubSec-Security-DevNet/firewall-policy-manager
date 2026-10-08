# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Canonical application release identifier (packaging normalizes PEP 440 spelling)."""

import os

__version__ = "1.0.0-rc1"
GIT_SHA = os.environ.get("APP_GIT_SHA", "unknown")[:12]
