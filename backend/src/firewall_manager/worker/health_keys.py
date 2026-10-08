# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Shared Redis keys for background process liveness."""

WORKER_HEARTBEAT_KEY = "firewall-manager:worker:last-heartbeat"
SCHEDULER_HEARTBEAT_KEY = "firewall-manager:scheduler:heartbeat"
